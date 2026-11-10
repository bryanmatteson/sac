#!/usr/bin/env python3
"""Independent, offline SAC1 reader and explicit salvage tool.

Only public blake3 and zstandard packages are required. This module neither
imports the application nor invokes another SAC implementation. See
SAC1_RECOVERY.md for verification scopes, quotas and command examples.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
import weakref

import blake3
import zstandard

MAGIC = b"SAC1"
U64 = (1 << 64) - 1
MIB = 1 << 20
ID_RE = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+\Z")


class CborMap(list):
    """Ordered pairs for maps whose keys cannot be represented by a Python dict."""


class SacError(Exception):
    def __init__(self, category, message, dimension=None):
        super().__init__(message)
        self.category, self.dimension = category, dimension


def require(ok, message, category="malformed_input"):
    if not ok:
        raise SacError(category, message)


def uint(value, maximum=U64, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, "integer out of range")
    return value


def array(value, length=None):
    require(type(value) is list and (length is None or len(value) == length), "wrong array shape")
    return value


def bstr(value, length=None):
    require(type(value) is bytes and (length is None or len(value) == length), "wrong byte string")
    return value


def identifier(value):
    require(type(value) is str and 1 <= len(value) <= 128 and ID_RE.fullmatch(value), "invalid namespace ID")
    return value


def digest(domain, data):
    return blake3.blake3(domain.encode("ascii") + b"\0" + data).digest()


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def cbor_encode(value):
    def head(major, n):
        if n < 24:
            return bytes([(major << 5) | n])
        for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * width):
                return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
        raise SacError("malformed_input", "integer too large")
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if type(value) in (bytes, str):
        data = value.encode("utf-8") if type(value) is str else value
        return head(3 if type(value) is str else 2, len(data)) + data
    if type(value) is list:
        return head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if type(value) is dict or isinstance(value, CborMap):
        pairs = sorted((cbor_encode(k), cbor_encode(v)) for k, v in (value.items() if type(value) is dict else value))
        require(all(pairs[i - 1][0] < pairs[i][0] for i in range(1, len(pairs))), "duplicate CBOR map key")
        return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise SacError("malformed_input", "unsupported CBOR value")


def cbor_decode(data, memory_limit=64 * MIB, *, text_keys=True):
    """Strict RFC 8949 core deterministic subset, with bounded parser state.

    All format maps have text keys. Rejecting other map keys also avoids Python
    bool/int key conflation. Profile payload maps use this same restriction.
    """
    pos, items = 0, 0
    require(len(data) <= memory_limit, "CBOR memory limit", "exhausted_limits")

    def parse(depth=0):
        nonlocal pos, items
        items += 1
        if items > 1048576 or len(data) + items * 128 > memory_limit:
            raise SacError("exhausted_limits", "CBOR item/memory limit", "resident_memory")
        require(pos < len(data), "truncated CBOR")
        initial = data[pos]
        pos += 1
        major, ai = initial >> 5, initial & 31
        if major == 7:
            require(ai in (20, 21, 22), "forbidden CBOR simple value or float")
            return {20: False, 21: True, 22: None}[ai]
        require(major <= 5 and ai <= 27, "forbidden CBOR type or indefinite length")
        if ai < 24:
            n = ai
        else:
            width = 1 << (ai - 24)
            require(pos + width <= len(data), "truncated CBOR argument")
            n = int.from_bytes(data[pos:pos + width], "big")
            pos += width
            require(n >= (24 if width == 1 else 1 << (8 * (width // 2))), "nonminimal CBOR integer")
        if major in (0, 1):
            return n if major == 0 else -1 - n
        if major in (2, 3):
            require(n <= len(data) - pos, "CBOR string exceeds enclosing bytes")
            result = data[pos:pos + n]
            pos += n
            if major == 3:
                try:
                    return result.decode("utf-8", "strict")
                except UnicodeDecodeError as error:
                    raise SacError("malformed_input", "invalid UTF-8") from error
            return result
        require(depth < 64, "CBOR nesting limit", "exhausted_limits")
        count = n * (2 if major == 5 else 1)
        require(count <= len(data) - pos and count <= 1048576 - items,
                "CBOR count exceeds enclosing bytes/items")
        if major == 4:
            return [parse(depth + 1) for _ in range(n)]
        pairs, previous = [], None
        for _ in range(n):
            start = pos
            key = parse(depth + 1)
            encoded = data[start:pos]
            require(previous is None or previous < encoded, "duplicate or unordered CBOR map key")
            require(not text_keys or type(key) is str, "core/profile metadata map key must be text")
            previous = encoded
            pairs.append((key, parse(depth + 1)))
        return dict(pairs) if all(type(key) is str for key, _ in pairs) else CborMap(pairs)
    value = parse()
    require(pos == len(data), "trailing CBOR item")
    return value


def parse_attestation(encoded):
    """Exact baseline COSE structure only; never establishes key trust."""
    require(0 < len(bstr(encoded)) <= 1024 and encoded[0] == 0xd2, "expected bounded canonical COSE Sign1 tag18")
    protected, unprotected, payload, signature = array(cbor_decode(encoded[1:], text_keys=False), 4)
    headers = cbor_decode(bstr(protected), text_keys=False)
    require(type(headers) is dict or isinstance(headers, CborMap), "protected header must be a map")
    pairs = list(headers.items()) if type(headers) is dict else headers
    require(type(unprotected) is dict and not unprotected, "unprotected header must be empty")
    require(all(type(key) is int and key in (1, 4) for key, _ in pairs), "unsupported COSE protected header", "unsupported_schema")
    fields = dict(pairs)
    require(1 in fields, "missing protected algorithm")
    require(type(fields[1]) is int and fields[1] == -19, "unsupported signature algorithm", "unsupported_schema")
    kid = fields.get(4)
    if 4 in fields:
        require(1 <= len(bstr(kid)) <= 128, "invalid protected key ID")
    tag, purpose, snapshot = array(cbor_decode(bstr(payload)), 3)
    require(tag == "sac.snapshot.v1" and type(purpose) is str and 1 <= len(purpose.encode()) <= 256, "invalid attestation payload domain/purpose")
    bstr(snapshot, 32)
    bstr(signature, 64)
    return {"purpose": purpose, "snapshot": snapshot.hex(), "key_id": kid.hex() if kid is not None else None,
            "signature": "unchecked", "trust": "unaccepted"}


@dataclass
class Limits:
    source_bytes: int = 16 << 30
    decoded_bytes: int = 16 << 30
    hash_bytes: int = 16 << 30
    frame_visits: int = 2000000
    edge_visits: int = 4000000
    entries: int = 1000000
    output_bytes: int = 4 << 30
    allocated_bytes: int = 4 << 30
    file_bytes: int = 4 << 30
    temporary_bytes: int = 4 << 30
    resident_memory: int = 64 * MIB
    depth: int = 512
    path_bytes: int = 16384
    seconds: float = 600


@dataclass
class Budget:
    limits: Limits
    used: dict = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)

    def charge(self, dimension, amount=1):
        if time.monotonic() - self.started > self.limits.seconds:
            raise SacError("exhausted_limits", "elapsed work limit", "seconds")
        value = self.used.get(dimension, 0) + amount
        if value > getattr(self.limits, dimension):
            raise SacError("exhausted_limits", f"{dimension} limit", dimension)
        self.used[dimension] = value

    def depth(self, value):
        if value > self.limits.depth:
            raise SacError("exhausted_limits", "path/graph depth limit", "depth")

    def release(self, dimension, amount):
        self.used[dimension] -= amount


@dataclass
class Object:
    offset: int
    span: int
    oid: bytes
    kind: int
    schema: int
    children: list
    locators: list
    canonical: bytes
    body: object
    weight: int = 0


class Archive:
    """Pinned local descriptor. Never mutates the input or obtains write authority."""
    def __init__(self, path, limits=None, *, admit=True, budget=None):
        self.path, self.limits = Path(path), limits or Limits()
        self.budget = budget or Budget(self.limits)
        self.file = self.path.open("rb")
        self.size = os.fstat(self.file.fileno()).st_size
        self.end, self.first, self.trailer_offset = self.size, 128, self.size
        self.temp = tempfile.TemporaryDirectory(prefix="sac1-reader-")
        self.budget.charge("temporary_bytes", 65536)
        self.db = sqlite3.connect(str(Path(self.temp.name) / "inventory.sqlite"))
        self.db.execute("pragma cache_size=-1024")
        self.db.execute("create table records (off integer primary key, span integer, tag integer)")
        self.db.execute("create table visited (off integer primary key, id blob)")
        self.db.execute("create table attestation_outcomes (off integer, ordinal integer, expected blob, status text, outcome text, primary key(off,ordinal,expected))")
        self.inventory = False
        self.cache, self.cache_bytes = OrderedDict(), 0
        self.state = {"root": "unadmitted", "physical": "unchecked", "core": "unchecked",
                      "profiles": {}, "trust": "unaccepted", "durability": "uncoordinated"}
        self.degraded = False
        self.salvage_mode = False
        if admit:
            try:
                self._admit()
            except BaseException:
                self.close()
                raise

    def close(self):
        self.cache.clear()
        self.commit = self.snapshot = None
        self.file.close()
        self.db.close()
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read(self, offset, length):
        require(type(offset) is int and type(length) is int and offset >= 0 and length >= 0
                and offset + length <= self.size and offset + length <= U64, "source range out of bounds")
        self.budget.charge("source_bytes", length)
        result = os.pread(self.file.fileno(), length, offset)
        require(len(result) == length, "short source read", "integrity_failure")
        return result

    def _admit(self):
        pre = self.read(0, 128)
        require(pre[:4] == MAGIC, "not a SAC1 file", "unsupported_schema")
        require(pre[8] in (0, 1), "unsupported locator policy", "unsupported_schema")
        self.policy = pre[8]
        require(pre[4:8] == bytes(4) and pre[9:16] == bytes(7) and pre[32:96] == bytes(64),
                "nonzero preamble reserved bytes")
        require((pre[16:32] != bytes(16)) == bool(self.policy), "invalid incarnation")
        self.preamble_digest = digest("SAC1/preamble", pre[:96])
        require(pre[96:] == self.preamble_digest, "preamble digest mismatch", "integrity_failure")
        self.incarnation = pre[16:32]
        self.first = 12288 if self.policy else 128
        if self.policy:
            require(self.read(128, 4096 - 128) == bytes(4096 - 128), "nonzero live preamble fill")
            slots = []
            for index in range(2):
                raw = self.read(4096 + index * 4096, 4096)
                if raw == bytes(4096):
                    continue
                if digest("SAC1/slot", raw[:4064]) != raw[4064:]:
                    self.degraded = True
                    continue
                generation, offset = struct.unpack_from("<QQ", raw, 40)
                require(raw[:8] == b"SAC1SLOT" and raw[8:40] == self.preamble_digest
                        and generation > 0 and generation % 2 == index
                        and raw[88:4064] == bytes(3976), "malformed checksum-valid live slot")
                slots.append((generation, offset, raw[56:88]))
            require(slots, "no intact authorized slot; retry coordinated admission", "admission_busy")
            generation, offset, expected = max(slots)
            trailer = self._trailer(offset)
            require(trailer["generation"] == generation and trailer["digest"] == expected,
                    "selected slot/trailer binding mismatch", "integrity_failure")
        else:
            offset = self.size - 160
            trailer = self._trailer(offset)
            require(trailer["end"] == self.size and trailer["generation"] == 1, "sealed EOF/generation mismatch")
        self.trailer_offset, self.end, self.generation = offset, trailer["end"], trailer["generation"]
        self.commit = self.object(trailer["commit_offset"], trailer["commit_span"], trailer["commit_id"])
        require(self.commit.kind == 1 and self.commit.schema == 1, "commit kind/schema mismatch")
        self._shape(self.commit)
        self.snapshot = self.child(self.commit, self.commit.body[0], (2,))
        self._shape(self.snapshot)
        control = self.end - min(65536, self.end - self.first)
        for obj in (self.commit, self.snapshot):
            require(control <= obj.offset and obj.offset + obj.span <= offset
                    and len(obj.canonical) <= 16384, "root outside control bound")
            require(self.read(obj.offset + 4, 1) == b"\0", "control frames must use stored codec")
        require(self.snapshot.offset + self.snapshot.span <= self.commit.offset, "overlapping control roots")
        self.state["root"] = "admitted_degraded" if self.degraded else "admitted"
        self.state["snapshot"] = self.snapshot.oid.hex()
        self.state["generation"] = self.generation

    def _trailer(self, offset):
        raw = self.read(offset, 160)
        require(offset % 8 == 0 and raw[:8] == b"SAC1END\0", "invalid trailer tag/alignment")
        require(raw[8:40] == self.preamble_digest and raw[104:128] == bytes(24), "trailer preamble/reserved mismatch")
        generation, end, commit_offset, commit_span = struct.unpack_from("<QQQQ", raw, 40)
        require(generation > 0 and end == offset + 160 and end >= self.first + 160 and end <= self.size,
                "invalid committed extent")
        require(digest("SAC1/trailer", raw[:128]) == raw[128:], "trailer digest mismatch", "integrity_failure")
        return dict(generation=generation, end=end, commit_offset=commit_offset,
                    commit_span=commit_span, commit_id=raw[72:104], digest=raw[128:])

    def _header(self, offset):
        raw = self.read(offset, 56)
        require(offset % 8 == 0 and raw[:4] == b"SO1\0", "invalid frame start")
        codec, revision, count, stored, decoded = struct.unpack_from("<BBHII", raw, 4)
        require(codec in (0, 1) and revision == 1, "unsupported frame codec/revision", "unsupported_schema")
        require(count <= 1024 and stored <= 8 * MIB and 8 <= decoded <= 8 * MIB,
                "frame size/count bound exceeded")
        require(raw[52:56] == bytes(4), "nonzero frame reserved bytes")
        checked = raw[:48] + bytes(4) + raw[52:]
        require(crc32c(checked) == struct.unpack_from("<I", raw, 48)[0], "frame CRC mismatch", "integrity_failure")
        span = (56 + stored + 12 * count + 7) & ~7
        return raw, codec, count, stored, decoded, span

    def object(self, offset, span, expected):
        self.budget.charge("frame_visits")
        require(self.first <= offset < self.trailer_offset and span <= (1 << 32) - 1
                and offset + span <= self.trailer_offset, "frame locator outside committed extent")
        key = (offset, span, expected)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        raw, codec, count, stored, decoded, actual_span = self._header(offset)
        require(span == actual_span and raw[16:48] == expected, "frame span/expected ID mismatch", "integrity_failure")
        if self.inventory:
            require(self.db.execute("select span from records where off=? and tag=0", (offset,)).fetchone() == (span,),
                    "locator is not a top-level object start")
        # Reserve room for wire slices, decoded/canonical bodies and child
        # tables before the first large read or decoder allocation. Cache
        # eviction releases only objects with no active users.
        working = 2 * stored + 3 * decoded + count * 128 + 1024
        while self.cache and self.budget.used.get("resident_memory", 0) + working > self.limits.resident_memory:
            _, old = self.cache.popitem(last=False)
            self.cache_bytes -= old.weight
            del old
        if self.budget.used.get("resident_memory", 0) + working > self.limits.resident_memory:
            raise SacError("exhausted_limits", "frame working memory limit before allocation", "resident_memory")
        self.budget.charge("decoded_bytes", decoded)
        wire = self.read(offset + 56, span - 56)
        encoded = wire[:stored]
        if codec == 0:
            require(stored == decoded, "stored/decoded size mismatch")
            canonical = encoded
        else:
            require(encoded[:4] == b"\x28\xb5\x2f\xfd" and len(encoded) >= 5
                    and encoded[4] & 3 == 0, "Zstandard dictionary/skippable frame forbidden")
            try:
                params = zstandard.get_frame_parameters(encoded)
                require(params.content_size == decoded and params.window_size <= 8 * MIB,
                        "Zstandard content/window size mismatch")
                canonical = zstandard.ZstdDecompressor(max_window_size=8192).decompress(
                    encoded, max_output_size=decoded, allow_extra_data=False)
            except zstandard.ZstdError as error:
                raise SacError("malformed_input", "invalid or concatenated Zstandard frame") from error
        self.budget.charge("hash_bytes", len(canonical))
        require(len(canonical) == decoded and digest("SAC1/object", canonical) == expected,
                "object decoded size/hash mismatch", "integrity_failure")
        kind, schema, common_count = struct.unpack_from("<HHI", canonical)
        require(common_count == count and decoded >= 8 + 32 * count, "canonical child-count mismatch")
        if kind == 3:
            require(decoded <= 131072 and span <= 147456, "directory leaf size bound exceeded")
        elif kind in (4, 5, 6):
            require(decoded <= 65536 and span <= 81920, "index page size bound exceeded")
        children = [canonical[8 + i * 32:40 + i * 32] for i in range(count)]
        locators = [struct.unpack_from("<QI", wire, stored + 12 * i) for i in range(count)]
        require(wire[stored + 12 * count:] == bytes(span - 56 - stored - 12 * count), "nonzero frame padding")
        if not self.salvage_mode:
            for child_offset, child_span in locators:
                require(child_offset >= self.first and child_offset % 8 == 0 and child_span >= 64
                        and child_offset + child_span <= offset, "child locator violates dependency ordering")
        body_bytes = canonical[8 + 32 * count:]
        body = body_bytes if kind == 7 or kind not in range(1, 10) or schema != 1 else cbor_decode(
            body_bytes, min(self.limits.resident_memory // 2,
                            self.limits.resident_memory - self.budget.used.get("resident_memory", 0) - 2 * stored - 3 * decoded))
        obj = Object(offset, span, expected, kind, schema, children, locators, canonical, body)
        def weight(value):
            if type(value) is list:
                return 128 + sum(weight(item) for item in value)
            if type(value) is dict:
                return 128 + sum(weight(k) + weight(v) for k, v in value.items())
            return 128
        cost = len(canonical) * 3 + weight(body) + 1024
        obj.weight = cost
        cap = self.limits.resident_memory // 4
        while self.cache and self.cache_bytes + cost > cap:
            _, old = self.cache.popitem(last=False)
            self.cache_bytes -= old.weight
            del old
        self.budget.charge("resident_memory", cost)
        weakref.finalize(obj, self.budget.release, "resident_memory", cost)
        if cost <= cap:
            self.cache[key], self.cache_bytes = obj, self.cache_bytes + cost
        return obj

    def child(self, parent, index, kinds=None):
        self.budget.charge("edge_visits")
        uint(index, len(parent.children) - 1)
        child = self.object(*parent.locators[index], parent.children[index])
        if kinds:
            require(child.kind in kinds and child.schema == 1, "edge kind/schema mismatch", "unsupported_schema")
        return child

    def _shape(self, obj, opaque_allowed=False):
        if obj.kind in range(1, 10):
            require(obj.schema == 1, "unsupported reserved core schema", "unsupported_schema")
        else:
            require(opaque_allowed, "unsupported undeclared object kind/schema", "unsupported_schema")
            return
        body, used = obj.body, set()
        def index(value):
            used.add(uint(value, len(obj.children) - 1))
        if obj.kind == 1:
            array(body, 3)
            index(body[0])
            for value in body[1:]:
                if value is not None:
                    index(value)
            require(self.policy or body[2] is None, "sealed commit contains local data")
        elif obj.kind == 2:
            directory, profiles, features = array(body, 3)
            index(directory)
            previous, declared = None, set()
            for item in array(profiles):
                name, version, root = array(item, 3)
                identifier(name)
                uint(version, (1 << 32) - 1, 1)
                require(previous is None or previous < name, "duplicate/unsorted profile")
                previous = name
                declared.add(name)
                index(root)
                profile = self.child(obj, root, (8,))
                array(profile.body, 4)
                require(profile.body[:3] == [name, "root", version], "profile root binding mismatch")
                self.state["profiles"][name] = "semantics_unverified"
            previous = None
            for item in array(features):
                scope, name, version, required = array(item, 4)
                require(scope is None or (type(scope) is str and scope in declared), "feature scope is not declared")
                identifier(name)
                uint(version, (1 << 32) - 1, 1)
                require(type(required) is bool, "feature required flag is not boolean")
                key = cbor_encode([scope, name])
                require(previous is None or previous < key, "duplicate/unsorted feature")
                previous = key
                if required and scope is None:
                    raise SacError("unsupported_capability", f"required core capability {name}/{version}")
        elif obj.kind == 3:
            previous = None
            for entry in array(body):
                name, entry_type, metadata, value = array(entry, 4)
                self._name(name)
                require(previous is None or previous < name, "duplicate/unsorted directory key")
                previous = name
                uint(entry_type, 2)
                self._metadata(metadata, entry_type)
                if entry_type == 0:
                    length, storage, data = array(value, 3)
                    uint(length)
                    uint(storage, 1)
                    if storage == 0:
                        bstr(data, length)
                        require(length <= 49152, "oversized inline file")
                    else:
                        require(length > 0, "empty file must use inline storage")
                        index(data)
                elif entry_type == 1:
                    index(value)
                else:
                    require(len(bstr(value)) <= 4096, "oversized symbolic link")
        elif obj.kind in (4, 6):
            height, ranges = array(body, 2)
            uint(height, 16, 1)
            require(len(array(ranges)) >= 2, "single-child or empty branch")
            previous = None
            for item in ranges:
                end, child = array(item, 2)
                self._name(end) if obj.kind == 4 else uint(end, U64, 1)
                require(previous is None or previous < end, "unordered branch fences")
                previous = end
                index(child)
        elif obj.kind == 5:
            require(len(array(body)) > 0, "empty extent leaf")
            total = 0
            for item in body:
                length, child = array(item, 2)
                total += uint(length, U64, 1)
                uint(total)
                if child is not None:
                    index(child)
        elif obj.kind == 7:
            require(not obj.children, "byte object has children")
        elif obj.kind == 8:
            namespace, record_type, version, payload = array(body, 4)
            identifier(namespace)
            require(type(record_type) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,127}", record_type), "invalid profile type")
            uint(version, (1 << 32) - 1, 1)
            bstr(payload)
            return  # Dependency roles belong to the owning profile.
        elif obj.kind == 9:
            require(not obj.children and len(obj.canonical) <= 65536 and len(array(body)) <= 256,
                    "attestation catalogue bound exceeded")
            for value in body:
                require(len(bstr(value)) <= 1024, "oversized attestation")
        require(used == set(range(len(obj.children))), "unused canonical child table entry")

    @staticmethod
    def _name(value):
        require(type(value) is bytes and 1 <= len(value) <= 4096 and b"/" not in value
                and b"\0" not in value and value not in (b".", b".."), "invalid directory key")

    def _metadata(self, metadata, entry_type):
        require(type(metadata) is dict and len(cbor_encode(metadata)) <= 16384, "invalid/oversized metadata")
        for key, value in metadata.items():
            if key == "mode":
                uint(value, 0o7777)
            elif key == "mtime":
                seconds, nanos = array(value, 2)
                require(type(seconds) is int and -(1 << 63) <= seconds < 1 << 63, "mtime seconds out of range")
                uint(nanos, 999999999)
            elif key == "media_type":
                require(type(value) is str and len(value.encode("utf-8")) <= 4096, "invalid media type")
            elif key == "byte_digest":
                require(entry_type == 0, "digest metadata on non-file")
                bstr(value, 32)
            else:
                identifier(key)

    def physical_scan(self):
        offset = self.first
        while offset < self.end:
            self.budget.charge("frame_visits")
            if self.read(offset, 8) == b"SAC1END\0":
                span, tag = 160, 1
                require(offset + span <= self.end, "truncated top-level trailer")
            else:
                *_, span = self._header(offset)
                tag = 0
            require(offset + span <= self.end, "physical record exceeds committed extent")
            self.budget.charge("temporary_bytes", 512)
            self.db.execute("insert into records values (?,?,?)", (offset, span, tag))
            offset += span
        require(offset == self.end, "record inventory does not reach committed end")
        self.db.commit()
        self.inventory = True
        self.cache.clear()
        self.cache_bytes = 0
        self.state["physical"] = "inventory_scanned"

    def _extent(self, obj, expected=None, height=None, depth=0):
        self.budget.depth(depth)
        self._shape(obj)
        require(obj.kind in (5, 6), "not an extent tree")
        actual_height = 0 if obj.kind == 5 else obj.body[0]
        require(height is None or actual_height == height, "extent height mismatch")
        total = 0
        if obj.kind == 5:
            for length, index in obj.body:
                if index is not None:
                    child = self.child(obj, index, (7,))
                    self._shape(child)
                    require(len(child.body) == length, "extent byte length mismatch")
                total += length
        else:
            for end, index in obj.body[1]:
                self._extent(self.child(obj, index, (5, 6)), end - total, actual_height - 1, depth + 1)
                total = end
        require(expected is None or total == expected, "extent logical length mismatch")
        return total

    def _directory_pages(self, obj, height=None, lower=None, upper=None, depth=0):
        self.budget.depth(depth)
        self._shape(obj)
        require(obj.kind in (3, 4), "not a directory tree")
        actual_height = 0 if obj.kind == 3 else obj.body[0]
        require(height is None or actual_height == height, "directory height mismatch")
        if obj.kind == 3:
            if height is not None:
                require(obj.body, "empty leaf below directory branch")
            for entry in obj.body:
                name = entry[0]
                require((lower is None or lower < name) and (upper is None or name <= upper), "directory inherited interval mismatch")
                yield obj, entry
            if upper is not None:
                require(obj.body and obj.body[-1][0] == upper, "directory fence is not exact")
        else:
            require(upper is None or obj.body[1][-1][0] == upper, "branch maximum fence mismatch")
            for fence, index in obj.body[1]:
                require((lower is None or lower < fence) and (upper is None or fence <= upper), "branch inherited interval mismatch")
                child = self.child(obj, index, (3, 4))
                yield from self._directory_pages(child, actual_height - 1, lower, fence, depth + 1)
                lower = fence

    def entries(self, directory=None):
        def walk(root, path):
            self.budget.depth(len(path))
            for owner, entry in self._directory_pages(root):
                self.budget.charge("entries")
                logical = path + [entry[0]]
                require(sum(map(len, logical)) + len(logical) <= self.limits.path_bytes,
                        "logical path length limit", "exhausted_limits")
                yield logical, owner, entry
                if entry[1] == 1:
                    yield from walk(self.child(owner, entry[3], (3, 4)), logical)
        yield from walk(directory if directory is not None else self.child(self.snapshot, self.snapshot.body[0], (3, 4)), [])

    def chunks(self, owner, entry):
        require(entry[1] == 0, "not a regular file")
        length, storage, data = entry[3]
        if not storage:
            yield data
            return
        def expand(obj, depth=0):
            self.budget.depth(depth)
            if obj.kind == 5:
                for size, index in obj.body:
                    if index is None:
                        remaining = size
                        while remaining:
                            self.budget.charge("decoded_bytes", 0)  # Enforce elapsed work even without source reads.
                            block = bytes(min(65536, remaining))
                            remaining -= len(block)
                            yield block
                    else:
                        yield self.child(obj, index, (7,)).body
            else:
                for _, index in obj.body[1]:
                    yield from expand(self.child(obj, index, (5, 6)), depth + 1)
        root = self.child(owner, data, (5, 6))
        self._extent(root, length)
        yield from expand(root)

    def verify(self):
        if not self.inventory:
            self.physical_scan()
        stack = [(self.commit.offset, self.commit.span, self.commit.oid, 0, None)]
        while stack:
            offset, span, oid, depth, owner_profile = stack.pop()
            self.budget.depth(depth)
            if self.db.execute("select 1 from visited where off=?", (offset,)).fetchone():
                continue
            obj = self.object(offset, span, oid)
            self._shape(obj, opaque_allowed=owner_profile is not None)
            self.budget.charge("temporary_bytes", 256)
            self.db.execute("insert into visited values (?,?)", (offset, oid))
            # Validate every physical occurrence's links, even when canonical IDs repeat.
            for index in range(len(obj.children)):
                child = self.child(obj, index)
                child_owner = owner_profile
                if obj.kind == 2 and obj.schema == 1:
                    child_owner = next((name for name, _, ordinal in obj.body[1] if ordinal == index), None)
                elif obj.kind == 1 and obj.schema == 1 and obj.body[2] == index:
                    child_owner = "commit-local"
                if child_owner is not None:
                    self.state["profiles"].setdefault(child_owner, "semantics_unverified")
                require((len(stack) + 1) * 160 <= self.limits.resident_memory // 8,
                        "traversal stack memory limit", "exhausted_limits")
                stack.append((child.offset, child.span, child.oid, depth + 1, child_owner))
            if obj.schema != 1 or obj.kind not in range(1, 10):
                continue  # Authenticated opaque profile data; no semantic core dispatch.
            if obj.kind == 1:
                snapshot = self.child(obj, obj.body[0], (2,))
                for index, kinds in ((obj.body[1], (9,)), (obj.body[2], (8,))):
                    if index is not None:
                        target = self.child(obj, index, kinds)
                        if kinds == (9,):
                            self._inspect_attestations(target, snapshot.oid)
            if obj.kind in (3, 4):
                for owner, entry in self._directory_pages(obj):
                    if entry[1] == 0 and entry[3][1] == 1:
                        self._extent(self.child(owner, entry[3][2], (5, 6)), entry[3][0])
                    elif entry[1] == 1:
                        self.child(owner, entry[3], (3, 4))
            elif obj.kind in (5, 6):
                self._extent(obj)
        self.db.commit()
        try:
            if self.metadata_directory() is not None:
                for _, owner, entry in self.metadata_entries():
                    self._metadata_value(owner, entry)
                self.state["profiles"]["sac.metadata.v1"] = "validated"
        except SacError as error:
            if error.category not in ("unsupported_schema", "unsupported_capability"):
                raise
            self.state["profiles"]["sac.metadata.v1"] = "semantics_unsupported"
        self.state["physical"] = "validated"
        self.state["core"] = "validated"
        self.state["attestations"] = {status: count for status, count in self.db.execute("select status,count(*) from attestation_outcomes group by status order by status")}
        self.state["attestation_details"] = "attestations_command; signatures_unchecked; trust_unaccepted"
        return self.state

    def metadata_directory(self):
        """Open only the generic metadata root, independent of application profiles."""
        declaration = next((p for p in self.snapshot.body[1] if p[0] == "sac.metadata.v1"), None)
        if declaration is None:
            return None
        require(declaration[1] == 1, "unsupported metadata profile version", "unsupported_schema")
        require(not any(f[0] == "sac.metadata.v1" and f[3] for f in self.snapshot.body[2]),
                "unsupported required metadata capability", "unsupported_capability")
        root = self.child(self.snapshot, declaration[2], (8,))
        require(root.body == ["sac.metadata.v1", "root", 1, b"\x81\x00"] and len(root.children) == 1,
                "invalid metadata profile root")
        return self.child(root, 0, (3, 4))

    def metadata_entries(self):
        directory = self.metadata_directory()
        if directory is None:
            return
        for path, owner, entry in self.entries(directory):
            require(len(path) == 1 and entry[1] == 0 and entry[3][0] <= 8 * MIB,
                    "metadata must contain bounded flat regular files")
            try:
                key = path[0].decode("ascii")
            except UnicodeDecodeError as error:
                raise SacError("malformed_input", "metadata key must be an ASCII namespace ID") from error
            identifier(key)
            yield key, owner, entry

    def _metadata_value(self, owner, entry):
        length = entry[3][0]
        require(length <= min(8 * MIB, self.limits.file_bytes, self.limits.resident_memory // 4),
                "metadata value limit", "exhausted_limits")
        self.budget.charge("allocated_bytes", length)
        data = b"".join(self.chunks(owner, entry))
        require(len(data) == length, "metadata value length mismatch")
        cbor_decode(data, self.limits.resident_memory // 2, text_keys=False)
        return data

    def metadata_get(self, key):
        """Authenticated point lookup; a miss checks directory completeness."""
        identifier(key)
        directory = self.metadata_directory()
        if directory is None:
            return None
        raw = key.encode("ascii")
        obj, lower, upper, height = directory, None, None, None
        while obj.kind == 4:
            self._shape(obj)
            level, routes = obj.body
            require(height is None or level == height, "metadata directory height")
            require(upper is None or routes[-1][0] == upper, "metadata branch maximum")
            require(lower is None or routes[0][0] > lower, "metadata branch lower fence")
            chosen = next(((i, fence, slot) for i, (fence, slot) in enumerate(routes) if raw <= fence), None)
            if chosen is None:
                break
            i, fence, slot = chosen
            lower = routes[i - 1][0] if i else lower
            upper, height = fence, level - 1
            obj = self.child(obj, slot, (3, 4))
        else:
            for owner, entry in self._directory_pages(obj, height, lower, upper):
                if entry[0] == raw:
                    require(entry[1] == 0, "metadata value must be a regular file")
                    return self._metadata_value(owner, entry)
        # Do not turn an unchecked route miss into certified absence.
        for _ in self.metadata_entries():
            pass
        return None

    def recover_metadata(self, destination):
        directory = self.metadata_directory()
        require(directory is not None, "no generic metadata profile", "missing_dependency")
        return self.extract(destination, directory=directory)

    def _inspect_attestations(self, catalogue, expected_snapshot):
        for ordinal, encoded in enumerate(array(catalogue.body)):
            if self.db.execute("select 1 from attestation_outcomes where off=? and ordinal=? and expected=?", (catalogue.offset, ordinal, expected_snapshot)).fetchone():
                continue
            self.budget.charge("edge_visits")
            self.budget.charge("decoded_bytes", len(bstr(encoded)))
            try:
                result = parse_attestation(encoded)
                require(result["snapshot"] == expected_snapshot.hex(), "signed snapshot differs from attached commit")
                status = "valid_structure"
            except SacError as error:
                status = "unsupported" if error.category in ("unsupported_schema", "unsupported_capability") else "invalid"
                result = {"error": error.category, "message": str(error), "signature": "unchecked", "trust": "unaccepted"}
            result.update(catalogue_id=catalogue.oid.hex(), ordinal=str(ordinal), expected_snapshot=expected_snapshot.hex(), status=status)
            self.budget.charge("temporary_bytes", 4096 + len(json.dumps(result)))
            self.db.execute("insert into attestation_outcomes values (?,?,?,?,?)", (catalogue.offset, ordinal, expected_snapshot, status, json.dumps(result)))

    def attestation_outcomes(self):
        self.verify()
        for (encoded,) in self.db.execute("select outcome from attestation_outcomes order by off,ordinal,expected"):
            yield json.loads(encoded)

    def _reserve_outputs(self, directory=None):
        self.db.execute("create table extraction_names (logical blob primary key, parent blob, name text, destination blob)")
        for path, _, entry in self.entries(directory):
            components = ["sac-" + digest("SAC1/extract-name", cbor_encode(path[:i])).hex()
                          for i in range(1, len(path) + 1)]
            require(len("/".join(components).encode()) <= self.limits.path_bytes,
                    "mapped destination path length limit", "exhausted_limits")
            self.budget.charge("temporary_bytes", 4 * (len(cbor_encode(path)) + len(cbor_encode(components))) + 4096)
            self.db.execute("insert into extraction_names values (?,?,?,?)",
                            (cbor_encode(path), cbor_encode(path[:-1]), components[-1], cbor_encode(components)))
            if entry[1] == 0:
                length = entry[3][0]
                require(length <= self.limits.file_bytes, "individual output length limit", "exhausted_limits")
                self.budget.charge("output_bytes", length)
                self.budget.charge("allocated_bytes", length)
                self.budget.charge("temporary_bytes", length)
        # All components are reserved ASCII on the supported hosts. An actual
        # digest collision is rejected before output files are created.
        require(not self.db.execute("select 1 from extraction_names group by parent,name having count(*)>1 limit 1").fetchone(),
                "generated destination collision during preflight")
        self.db.commit()

    def extract(self, destination, *, directory=None):
        """Strict whole-archive extraction; conservative all-name mapping on POSIX."""
        require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "host lacks confined extraction", "unsupported_schema")
        self.verify()
        self._reserve_outputs(directory)
        destination = Path(destination).absolute()
        require(not destination.exists() and not destination.is_symlink(), "destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".sac1-extract-", dir=destination.parent))
        report_file = stage / "report.cbor"
        # Stream report rows to a spool: no archive-sized in-memory name/report map.
        spool = tempfile.TemporaryFile(dir=stage)
        count = 0
        try:
            (stage / "content").mkdir(mode=0o700)
            rootfd = os.open(stage / "content", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for logical, owner, entry in self.entries(directory):
                    components = cbor_decode(self.db.execute("select destination from extraction_names where logical=?",
                                             (cbor_encode(logical),)).fetchone()[0])
                    parent = os.dup(rootfd)
                    try:
                        for component in components[:-1]:
                            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                            os.close(parent)
                            parent = child
                        output_digest = None
                        if entry[1] == 1:
                            os.mkdir(components[-1], 0o700, dir_fd=parent)
                        elif entry[1] == 0:
                            fd = os.open(components[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                            hasher, length = blake3.blake3(), 0
                            with os.fdopen(fd, "wb") as out:
                                for chunk in self.chunks(owner, entry):
                                    self.budget.charge("hash_bytes", len(chunk))
                                    out.write(chunk)
                                    hasher.update(chunk)
                                    length += len(chunk)
                                require(length == entry[3][0], "expanded output length mismatch")
                                out.flush()
                                os.fsync(out.fileno())
                            output_digest = hasher.digest()
                            if "byte_digest" in entry[2]:
                                require(output_digest == entry[2]["byte_digest"], "resource digest mismatch", "integrity_failure")
                        row = [logical, components, entry[1], "mapped", entry[2],
                               "DigestVerified" if output_digest and "byte_digest" in entry[2] else "DigestUnchecked", output_digest,
                               entry[3] if entry[1] == 2 else None]
                        encoded = cbor_encode(row)
                        self.budget.charge("temporary_bytes", 2 * len(encoded))
                        spool.write(encoded)
                        count += 1
                    finally:
                        os.close(parent)
            finally:
                os.close(rootfd)
            with report_file.open("xb") as out:
                prefix = cbor_encode(["sac.extract", 1, self.snapshot.oid, self.state])
                # Report is [header, rows], with a definite-length streamed row array.
                header = b"\x82" + prefix + _array_header(count)
                report_length = len(header) + spool.tell()
                require(report_length <= self.limits.file_bytes, "individual report file length limit", "exhausted_limits")
                self.budget.charge("output_bytes", report_length)
                self.budget.charge("allocated_bytes", report_length)
                self.budget.charge("temporary_bytes", len(header))
                out.write(header)
                spool.seek(0)
                shutil.copyfileobj(spool, out, 65536)
                out.flush()
                os.fsync(out.fileno())
            # Sync created directory entries before namespace publication.
            for directory, _, _ in os.walk(stage, topdown=False, followlinks=False):
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            _install_directory(stage, destination)
            return dict(self.state, destination=str(destination), entries=count)
        finally:
            spool.close()
            if stage.exists():
                shutil.rmtree(stage)


def _array_header(length):
    # Drop the null elements from an encoded header without allocating a list.
    if length < 24:
        return bytes([0x80 + length])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if length < 1 << (width * 8):
            return bytes([0x80 + ai]) + length.to_bytes(width, "big")
    raise SacError("exhausted_limits", "report count overflow")


def _install_directory(stage, destination):
    """Atomic no-clobber directory publication on the two supported POSIX hosts."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        result = libc.renamex_np(os.fsencode(stage), os.fsencode(destination), 4)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(-100, os.fsencode(stage), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise SacError("unsupported_schema", "host lacks atomic no-clobber directory installation")
    if result:
        raise SacError("io_error", f"atomic extraction installation failed: {os.strerror(ctypes.get_errno())}")
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _exclusive_output:
    def __init__(self, path, budget=None):
        self.path, self.budget = Path(path), budget
    def __enter__(self):
        self.temp = tempfile.NamedTemporaryFile(prefix=".sac1-", dir=self.path.parent, delete=False)
        return self
    def __getattr__(self, name):
        return getattr(self.temp, name)
    def write(self, data):
        if self.budget is not None:
            require(self.temp.tell() + len(data) <= self.budget.limits.file_bytes, "individual output file length limit", "exhausted_limits")
            for dimension in ("output_bytes", "allocated_bytes", "temporary_bytes"):
                self.budget.charge(dimension, len(data))
        return self.temp.write(data)
    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.temp.flush()
                os.fsync(self.temp.fileno())
                self.temp.close()
                os.link(self.temp.name, self.path)  # Atomic exclusive installation; never overwrites.
                fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            self.temp.close()
            os.unlink(self.temp.name)


def metadata_json(value):
    """Lossless presentation shared with the native metadata get --json command."""
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["uint", str(value)] if value >= 0 else ["nint", str(-1 - value)]
    if type(value) is str:
        return ["text", value]
    if type(value) is bytes:
        return ["bytes", value.hex()]
    if type(value) is list:
        return ["array", [metadata_json(v) for v in value]]
    if isinstance(value, CborMap) or type(value) is dict:
        pairs = value.items() if type(value) is dict else value
        return ["map", [[metadata_json(k), metadata_json(v)] for k, v in pairs]]
    raise SacError("malformed_input", "unsupported metadata CBOR value")


def _frame(canonical, children):
    oid = digest("SAC1/object", canonical)
    count = len(children)
    header = bytearray(struct.pack("<4sBBHII32sII", b"SO1\0", 0, 1, count,
                                   len(canonical), len(canonical), oid, 0, 0))
    struct.pack_into("<I", header, 48, crc32c(header))
    result = bytes(header) + canonical + b"".join(struct.pack("<QI", *loc) for loc in children)
    return result + bytes((-len(result)) % 8), oid


def salvage(source, destination, expected_snapshot=None, limits=None):
    """Reframe an authorized graph. A supplied expected ID is explicit authority.

    Without one, ordinary live/sealed root admission must succeed. Scanner hits
    and self-hashed orphan roots are never implicitly promoted.
    """
    limits = limits or Limits()
    budget = Budget(limits)
    original = None
    try:
        with Archive(source, limits, budget=budget) as admitted:
            authoritative = admitted.snapshot.oid
            if expected_snapshot is not None:
                require(authoritative == expected_snapshot, "expected snapshot mismatch", "integrity_failure")
            try:
                admitted.verify()
            except SacError as error:
                if error.category == "exhausted_limits":
                    raise
                original = {"category": error.category, "message": str(error),
                            "physical": admitted.state["physical"], "core": admitted.state["core"]}
    except SacError as error:
        if error.category == "exhausted_limits":
            raise
        original = {"category": error.category, "message": str(error)}
        require(expected_snapshot is not None, "salvage needs ordinary root admission or --expected-snapshot", "recovery_required")
        authoritative = bstr(expected_snapshot, 32)
    with Archive(source, limits, admit=False, budget=budget) as archive:
        archive.first, archive.trailer_offset, archive.end = 0, archive.size, archive.size
        archive.policy = 0
        archive.salvage_mode = True
        archive.db.execute("create table candidates (id blob, off integer, span integer)")
        offset = 0
        while offset + 56 <= archive.size:
            archive.budget.charge("frame_visits")
            try:
                raw, _, _, _, _, span = archive._header(offset)
                obj = archive.object(offset, span, raw[16:48])
                archive.budget.charge("temporary_bytes", 512)
                archive.db.execute("insert into candidates values (?,?,?)", (obj.oid, offset, span))
            except SacError as error:
                if error.category == "exhausted_limits":
                    raise
            offset += 8  # A claimed span never skips embedded independent candidates.
        archive.db.execute("create index candidate_ids on candidates(id)")
        archive.db.execute("create table copied (id blob primary key, off integer, span integer)")
        pre = MAGIC + bytes(96 - len(MAGIC))
        pre += digest("SAC1/preamble", pre)
        with _exclusive_output(destination, budget) as out:
            out.write(pre)
            active = set()
            def copy(oid, depth=0):
                archive.budget.depth(depth)
                prior = archive.db.execute("select off,span from copied where id=?", (oid,)).fetchone()
                if prior:
                    return prior
                require(oid not in active, "candidate dependency cycle")
                active.add(oid)
                row = archive.db.execute("select off,span from candidates where id=? order by off limit 1", (oid,)).fetchone()
                require(row is not None, f"missing object {oid.hex()}", "missing_dependency")
                obj = archive.object(*row, oid)
                children = [copy(child, depth + 1) for child in obj.children]
                wire, actual = _frame(obj.canonical, children)
                location = (out.tell(), len(wire))
                out.write(wire)
                archive.db.execute("insert into copied values (?,?,?)", (actual, *location))
                active.remove(oid)
                return location
            root = copy(authoritative)
            # Ensure the snapshot copy is in the bounded control region.
            row = archive.db.execute("select off,span from candidates where id=? order by off limit 1", (authoritative,)).fetchone()
            obj = archive.object(*row, authoritative)
            require(obj.kind == 2 and obj.schema == 1, "authorized ID is not a snapshot")
            if out.tell() - root[0] > 16384:
                children = [archive.db.execute("select off,span from copied where id=?", (oid,)).fetchone() for oid in obj.children]
                wire, _ = _frame(obj.canonical, children)
                root = out.tell(), len(wire)
                out.write(wire)
            canonical = struct.pack("<HHI", 1, 1, 1) + authoritative + cbor_encode([0, None, None])
            commit, commit_id = _frame(canonical, [root])
            commit_offset = out.tell()
            out.write(commit)
            end = out.tell() + 160
            trailer = b"SAC1END\0" + pre[96:] + struct.pack("<QQQQ", 1, end, commit_offset, len(commit)) + commit_id + bytes(24)
            out.write(trailer + digest("SAC1/trailer", trailer))
            out.flush()
            # Validate the new complete graph before publishing it.
            with Archive(out.name, limits, budget=budget) as checked:
                checked.verify()
        return {"snapshot": authoritative.hex(), "publication": "new_sealed_recovery",
                "original_failure": original, "profiles": "semantics_unverified", "trust": "unaccepted"}


def _recovery_geometry(info, stripe):
    block, count = info["block_size"], info["data_shards"]
    k = min(count, (info["source_bytes"] - stripe * block * count + block - 1) // block)
    m = (k * info["parity_shards"] + count - 1) // count
    return k, m


def _recovery_span(info, k, m):
    return 2 * ((k + m) * 32 + 32) + m * info["block_size"]


def _recovery_info(size, block, k, m, source_digest):
    require(1024 <= block <= MIB and block & (block - 1) == 0
            and 1 <= k <= 128 and 1 <= m <= 128 and k + m <= 256,
            "recovery block/code geometry")
    require(1 <= size <= U64, "empty/oversized recovery source")
    stripes = (size + block * k - 1) // (block * k)
    info = {"schema": "sac.recovery.v1", "source_bytes": size, "source_digest": source_digest.hex(),
            "block_size": block, "data_shards": k, "parity_shards": m, "stripes": stripes, "trust": "unaccepted"}
    last_k, last_m = _recovery_geometry(info, stripes - 1)
    info["record_bytes"] = 256 + (stripes - 1) * _recovery_span(info, k, m) + _recovery_span(info, last_k, last_m)
    require(info["record_bytes"] <= U64, "recovery length overflow")
    return info


def _recovery_header(info):
    raw = struct.pack("<8sIIQIHHQQ32s16s", b"SAC1REC\0", 1, 128, info["source_bytes"],
                      info["block_size"], info["data_shards"], info["parity_shards"],
                      info["stripes"], info["record_bytes"], bytes.fromhex(info["source_digest"]), bytes(16))
    return raw + digest("SAC1/recovery-header", raw)


def _recovery_read_at(stream, offset, count):
    stream.seek(offset)
    return stream.read(count)


def _recovery_decode_header(raw):
    if len(raw) != 128 or raw[:8] != b"SAC1REC\0" or digest("SAC1/recovery-header", raw[:96]) != raw[96:]:
        return None
    _, version, header_size, size, block, k, m, stripes, length, source_digest, reserved = struct.unpack("<8sIIQIHHQQ32s16s", raw[:96])
    if version != 1 or header_size != 128 or reserved != bytes(16):
        return None
    try:
        info = _recovery_info(size, block, k, m, source_digest)
        return info if (info["stripes"], info["record_bytes"]) == (stripes, length) else None
    except SacError:
        return None


def _recovery_check(info, limits, *, writing=False):
    block, k, m = info["block_size"], info["data_shards"], info["parity_shards"]
    # Python also retains translated equation temporaries and integer XOR buffers.
    memory = (k + 2 * m + 6) * block + MIB
    require(info["source_bytes"] <= limits.source_bytes and info["record_bytes"] <= (limits.output_bytes if writing else limits.source_bytes)
            and info["stripes"] <= limits.entries and memory <= limits.resident_memory,
            "recovery input, stripes or memory limit", "exhausted_limits")


def recovery_inspect(stream, limits=None):
    """Admit duplicated sidecar headers; no original application is needed."""
    limits = limits or Limits()
    size = stream.seek(0, os.SEEK_END)
    require(size <= limits.source_bytes, "recovery record input limit", "exhausted_limits")
    first = _recovery_decode_header(_recovery_read_at(stream, 0, 128))
    last = _recovery_decode_header(_recovery_read_at(stream, size - 128, 128)) if size >= 256 else None
    require(first is None or last is None or first == last, "conflicting recovery headers", "integrity_failure")
    info = first or last
    require(info is not None, "no intact recovery header", "integrity_failure")
    _recovery_check(info, limits)
    require(size <= info["record_bytes"], "recovery record trailing bytes")
    return info


class _RecoveryField:
    """Independent GF(256) implementation, polynomial 0x11d, generator 2."""
    def __init__(self):
        self.exp, self.log = [0] * 512, [0] * 256
        x = 1
        for i in range(255):
            self.exp[i], self.log[x] = x, i
            x <<= 1
            if x & 256:
                x ^= 0x11d
        for i in range(255, 512):
            self.exp[i] = self.exp[i - 255]

    def mul(self, a, b):
        return self.exp[self.log[a] + self.log[b]] if a and b else 0

    def inv(self, a):
        require(a != 0, "singular recovery matrix")
        return self.exp[255 - self.log[a]]

    def scaled(self, block, factor):
        table = bytes(self.mul(i, factor) for i in range(256))
        return int.from_bytes(block.translate(table), "little")

    def inverse(self, matrix):
        n = len(matrix)
        rows = [row[:] + [int(i == j) for j in range(n)] for i, row in enumerate(matrix)]
        for col in range(n):
            pivot = next((r for r in range(col, n) if rows[r][col]), None)
            require(pivot is not None, "singular recovery matrix", "integrity_failure")
            rows[col], rows[pivot] = rows[pivot], rows[col]
            factor = self.inv(rows[col][col])
            rows[col] = [self.mul(v, factor) for v in rows[col]]
            for row in range(n):
                if row != col:
                    factor = rows[row][col]
                    rows[row] = [v ^ self.mul(factor, p) for v, p in zip(rows[row], rows[col])]
        return [row[n:] for row in rows]


def _recovery_block_hash(stripe, index, block, budget=None):
    if budget is not None:
        budget.charge("hash_bytes", len(block))
    return digest("SAC1/recovery-block", struct.pack("<QH", stripe, index) + block)


def _recovery_meta_hash(stripe, raw, budget=None):
    if budget is not None:
        budget.charge("hash_bytes", len(raw))
    return digest("SAC1/recovery-metadata", struct.pack("<Q", stripe) + raw)


def _recovery_source_hash(source, size, budget):
    source.seek(0)
    hasher = blake3.blake3(b"SAC1/recovery-source\0")
    left = size
    while left:
        raw = source.read(min(left, 64 * 1024))
        require(raw, "source changed during recovery generation", "integrity_failure")
        budget.charge("hash_bytes", len(raw))
        hasher.update(raw)
        left -= len(raw)
    return hasher.digest()


def recovery_create(source, output, percent=10, block_size=16 * 1024, limits=None):
    """Write provisional records; caller must exclude writers and stage output."""
    limits = limits or Limits()
    budget = Budget(limits)
    require(type(percent) is int and 1 <= percent <= 100, "recovery percentage must be 1 through 100")
    size = source.seek(0, os.SEEK_END)
    info = _recovery_info(size, block_size, 100, percent, bytes(32))
    _recovery_check(info, limits, writing=True)
    require(info["record_bytes"] <= limits.temporary_bytes, "recovery temporary limit", "exhausted_limits")
    info["source_digest"] = _recovery_source_hash(source, size, budget).hex()
    output.write(_recovery_header(info))
    source.seek(0)
    second = blake3.blake3(b"SAC1/recovery-source\0")
    field, left = _RecoveryField(), size
    for stripe in range(info["stripes"]):
        budget.charge("frame_visits")
        k, m = _recovery_geometry(info, stripe)
        data = []
        for _ in range(k):
            n = min(left, block_size)
            raw = source.read(n)
            require(len(raw) == n, "source changed during recovery generation", "integrity_failure")
            budget.charge("hash_bytes", len(raw))
            second.update(raw)
            data.append(raw.ljust(block_size, b"\0"))
            left -= n
        parity = []
        for row in range(m):
            budget.charge("edge_visits", k)
            value = 0
            for col, block in enumerate(data):
                value ^= field.scaled(block, field.inv(col ^ (k + row)))
            parity.append(value.to_bytes(block_size, "little"))
        metadata = b"".join(_recovery_block_hash(stripe, i, block, budget) for i, block in enumerate(data + parity))
        metadata += _recovery_meta_hash(stripe, metadata, budget)
        output.write(metadata)
        for block in parity:
            output.write(block)
        output.write(metadata)
    require(second.hexdigest() == info["source_digest"] and source.seek(0, os.SEEK_END) == size,
            "source changed during recovery generation", "integrity_failure")
    output.write(_recovery_header(info))
    return info


def recovery_repair(source, records, output, limits=None):
    """Repair exact bytes into provisional output; discard output on any error."""
    limits = limits or Limits()
    budget = Budget(limits)
    info = recovery_inspect(records, limits)
    require(source.seek(0, os.SEEK_END) <= limits.source_bytes and info["source_bytes"] <= min(limits.output_bytes, limits.temporary_bytes),
            "recovery source/output limit", "exhausted_limits")
    report = dict(info, repaired_data_shards=0, damaged_parity_shards=0, degraded_metadata_copies=0)
    field, offset, position = _RecoveryField(), 128, 0
    hasher = blake3.blake3(b"SAC1/recovery-source\0")
    for stripe in range(info["stripes"]):
        budget.charge("frame_visits")
        k, m = _recovery_geometry(info, stripe)
        b = info["block_size"]
        meta_size = (k + m) * 32 + 32
        def metadata_at(at):
            raw = _recovery_read_at(records, at, meta_size)
            return raw if len(raw) == meta_size and _recovery_meta_hash(stripe, raw[:-32], budget) == raw[-32:] else None
        first, last = metadata_at(offset), metadata_at(offset + meta_size + m * b)
        require(first is None or last is None or first == last, "conflicting recovery metadata", "integrity_failure")
        report["degraded_metadata_copies"] += int(first is None) + int(last is None)
        metadata = first or last
        require(metadata is not None, "no intact recovery stripe metadata", "integrity_failure")
        data, missing = [], []
        for col in range(k):
            at = position + col * b
            n = min(b, info["source_bytes"] - at)
            raw = _recovery_read_at(source, at, n)
            block = raw.ljust(b, b"\0")
            if len(raw) != n or _recovery_block_hash(stripe, col, block, budget) != metadata[col * 32:(col + 1) * 32]:
                missing.append(col)
            data.append(block)
        rows, equations = [], []
        for row in range(m):
            block = _recovery_read_at(records, offset + meta_size + row * b, b)
            if len(block) != b or _recovery_block_hash(stripe, k + row, block, budget) != metadata[(k + row) * 32:(k + row + 1) * 32]:
                report["damaged_parity_shards"] += 1
            elif len(rows) < len(missing):
                rows.append(row)
                equations.append(block)
        require(len(rows) >= len(missing), "recovery redundancy exhausted in stripe", "integrity_failure")
        if missing:
            inverse = field.inverse([[field.inv(col ^ (k + row)) for col in missing] for row in rows])
            for i, row in enumerate(rows):
                budget.charge("edge_visits", k)
                value = int.from_bytes(equations[i], "little")
                for col, block in enumerate(data):
                    if col not in missing:
                        value ^= field.scaled(block, field.inv(col ^ (k + row)))
                equations[i] = value.to_bytes(b, "little")
            for i, col in enumerate(missing):
                budget.charge("edge_visits", len(missing))
                value = 0
                for j, equation in enumerate(equations):
                    value ^= field.scaled(equation, inverse[i][j])
                data[col] = value.to_bytes(b, "little")
                require(_recovery_block_hash(stripe, col, data[col], budget) == metadata[col * 32:(col + 1) * 32],
                        "reconstructed recovery block digest", "integrity_failure")
            report["repaired_data_shards"] += len(missing)
        for block in data:
            n = min(b, info["source_bytes"] - position)
            budget.charge("output_bytes", n)
            budget.charge("hash_bytes", n)
            output.write(block[:n])
            hasher.update(block[:n])
            position += n
        offset += _recovery_span(info, k, m)
    require(hasher.hexdigest() == info["source_digest"], "recovered source digest mismatch (wrong or stale records)", "integrity_failure")
    budget.charge("frame_visits", 0)
    return report


def _embedded_discover(source, limits):
    """Explicit physical scan, independent of preamble, frames and root admission."""
    budget = Budget(limits)
    size = source.seek(0, os.SEEK_END)
    require(size <= limits.source_bytes and limits.resident_memory >= 4 * MIB,
            "embedded recovery input/memory limit", "exhausted_limits")
    identity, segments, position = None, {}, 0
    while position < size:
        budget.charge("frame_visits")
        data = _recovery_read_at(source, position, MIB + 7)
        begin = 0
        while True:
            found = data.find(b"SAC1RSEG", begin)
            if found < 0:
                break
            begin = found + 1
            budget.charge("edge_visits")
            at = position + found
            raw = _recovery_read_at(source, at, 320)
            if len(raw) != 320 or raw[8:16] != struct.pack("<II", 1, 320) or raw[92:96] != bytes(4):
                continue
            budget.charge("hash_bytes", 288)
            if digest("SAC1/recovery-segment", raw[:288]) != raw[288:]:
                continue
            source_bytes, record_bytes, offset, length, self_at, physical = struct.unpack("<QQQIQQ", raw[48:92])
            if (self_at != at or not 288 <= source_bytes <= limits.source_bytes or record_bytes > limits.source_bytes
                    or not 1 <= length <= MIB or offset + length > record_bytes or physical > size
                    or physical < source_bytes - 160 or not (physical == at + 320 or physical + length == at)):
                continue
            candidate = (raw[16:48], source_bytes, record_bytes, raw[96:256], raw[256:288])
            require(identity is None or identity == candidate, "ambiguous embedded recovery checkpoints", "integrity_failure")
            identity = candidate
            segment = offset, length, physical
            require(offset not in segments or segments[offset] == segment, "overlapping embedded recovery segments", "integrity_failure")
            segments[offset] = segment
            require(len(segments) <= limits.entries and len(segments) * 256 + 4 * MIB <= limits.resident_memory,
                    "embedded discovery index limit", "exhausted_limits")
        position += max(1, len(data) - 7)
    require(identity is not None, "no embedded recovery records for this layout", "integrity_failure")
    segments = sorted(segments.values())
    require(all(a[0] + a[1] <= b[0] for a, b in zip(segments, segments[1:])),
            "overlapping embedded recovery segments", "integrity_failure")
    return identity, segments


class _EmbeddedView:
    def __init__(self, source, identity, segments=None):
        self.source, self.identity, self.segments, self.position = source, identity, segments, 0

    def seek(self, offset, whence=os.SEEK_SET):
        length = self.identity[2] if self.segments is not None else self.identity[1]
        position = offset if whence == os.SEEK_SET else self.position + offset if whence == os.SEEK_CUR else length + offset
        require(0 <= position <= U64, "embedded view seek")
        self.position = position
        return position

    def read(self, count=-1):
        import bisect
        length = self.identity[2] if self.segments is not None else self.identity[1]
        count = min(length - self.position, count) if count >= 0 else length - self.position
        if count <= 0:
            return b""
        output = bytearray()
        while len(output) < count:
            at, left = self.position + len(output), count - len(output)
            if self.segments is None:
                trailer_at = self.identity[1] - 160
                if at >= trailer_at:
                    output += self.identity[3][at - trailer_at:at - trailer_at + left]
                else:
                    n = min(left, trailer_at - at)
                    output += _recovery_read_at(self.source, at, n).ljust(n, b"\0")
            else:
                # Keyed bisect avoids retaining a second index beside the segment map.
                i = bisect.bisect_right(self.segments, at, key=lambda s: s[0]) - 1
                segment = self.segments[i] if i >= 0 else None
                if segment is not None and at < segment[0] + segment[1]:
                    n = min(left, segment[0] + segment[1] - at)
                    output += _recovery_read_at(self.source, segment[2] + at - segment[0], n).ljust(n, b"\0")
                else:
                    n = min(left, self.segments[i + 1][0] - at) if i + 1 < len(self.segments) else left
                    output += bytes(n)
        self.position += count
        return bytes(output)


def recovery_inspect_embedded(source, limits=None):
    limits = limits or Limits()
    identity, segments = _embedded_discover(source, limits)
    info = recovery_inspect(_EmbeddedView(source, identity, segments), limits)
    require((info["source_digest"], info["source_bytes"], info["record_bytes"]) ==
            (identity[0].hex(), identity[1], identity[2]), "embedded checkpoint binding", "integrity_failure")
    return dict(info, storage="embedded", protected_snapshot=identity[4].hex(), segments=len(segments))


def recovery_repair_embedded(source, output, limits=None):
    """Restore the sealed checkpoint; parity/profile themselves are excluded."""
    limits = limits or Limits()
    identity, segments = _embedded_discover(source, limits)
    records = _EmbeddedView(source, identity, segments)
    info = recovery_inspect(records, limits)
    require((info["source_digest"], info["source_bytes"], info["record_bytes"]) ==
            (identity[0].hex(), identity[1], identity[2]), "embedded checkpoint binding", "integrity_failure")
    return recovery_repair(_EmbeddedView(source, identity), records, output, limits)


def _recovery_command(args, limits):
    with open(args.source, "rb") as source:
        if args.command == "recovery-inspect":
            require(args.destination is None and args.output is None, "recovery inspect takes one path")
            return recovery_inspect_embedded(source, limits) if args.embedded else recovery_inspect(source, limits)
        require(args.destination is not None, "recovery destination required")
        if args.command == "recovery-create":
            require(args.output is None, "recovery create takes two paths")
        elif args.embedded:
            require(args.output is None, "embedded repair takes source and destination")
        else:
            require(args.output is not None, "recovery repair takes damaged source, records and destination")
        destination = Path(args.output if args.command == "recovery-repair" and not args.embedded else args.destination)
        with tempfile.TemporaryDirectory(prefix=".sac-recovery-", dir=destination.parent) as temp:
            stage = Path(temp) / "output"
            with open(stage, "xb") as output:
                os.chmod(stage, 0o600)
                if args.command == "recovery-create":
                    result = recovery_create(source, output,
                                             10 if args.redundancy_percent is None else args.redundancy_percent,
                                             16 * 1024 if args.block_size is None else args.block_size, limits)
                elif args.embedded:
                    result = recovery_repair_embedded(source, output, limits)
                else:
                    with open(args.destination, "rb") as records:
                        result = recovery_repair(source, records, output, limits)
                output.flush()
                os.fsync(output.fileno())
            os.link(stage, destination)  # atomic no-clobber install
            parent = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return result


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) >= 2 and argv[0] == "recovery":
        argv[:2] = ["--help"] if argv[1] in ("--help", "-h", "help") else ["recovery-" + argv[1]]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "verify", "attestations", "extract", "metadata", "salvage", "recovery-create", "recovery-inspect", "recovery-repair"))
    parser.add_argument("source")
    parser.add_argument("destination", nargs="?")
    parser.add_argument("output", nargs="?", help="recovery repair output archive")
    parser.add_argument("--redundancy-percent", type=int, help="recovery create parity percentage (default 10)")
    parser.add_argument("--block-size", type=int, help="recovery create block size (default 16384)")
    parser.add_argument("--embedded", action="store_true", help="inspect/repair the sac.recovery.v1 profile")
    parser.add_argument("--key", help="metadata key to read as canonical CBOR")
    parser.add_argument("--json", action="store_true", help="metadata --key: emit lossless typed JSON")
    parser.add_argument("--expected-snapshot", help="independently trusted 32-byte snapshot ID, hex; salvage only")
    parser.add_argument("--max-source-bytes", type=int, default=Limits.source_bytes)
    parser.add_argument("--max-output-bytes", type=int, default=Limits.output_bytes)
    parser.add_argument("--max-temporary-bytes", type=int, default=Limits.temporary_bytes)
    parser.add_argument("--max-entries", type=int, default=Limits.entries)
    parser.add_argument("--max-seconds", type=float, default=Limits.seconds)
    for name in ("decoded_bytes", "hash_bytes", "frame_visits", "edge_visits", "file_bytes", "allocated_bytes",
                 "resident_memory", "depth", "path_bytes"):
        parser.add_argument("--max-" + name.replace("_", "-"), type=int, default=getattr(Limits, name))
    args = parser.parse_args(argv)
    limits = Limits(source_bytes=args.max_source_bytes, output_bytes=args.max_output_bytes,
                    temporary_bytes=args.max_temporary_bytes, entries=args.max_entries, seconds=args.max_seconds,
                    **{name: getattr(args, "max_" + name) for name in ("decoded_bytes", "hash_bytes", "frame_visits", "edge_visits", "file_bytes",
                                                                      "allocated_bytes", "resident_memory", "depth", "path_bytes")})
    try:
        require(all(value > 0 and math.isfinite(value) for value in vars(limits).values()), "limits must be positive and finite")
        if args.command in ("extract", "salvage"):
            require(args.destination is not None, "destination required")
        require(args.key is None or args.command == "metadata", "--key is only for metadata")
        require(not args.json or (args.command == "metadata" and args.key is not None), "--json requires metadata --key")
        require(args.output is None or args.command == "recovery-repair", "third path is only for recovery repair")
        require(not args.embedded or args.command in ("recovery-inspect", "recovery-repair"),
                "--embedded is only for recovery inspect/repair")
        require(args.command == "recovery-create" or (args.redundancy_percent is None and args.block_size is None),
                "--redundancy-percent and --block-size are only for recovery create")
        if args.command.startswith("recovery-"):
            require(args.expected_snapshot is None, "--expected-snapshot is only for salvage")
            result = _recovery_command(args, limits)
        elif args.command == "salvage":
            expected = bytes.fromhex(args.expected_snapshot) if args.expected_snapshot else None
            result = salvage(args.source, args.destination, expected, limits)
        else:
            require(args.expected_snapshot is None, "--expected-snapshot is only for salvage")
            with Archive(args.source, limits) as archive:
                if args.command == "metadata":
                    if args.key is not None:
                        require(args.destination is None, "metadata --key does not take a destination")
                        data = archive.metadata_get(args.key)
                        require(data is not None, "metadata key not found", "missing_dependency")
                        output = (json.dumps(metadata_json(cbor_decode(data, text_keys=False)), ensure_ascii=True) + "\n").encode() if args.json else data
                        archive.budget.charge("output_bytes", len(output))
                        sys.stdout.buffer.write(output)
                        return 0
                    if args.destination is not None:
                        result = archive.recover_metadata(args.destination)
                    else:
                        for key, _, entry in archive.metadata_entries():
                            row = json.dumps({"key": key, "encoded_bytes": str(entry[3][0])}, ensure_ascii=True) + "\n"
                            archive.budget.charge("output_bytes", len(row.encode()))
                            sys.stdout.write(row)
                        result = archive.state
                elif args.command == "extract":
                    result = archive.extract(args.destination)
                elif args.command == "verify":
                    result = archive.verify()
                elif args.command == "attestations":
                    for outcome in archive.attestation_outcomes():
                        print(json.dumps(outcome, ensure_ascii=True))
                    result = archive.state
                else:
                    archive.verify()
                    for path, _, entry in archive.entries():
                        print(json.dumps({"path": [name.hex() for name in path], "type": entry[1],
                                          "length": str(entry[3][0]) if entry[1] == 0 else None}))
                    result = archive.state
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except (SacError, OSError, ValueError, RecursionError, sqlite3.Error) as error:
        print(json.dumps({"error": getattr(error, "category", "io_error"), "message": str(error),
                          "dimension": getattr(error, "dimension", None), "complete": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

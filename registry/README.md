# SAC Registry

SAC Registry publishes immutable sealed SAC1 archives. Releases have an exact
`namespace/name@version`, a SAC snapshot and commit ID, and a SHA-256 digest and
length for the downloadable encoding. A release can select any profile declared
in its snapshot. Plain SAC1 archives also work.

Install both commands from the SAC checkout. The `sac registry` entry point finds
the companion beside `sac` or on `PATH`. An explicit `SAC_REGISTRY_BIN` path can
select a different companion build. The `sac-registry` executable also accepts
the same arguments directly.

```sh
cargo install --locked --path .
cargo install --locked --path registry
```

## Filesystem

The filesystem registry is a directory. Pass a directory path or a local
`file://` URL to `--registry`. The HTTP server opens that same directory, so
local and HTTP operations see each other's published releases.

```sh
sac registry --registry ./registry publish team/sample@1 ./sample.sac
sac registry --registry ./registry list --profile splice.program-db --profile-version 1
sac registry --registry ./registry fetch team/sample@1 --output downloaded.sac
```

Publish a sealed export of a live archive. For example,
`splice export program.sac --output shared.sac --selection portable` produces a
publishable investigation. Archive validation covers SAC framing, reachable
objects, resource integrity, and declared profile roots. Each application owns
validation of its profile's meaning and the authorization to act on its contents.

When present in `sac.metadata.v1`, the catalog copies text values for
`sac.registry.title` and `sac.registry.description` and a list of text values for
`sac.registry.tags`. Catalog values are capped at 4 KiB encoded bytes per key.
Use `list --tag TAG` for exact tag matches. The embedded metadata remains
available inside the exact downloaded file.

## HTTP

```sh
sac registry --registry ./registry serve --listen 127.0.0.1:8788 --writable
sac registry --registry http://127.0.0.1:8788 publish team/sample@1 ./sample.sac
sac registry --registry http://127.0.0.1:8788 resolve team/sample@1
sac read "http://127.0.0.1:8788/v1/archives/TRANSPORT_SHA256" path/in/archive
```

The server is read-only by default. For non-loopback service use
`SAC_REGISTRY_TOKEN` and an HTTPS reverse proxy. The token controls reads and
writes. Clients allow plaintext HTTP on loopback. Requests keep the token on
the configured origin and refuse redirects. Use the `sac` CLI's optional HTTP
feature for resource ranges on unauthenticated endpoints. Use
`sac-registry fetch` to retrieve a file from a bearer-protected registry.

- `GET /v1/releases` accepts optional `profile`, `version` and `tag` filters.
- `GET /v1/releases/NAMESPACE/NAME/VERSION` returns one release record.
- `POST /v1/objects/missing` returns the subset of a frame-body inventory
  still needed by the filesystem registry. Each JSON row has `object` (SAC
  canonical ID), `sha256` (encoded body digest), and `bytes`.
- `PUT /v1/objects/OBJECT/SHA256` stores one missing encoded frame body.
  Supply `If-None-Match: *` and the original 56-byte SAC frame header as hex in
  `Sac-Frame`. The server verifies the canonical object ID and encoded digest.
- `PUT /v1/releases/NAMESPACE/NAME/VERSION` publishes after all bodies arrive.
  The CLI sends the release and exact layout as JSON with media type
  `application/vnd.sac.registry.publication.v1+json`. A direct upload can send
  sealed SAC bytes as `application/octet-stream` and select an optional
  `Sac-Profile`. Both forms require `If-None-Match: *`. An identical retry
  succeeds and a differing release under the same coordinate returns 409.
- `HEAD` and `GET /v1/archives/SHA256` use a strong `"sha256:HEX"` ETag. GET
  supports one byte range and `If-Match` pinning.

The registry directory is private operator storage. Use the HTTP routes to
serve downloads. They reconstruct the exact stream and expose stable offsets.

## OCI

```sh
sac registry --registry ./registry oci-push team/sample@1 --repository oci://registry.example.org/team/sac
sac registry --registry ./imported oci-pull team/sample@1 \
  --repository oci://registry.example.org/team/sac --manifest-digest sha256:HEX
```

Supply an operator-issued Bearer token through `SAC_REGISTRY_TOKEN` as needed.
`oci+http://` is available on loopback. The OCI publication result includes
`manifest_digest` and `named`. The client uses a named tag when the server
enforces create-only writes. Otherwise it publishes by immutable manifest
digest. Use `--named` to require a named publication or `--digest-only` to skip
the tag capability probe.

Replace `sha256:HEX` with the manifest digest returned by `oci-push`.
If that result reports `named: true`, you can also pull by the release name
alone. The OCI artifact uses a release JSON
layer, a layout JSON layer, and independently digest-addressed frame bodies.
The client skips bodies already available on the repository and installs the
manifest last. A pull verifies the OCI descriptors, reconstructs the exact
SAC stream, and admits it before publishing a local release. An optional
`--sha256` pins the full transport on pull or fetch.

## Storage and identity

The registry stores each frame body under its SAC canonical object ID and the
SHA-256 of the encoded body. Multiple archives using the same encoding share
the same body bytes even when the frames appear at different offsets. An archive
layout holds the preamble, headers, physical locators, padding, trailer, and
ordered references to those bodies. A different encoding of one canonical
object may have a separate body variant so the original downloads remain byte
exact. The release record becomes visible after the bodies and layout. Content
placed by an interrupted publication can be reused by a later publication.

The local store caps artifacts at 8 GiB by default (configure with
`--max-bytes`), frame count at 100,000, and layouts at 32 MiB. Catalog responses
are capped at 16 MiB and scans at 10,000 release records. OCI manifests are
capped at 4 MiB. The service is intended for an operator-controlled registry.

See [NOTICE](NOTICE) for the Koda Archive source revision and [LICENSE](LICENSE)
for this companion's license.

# Sealed SAC1 privacy

The `privacy-age` feature (enabled by default) encrypts one complete sealed SAC1
archive using the standard age stream format. The built-in writer and opener
accept explicit native X25519 age recipients and unencrypted native age identity
files. They do not invoke a shell, plugin, password prompt, or key service.
Application profile semantics remain the owning application's responsibility;
this operation fully validates physical SAC1 objects, core relationships and
resource contents.

```sh
sac privacy-wrap archive.sac private.sac --recipient age1...
sac privacy-open private.sac recovered.sac --identity /private/path/key.txt
sac verify recovered.sac
```

Recipients and identity files may be repeated. The input and output must be
regular filesystem paths. A live archive must first be exported as sealed SAC1.
The original sealed byte stream, including names, profile records and IDs, is
recovered exactly. Existing destinations are never replaced.

The outer sealed snapshot has no application profiles and exactly the optional
core feature `[null,"sac.privacy.age",1,false]`. Its sole regular resource is
`payload.age`, with empty metadata. The selected Commit has no local child or
attestations, earlier publications or unreachable frames. A generic resource extractor can recover this ciphertext without
understanding privacy. No recipient secret belongs in the container.

Independent recovery can use the reference age implementation:

```sh
sac unpack private.sac encrypted-output
age --decrypt --identity /private/path/key.txt --output recovered.sac encrypted-output/payload.age
sac verify recovered.sac
```

The age tool is external in this example; the built-in SAC commands use the
maintained Rust age implementation. Keep the external identity file available:
extracting ciphertext cannot recover a lost private key. Ciphertext size and the
public age header, including recipient stanzas, are visible.

Both built-in commands privately stage and authenticate inputs before installing
outputs. Plaintext staging files use the operating system's private temporary
file permissions and are removed on success or error. This is ordinary file
cleanup, not a secure-erasure claim. Outputs are synced and installed with
no-clobber semantics only after complete inner/outer validation. The operation
supports one encryption layer; nested privacy wrappers reject.

Common CLI input, output, temporary, memory, entry and elapsed limits also apply.
The API exposes `PrivacyLimits` for explicit operation budgets. It limits the age
header to 64KiB, identity file bytes to 1MiB and identities/recipients to 64 by
default. Temporary bytes count aggregate private input, ciphertext and staged
output; raising output size alone does not raise the temporary budget. The
operation checks elapsed time during streaming and every core validation phase.
Native X25519 operations have bounded key/header counts and no external KDF or
subprocess. It implements sealed whole-container privacy only; live mutation and
private indexed range reads require a separate extension.

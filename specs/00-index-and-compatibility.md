# SAC1 specification index

SAC1 is the current prerelease format for sealed resource archives and durable
live stores. Its normative wire layout, canonical objects, resource schemas,
publication rules and verification boundaries are specified in
[01-sac-core-v1.md](01-sac-core-v1.md).

The current object-graph design replaces all earlier prerelease drafts before
format stabilization. The Rust package remains version 0.2.0; package versions
and wire-format versions are independent. No earlier section container, SACOBJ02
file, or superseded SAC 2 development file is a supported read or migration
interface. Re-create development files from their original inputs.

Application profiles own their schemas and semantic validation. Core resource
integrity does not establish application semantic correctness or publisher trust.

- [Generic container metadata profile](02-generic-metadata-v1.md)
- [Optional recovery records](03-recovery-records-v1.md)
- [Overview, installation and feature boundaries](../README.md)
- [Rust API notes](../docs/api-notes.md)
- [Command-line tools](../docs/sac1-cli.md)
- [Independent recovery](../tools/SAC1_RECOVERY.md)
- [Current conformance vectors](../conformance/README.md)

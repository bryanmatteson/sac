//! Generic SAC1 tools. Binary payloads go to stdout only for `pack -`/`read`.
use crate as sac;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};

type AnyError = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, AnyError>;
const DEFAULT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const HELP: &str = "sac — generic SAC1 tools
usage:
  sac pack <source-directory-or-file> <archive|-> [--live] [--preserve] [--chunk-size N]
  sac list <archive|->
  sac verify <archive|->
  sac extract <archive|-> <new-directory>
  sac unpack <archive|-> <new-destination>
  sac recover <archive|-> <new-destination>
  sac read <archive|URL|-> <resource> [--offset N] [--length N] [--http-statistics]
  sac compact-in-place <live-archive>
  sac reclaim <live-archive> [--no-punch]
  sac compact <archive|-> <new-archive|-> [--strip-local]
  sac recover-live <archive> <new-live-archive> [--strip-local]
  sac salvage <archive|-> <new-archive|-> [--snapshot HEX]
  sac recovery create <quiescent-archive> <new-records> [--redundancy-percent N] [--block-size N]
  sac recovery embed <archive> <new-protected-archive> [--redundancy-percent N] [--block-size N] [--strip-local]
  sac recovery inspect <records-or-archive> [--embedded]
  sac recovery repair <damaged-archive> <records> <new-archive>
  sac recovery repair <damaged-protected-archive> <new-archive> --embedded
  sac metadata list <archive|->
  sac metadata get <archive|-> <key> [--json]
  sac metadata set <live-archive> <key> <value-file|-> [--json] [--strip-local]
  sac metadata remove <live-archive> <key> [--strip-local]
  sac metadata export <archive|-> <new-directory>
  sac inspect <archive>
  sac privacy-wrap <sealed-archive> <new-wrapper> --recipient age1... [--recipient ...]
  sac privacy-open <wrapper> <new-sealed-archive> --identity <key-file> [--identity ...]

Common limits: --max-input-bytes N --max-output-bytes N --max-temp-bytes N
               --max-entries N --max-seconds N --max-memory-bytes N
N is an unsigned decimal integer. Defaults: 64 GiB input/output, 128 GiB
temporary storage, 1,000,000 entries, one hour. Commands creating a new
destination never overwrite an existing path. pack --preserve records
permission bits and modification times. extract restores the tree itself:
recorded names, symbolic links, permission bits and modification times.
unpack writes content/ and report.cbor with host-neutral names and applies
no links or permissions. Same-file maintenance edits
owner-private live files under native reader coordination. Recovery preserves source bytes and never promotes an
orphan live commit. All commands use the current SAC1 format.
";

#[derive(Debug)]
struct CliError {
    code: &'static str,
    message: String,
}
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CliError {}
fn failure(code: &'static str, message: impl Into<String>) -> AnyError {
    Box::new(CliError {
        code,
        message: message.into(),
    })
}

#[derive(Debug)]
struct Args {
    command: String,
    paths: Vec<OsString>,
    live: bool,
    preserve: bool,
    metadata_json: bool,
    no_punch: bool,
    strip_local: bool,
    max_input: u64,
    max_output: u64,
    max_temp: u64,
    max_entries: u64,
    max_seconds: u64,
    max_memory: u64,
    expected_snapshot: Option<[u8; 32]>,
    offset: u64,
    length: Option<u64>,
    chunk_size: u64,
    recovery_percent: u64,
    recovery_block_size: u64,
    embedded_recovery: bool,
    http_statistics: bool,
    recipients: Vec<String>,
    identities: Vec<PathBuf>,
}
impl Args {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let command = arguments.next().unwrap_or_else(|| "help".into());
        let command = if command == "metadata" || command == "recovery" {
            let group = command.to_string_lossy();
            let action = arguments
                .next()
                .ok_or_else(|| failure("Usage", format!("{group} requires an action")))?;
            if matches!(action.to_str(), Some("--help" | "-h" | "help")) {
                return Self::parse([OsString::from("help")]);
            }
            OsString::from(format!(
                "{group}-{}",
                action
                    .to_str()
                    .ok_or_else(|| failure("Usage", "metadata action must be UTF-8"))?
            ))
        } else {
            command
        };
        let command = command
            .to_str()
            .ok_or_else(|| failure("Usage", "command must be UTF-8"))?;
        let mut out = Self {
            command: command.into(),
            paths: Vec::new(),
            live: false,
            preserve: false,
            metadata_json: false,
            no_punch: false,
            strip_local: false,
            max_input: DEFAULT_BYTES,
            max_output: DEFAULT_BYTES,
            max_temp: DEFAULT_BYTES * 2,
            max_entries: 1_000_000,
            max_seconds: 3_600,
            max_memory: 64 << 20,
            expected_snapshot: None,
            offset: 0,
            length: None,
            chunk_size: 256 << 10,
            recovery_percent: 10,
            recovery_block_size: 16 << 10,
            embedded_recovery: false,
            http_statistics: false,
            recipients: Vec::new(),
            identities: Vec::new(),
        };
        let mut literal = false;
        while let Some(argument) = arguments.next() {
            if !literal
                && argument == "--embedded"
                && matches!(out.command.as_str(), "recovery-inspect" | "recovery-repair")
            {
                out.embedded_recovery = true;
                continue;
            }
            if !literal && argument == "--recipient" && out.command == "privacy-wrap" {
                let value = arguments
                    .next()
                    .ok_or_else(|| failure("Usage", "missing recipient"))?;
                out.recipients.push(
                    value
                        .into_string()
                        .map_err(|_| failure("Usage", "recipient must be UTF-8"))?,
                );
                continue;
            }
            if !literal && argument == "--identity" && out.command == "privacy-open" {
                out.identities.push(
                    arguments
                        .next()
                        .ok_or_else(|| failure("Usage", "missing identity path"))?
                        .into(),
                );
                continue;
            }
            if !literal
                && argument == "--json"
                && matches!(out.command.as_str(), "metadata-get" | "metadata-set")
            {
                out.metadata_json = true;
                continue;
            }
            if !literal && argument == "--" {
                literal = true;
                continue;
            }
            if !literal && argument == "--no-punch" && out.command == "reclaim" {
                out.no_punch = true;
                continue;
            }
            if !literal && argument == "--live" {
                if out.command != "pack" {
                    return Err(failure("Usage", "--live is only valid with pack"));
                }
                out.live = true;
                continue;
            }
            if !literal && argument == "--preserve" {
                if out.command != "pack" {
                    return Err(failure("Usage", "--preserve is only valid with pack"));
                }
                out.preserve = true;
                continue;
            }
            if !literal && argument == "--http-statistics" {
                if out.command != "read" {
                    return Err(failure(
                        "Usage",
                        "--http-statistics is only valid with read",
                    ));
                }
                out.http_statistics = true;
                continue;
            }
            if !literal && argument == "--strip-local" {
                if !matches!(
                    out.command.as_str(),
                    "compact"
                        | "recover-live"
                        | "metadata-set"
                        | "metadata-remove"
                        | "recovery-embed"
                ) {
                    return Err(failure(
                        "Usage",
                        "--strip-local is only valid with compact/recover-live/metadata set/remove",
                    ));
                }
                out.strip_local = true;
                continue;
            }
            if !literal && argument == "--snapshot" {
                if out.command != "salvage" {
                    return Err(failure("Usage", "--snapshot is only valid with salvage"));
                }
                let value = arguments.next().ok_or_else(|| {
                    failure("Usage", "--snapshot requires a hexadecimal object ID")
                })?;
                let value = value
                    .to_str()
                    .ok_or_else(|| failure("Usage", "snapshot ID must be hexadecimal"))?;
                let bytes = hex::decode(value)
                    .map_err(|_| failure("Usage", "snapshot ID must be hexadecimal"))?;
                out.expected_snapshot =
                    Some(bytes.try_into().map_err(|_| {
                        failure("Usage", "snapshot ID must contain exactly 32 bytes")
                    })?);
                continue;
            }
            if !literal && argument.to_string_lossy().starts_with("--") {
                let name = argument
                    .to_str()
                    .ok_or_else(|| failure("Usage", "option must be UTF-8"))?;
                let target = match name {
                    "--max-input-bytes" => &mut out.max_input,
                    "--max-output-bytes" => &mut out.max_output,
                    "--max-temp-bytes" => &mut out.max_temp,
                    "--max-entries" => &mut out.max_entries,
                    "--max-seconds" => &mut out.max_seconds,
                    "--max-memory-bytes" => &mut out.max_memory,
                    "--offset" if out.command == "read" => &mut out.offset,
                    "--length" if out.command == "read" => out.length.get_or_insert(0),
                    "--chunk-size" if out.command == "pack" => &mut out.chunk_size,
                    "--redundancy-percent"
                        if matches!(out.command.as_str(), "recovery-create" | "recovery-embed") =>
                    {
                        &mut out.recovery_percent
                    }
                    "--block-size"
                        if matches!(out.command.as_str(), "recovery-create" | "recovery-embed") =>
                    {
                        &mut out.recovery_block_size
                    }
                    _ => return Err(failure("Usage", format!("unknown option {name}"))),
                };
                let value = arguments
                    .next()
                    .ok_or_else(|| failure("Usage", format!("missing value for {name}")))?;
                let digits = value
                    .to_str()
                    .ok_or_else(|| failure("Usage", format!("invalid integer for {name}")))?;
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(failure(
                        "Usage",
                        format!("invalid unsigned integer for {name}"),
                    ));
                }
                *target = digits
                    .parse()
                    .map_err(|_| failure("Usage", format!("integer overflow for {name}")))?;
            } else {
                out.paths.push(argument);
            }
        }
        let count = match out.command.as_str() {
            "help" | "--help" | "-h" => return Ok(out),
            "pack" | "extract" | "unpack" | "recover" | "recover-live" | "salvage" | "read"
            | "compact" | "privacy-wrap" | "privacy-open" => 2,
            "list" | "verify" | "inspect" | "compact-in-place" | "reclaim" | "metadata-list" => 1,
            "metadata-get" | "metadata-remove" | "metadata-export" => 2,
            "metadata-set" => 3,
            "recovery-repair" => {
                if out.embedded_recovery {
                    2
                } else {
                    3
                }
            }
            "recovery-create" | "recovery-embed" => 2,
            "recovery-inspect" => 1,
            _ => return Err(failure("Usage", format!("unknown command {}", out.command))),
        };
        if out.paths.len() != count {
            return Err(failure(
                "Usage",
                format!("{} expects {count} paths", out.command),
            ));
        }
        Ok(out)
    }
}

/// Owns exactly one newly created directory; Drop never removes another path.
struct Scratch {
    path: PathBuf,
}
impl Scratch {
    fn create(parent: &Path) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        for _ in 0..100 {
            let path = parent.join(format!(
                ".sac-{}-{time:x}-{:x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(failure(
            "Io",
            "unable to reserve private temporary directory",
        ))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Input {
    file: File,
    _scratch: Option<Scratch>,
}
impl Input {
    fn open(path: &OsStr, args: &Args) -> Result<Self> {
        if path != "-" {
            let file = File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(failure(
                    "Unsupported",
                    "input must be a regular file or stdin",
                ));
            }
            if file.metadata()?.len() > args.max_input {
                return Err(failure("LimitExceeded", "input byte budget exhausted"));
            }
            return Ok(Self {
                file,
                _scratch: None,
            });
        }
        let scratch = Scratch::create(&std::env::temp_dir())?;
        let path = scratch.path.join("input.sac");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        copy_bounded(
            &mut io::stdin().lock(),
            &mut file,
            args.max_input.min(args.max_temp),
            Duration::from_secs(args.max_seconds),
        )?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            file,
            _scratch: Some(scratch),
        })
    }
}

fn copy_bounded(
    source: &mut impl Read,
    target: &mut impl Write,
    limit: u64,
    elapsed: Duration,
) -> Result<u64> {
    let started = std::time::Instant::now();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if started.elapsed() > elapsed {
            return Err(failure("LimitExceeded", "elapsed-time budget exhausted"));
        }
        // Read one byte beyond the remaining quota only to distinguish EOF.
        let available = limit
            .saturating_sub(total)
            .saturating_add(1)
            .min(buffer.len() as u64) as usize;
        let count = source.read(&mut buffer[..available])?;
        if count == 0 {
            return Ok(total);
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| failure("LimitExceeded", "byte count overflow"))?;
        if total > limit {
            return Err(failure("LimitExceeded", "byte budget exhausted"));
        }
        target.write_all(&buffer[..count])?;
    }
}

/// Regular-file installation is atomic and cannot overwrite any destination.
fn install_file(staged: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged, fs::Permissions::from_mode(0o600))?;
    }
    let file = File::open(staged)?;
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    rustix::fs::fcntl_fullfsync(&file).map_err(io::Error::from)?;
    fs::hard_link(staged, destination)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)?;
    directory.sync_all()?;
    #[cfg(target_os = "macos")]
    rustix::fs::fcntl_fullfsync(&directory).map_err(io::Error::from)?;
    Ok(())
}

fn emit(value: &Json) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

/// Execute the generic tools in this process using standard input/output.
/// `command_name` is the invocation displayed in help, for example `sac` or
/// the subcommand of an embedding application. Arguments exclude that
/// invocation. No application profile decoder or application database
/// admission is required.
pub fn main_with_args(
    command_name: &str,
    arguments: impl IntoIterator<Item = OsString>,
) -> ExitCode {
    match Args::parse(arguments).and_then(|args| run(args, command_name)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let code = error_code(error.as_ref());
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                json!({"schema":"sac.cli-error.v1", "error":{"code":code,"message":error.to_string()}})
            );
            ExitCode::from(if code == "Usage" { 2 } else { 1 })
        }
    }
}

fn run(args: Args, command_name: &str) -> Result<()> {
    if matches!(args.command.as_str(), "help" | "--help" | "-h") {
        print!("{}", HELP.replace("sac ", &format!("{command_name} ")));
        return Ok(());
    }
    if args.max_memory < 48 << 20 {
        return Err(failure(
            "LimitExceeded",
            "native command requires at least 48 MiB resident-memory budget",
        ));
    }
    if matches!(args.command.as_str(), "pack" | "recover-live" | "salvage")
        && args.max_temp < 128 << 10
    {
        return Err(failure(
            "LimitExceeded",
            "temporary-storage budget cannot hold native bootstrap and bounded working metadata",
        ));
    }
    execute(args)
}

fn error_code(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if let Some(error) = error.downcast_ref::<CliError>() {
        return error.code;
    }
    if let Some(error) = error.downcast_ref::<sac::v1::Error>() {
        return match error {
            sac::v1::Error::Io(io) => {
                if io.to_string().contains("LimitExceeded") {
                    "LimitExceeded"
                } else {
                    "Io"
                }
            }
            sac::v1::Error::Corrupt(_) => "Integrity",
            sac::v1::Error::Unsupported(_) => "Unsupported",
            sac::v1::Error::Limit(_) => "LimitExceeded",
            sac::v1::Error::Missing => "MissingDependency",
            sac::v1::Error::Poisoned | sac::v1::Error::RecoveryRequired => "RecoveryRequired",
            sac::v1::Error::Busy => "AdmissionBusy",
        };
    }
    if let Some(io) = error.downcast_ref::<io::Error>() {
        return if io.to_string().contains("LimitExceeded") {
            "LimitExceeded"
        } else {
            "Io"
        };
    }
    "Failure"
}

struct LimitedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.limit.saturating_sub(self.written) {
            return Err(io::Error::other(
                "LimitExceeded: output byte budget exhausted",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(value.as_bytes().to_vec())
}
#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> Result<Vec<u8>> {
    value
        .to_str()
        .map(|s| s.as_bytes().to_vec())
        .ok_or_else(|| failure("Unsupported", "host name has no lossless byte encoding"))
}

fn limits(args: &Args) -> sac::v1::resources::Limits {
    sac::v1::resources::Limits {
        max_entries: args.max_entries,
        max_logical_bytes: args.max_output,
        max_file_bytes: args.max_output,
        max_source_bytes: args.max_input,
        max_temp_bytes: args.max_temp,
        max_elapsed: Duration::from_secs(args.max_seconds),
        max_memory_bytes: usize::try_from(args.max_memory).unwrap_or(usize::MAX),
        ..Default::default()
    }
}

fn entry_json(entry: sac::v1::resources::ResourceEntry) -> Json {
    use sac::v1::resources::EntryKind;
    let name: Option<Vec<&str>> = entry
        .path
        .iter()
        .map(|p| std::str::from_utf8(p).ok())
        .collect();
    json!({
        "schema":"sac.resource.v1",
        "path": name.map(|p|p.join("/")),
        "path_hex":entry.path.iter().map(hex::encode).collect::<Vec<_>>(),
        "kind":match entry.kind {EntryKind::File=>"file",EntryKind::Directory=>"directory",EntryKind::Symlink=>"symlink"},
        "length":entry.length.to_string(),
        "metadata_cbor_hex":hex::encode(sac::v1::cbor::encode(&entry.metadata)),
        "link_target_hex":entry.link_target.map(hex::encode),
    })
}

/// Enforce a scratch-file budget before passing newly encoded objects onward.
/// Charging the uncompressed upper bound is conservative, independent of codec.
struct BoundedStore<S> {
    inner: S,
    reserved: u64,
    limit: u64,
}
impl<S: sac::v1::ObjectStore> sac::v1::ObjectStore for BoundedStore<S> {
    fn get(&self, reference: sac::v1::ObjectRef) -> sac::v1::Result<sac::v1::CanonicalObject> {
        self.inner.get(reference)
    }
    fn get_shared(
        &self,
        reference: sac::v1::ObjectRef,
    ) -> sac::v1::Result<std::sync::Arc<sac::v1::CanonicalObject>> {
        self.inner.get_shared(reference)
    }
    fn physical_identity(&self) -> Option<u64> {
        self.inner.physical_identity()
    }
    fn physical_dependencies(
        &self,
        reference: sac::v1::ObjectRef,
    ) -> sac::v1::Result<Vec<sac::v1::ObjectRef>> {
        self.inner.physical_dependencies(reference)
    }
    fn put(
        &mut self,
        kind: u16,
        version: u16,
        bytes: &[u8],
        children: &[sac::v1::ObjectRef],
    ) -> sac::v1::Result<sac::v1::ObjectRef> {
        let charge = (bytes.len() as u64)
            .checked_add(64)
            .and_then(|n| n.checked_add(children.len() as u64 * 44))
            .ok_or(sac::v1::Error::Limit("scratch bytes"))?;
        if charge > self.limit.saturating_sub(self.reserved) {
            return Err(sac::v1::Error::Limit("scratch bytes"));
        }
        let reference = self.inner.put(kind, version, bytes, children)?;
        self.reserved = self.reserved.max(
            reference
                .address
                .offset
                .checked_add(u64::from(reference.address.length))
                .ok_or(sac::v1::Error::Limit("scratch bytes"))?,
        );
        Ok(reference)
    }
}

/// The core `mode` and `mtime` metadata of one source entry.
#[cfg(unix)]
fn recorded_metadata(metadata: &cap_std::fs::Metadata) -> Result<sac::v1::cbor::Value> {
    use cap_std::fs::MetadataExt;
    use sac::v1::cbor::Value;
    let seconds = metadata.mtime();
    let nanoseconds = u64::try_from(metadata.mtime_nsec())
        .ok()
        .filter(|n| *n <= 999_999_999)
        .ok_or_else(|| failure("Unsupported", "source modification time is out of range"))?;
    Ok(sac::v1::cbor::text_map(vec![
        ("mode", Value::Uint(u64::from(metadata.mode() & 0o7777))),
        (
            "mtime",
            Value::Array(vec![
                if seconds < 0 {
                    Value::NInt(seconds.unsigned_abs() - 1)
                } else {
                    Value::Uint(seconds as u64)
                },
                Value::Uint(nanoseconds),
            ]),
        ),
    ]))
}
#[cfg(not(unix))]
fn recorded_metadata(_: &cap_std::fs::Metadata) -> Result<sac::v1::cbor::Value> {
    Err(failure("Unsupported", "--preserve requires a Unix host"))
}

fn add_source<S: sac::v1::ObjectStore>(
    builder: &mut sac::v1::resources::ArchiveBuilder<'_, S>,
    source: &Path,
    exclude: &Path,
    args: &Args,
) -> Result<()> {
    use cap_std::{ambient_authority, fs::Dir};
    use sac::v1::cbor::Value;
    let metadata = fs::symlink_metadata(source)?;
    let mut count = 0u64;
    let start = std::time::Instant::now();
    #[allow(
        clippy::too_many_arguments,
        reason = "confined recursive walk keeps the directory capability, logical path and shared budgets explicit"
    )]
    fn add<S: sac::v1::ObjectStore>(
        builder: &mut sac::v1::resources::ArchiveBuilder<'_, S>,
        directory: &Dir,
        name: &OsStr,
        physical: &Path,
        exclude: &Path,
        path: &mut Vec<Vec<u8>>,
        count: &mut u64,
        start: std::time::Instant,
        args: &Args,
    ) -> Result<()> {
        if physical == exclude {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(args.max_seconds) {
            return Err(failure(
                "LimitExceeded",
                "pack elapsed-time budget exhausted",
            ));
        }
        *count = count
            .checked_add(1)
            .ok_or_else(|| failure("LimitExceeded", "entry count overflow"))?;
        if *count > args.max_entries || path.len() > 256 {
            return Err(failure(
                "LimitExceeded",
                "pack entry/depth budget exhausted",
            ));
        }
        let metadata = directory.symlink_metadata(name)?;
        let recorded = if args.preserve {
            recorded_metadata(&metadata)?
        } else {
            Value::Map(Vec::new())
        };
        if metadata.is_symlink() {
            let target = directory.read_link_contents(name)?;
            builder.add_symlink(path, &os_bytes(target.as_os_str())?)?;
        } else if metadata.is_dir() {
            builder.add_directory_with_metadata(path, recorded)?;
            let child = directory.open_dir(name)?;
            for entry in child.entries()? {
                let entry = entry?;
                path.push(os_bytes(&entry.file_name())?);
                add(
                    builder,
                    &child,
                    &entry.file_name(),
                    &physical.join(entry.file_name()),
                    exclude,
                    path,
                    count,
                    start,
                    args,
                )?;
                path.pop();
            }
        } else if metadata.is_file() {
            if metadata.len() > args.max_input {
                return Err(failure(
                    "LimitExceeded",
                    "source file byte budget exhausted",
                ));
            }
            let mut options = cap_std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                );
            }
            let file = directory.open_with(name, &options)?;
            if !file.metadata()?.is_file() {
                return Err(failure(
                    "Unsupported",
                    "source changed to a non-regular file",
                ));
            }
            builder.add_reader_with_metadata(path, file, recorded)?;
        } else {
            return Err(failure("Unsupported", "source contains a special file"));
        }
        Ok(())
    }
    if metadata.is_dir() {
        let root = Dir::open_ambient_dir(source, ambient_authority())?;
        let canonical = fs::canonicalize(source)?;
        for entry in root.entries()? {
            let entry = entry?;
            let mut path = vec![os_bytes(&entry.file_name())?];
            add(
                builder,
                &root,
                &entry.file_name(),
                &canonical.join(entry.file_name()),
                exclude,
                &mut path,
                &mut count,
                start,
                args,
            )?;
        }
    } else {
        let parent = source
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = source
            .file_name()
            .ok_or_else(|| failure("Usage", "source has no file name"))?;
        let root = Dir::open_ambient_dir(parent, ambient_authority())?;
        add(
            builder,
            &root,
            name,
            source,
            exclude,
            &mut vec![os_bytes(name)?],
            &mut count,
            start,
            args,
        )?;
    }
    Ok(())
}

fn incarnation() -> Result<[u8; 16]> {
    #[cfg(unix)]
    {
        let mut random = File::open("/dev/urandom")?;
        let mut instance = [0u8; 16];
        loop {
            random.read_exact(&mut instance)?;
            if instance != [0; 16] {
                break;
            }
        }
        Ok(instance)
    }
    #[cfg(not(unix))]
    {
        Err(failure(
            "Unsupported",
            "this native writer host lacks a supported durability contract",
        ))
    }
}

fn copy_limits(args: &Args) -> sac::v1::resources::Limits {
    let mut result = limits(args);
    result.max_temp_bytes = args.max_temp / 16;
    result
}

fn occupied_store(store: &sac::v1::NativeStore) -> Result<u64> {
    store
        .file_len()
        .checked_add(store.temporary_bytes()?)
        .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))
}

fn available_temp(args: &Args, occupied: u64) -> Result<u64> {
    args.max_temp
        .checked_sub(occupied)
        .ok_or_else(|| failure("LimitExceeded", "temporary-storage budget exhausted"))
}

fn native_staging_budget(args: &Args, occupied: u64) -> Result<u64> {
    let remaining = available_temp(args, occupied)?;
    // Check before creating the native bootstrap or its private index.
    if remaining < 32 << 10 {
        return Err(failure(
            "LimitExceeded",
            "temporary-storage budget cannot hold native bootstrap",
        ));
    }
    Ok(remaining)
}

fn write_archive(
    args: &Args,
    occupied_temp: u64,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let output = &args.paths[1];
    if output == "-" {
        let mut writer = LimitedWriter {
            inner: io::stdout().lock(),
            written: 0,
            limit: args.max_output,
        };
        write(&mut writer)?;
        writer.flush()?;
    } else {
        let destination = Path::new(output);
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let scratch = Scratch::create(parent)?;
        let staged = scratch.path.join("output.sac");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        let available = args
            .max_temp
            .saturating_sub(occupied_temp)
            .saturating_sub(copy_limits(args).max_temp_bytes);
        let mut writer = LimitedWriter {
            inner: file,
            written: 0,
            limit: args.max_output.min(available),
        };
        write(&mut writer)?;
        writer.flush()?;
        drop(writer);
        // Validate the actual on-disk artifact before making its name visible.
        let mut validation_limits = limits(args);
        validation_limits.max_temp_bytes = args
            .max_temp
            .saturating_sub(occupied_temp)
            .saturating_sub(fs::metadata(&staged)?.len());
        sac::v1::NativeReader::open(&staged)?.validate_with_limits(&validation_limits)?;
        install_file(&staged, destination)?;
    }
    Ok(())
}

fn execute(args: Args) -> Result<()> {
    use sac::v1::resources::{ArchiveBuilder, ArchiveReader};
    use sac::v1::{NativeReader, NativeStore, ObjectStore};
    if args.command.starts_with("recovery-") {
        return recovery_command(&args);
    }
    if args.command.starts_with("metadata-") {
        return metadata_command(&args);
    }
    if matches!(args.command.as_str(), "compact-in-place" | "reclaim") {
        #[cfg(unix)]
        {
            if args.paths[0] == "-" {
                return Err(failure(
                    "Usage",
                    "same-file maintenance requires a regular file path",
                ));
            }
            let mut store = NativeStore::open(Path::new(&args.paths[0]), true)?;
            let options = sac::ReclamationOptions {
                limits: limits(&args),
                punch_holes: !args.no_punch,
                ..Default::default()
            };
            let statistics = if args.command == "reclaim" {
                store.reclaim_online(options)?
            } else {
                store.compact_in_place(options)?
            };
            println!(
                "{}",
                json!({"file_bytes_before":statistics.file_bytes_before,"file_bytes_after":statistics.file_bytes_after,"allocated_bytes_before":statistics.allocated_bytes_before,"allocated_bytes_after":statistics.allocated_bytes_after,"retained_frames":statistics.retained_frames,"dead_frames":statistics.dead_frames,"punched_bytes":statistics.punched_bytes,"indexed_reuse_bytes":statistics.indexed_reuse_bytes,"moved_bytes":statistics.moved_bytes,"journal_peak_bound_bytes":statistics.journal_peak_bytes,"elapsed_ns":statistics.elapsed_ns})
            );
            return Ok(());
        }
        #[cfg(not(unix))]
        return Err(failure(
            "Unsupported",
            "same-file maintenance is supported on Unix hosts",
        ));
    }
    if matches!(args.command.as_str(), "privacy-wrap" | "privacy-open") {
        #[cfg(feature = "privacy-age")]
        {
            let budgets = sac::v1::privacy::PrivacyLimits {
                resources: limits(&args),
                max_input_bytes: args.max_input,
                max_output_bytes: args.max_output,
                max_temp_bytes: args.max_temp,
                ..Default::default()
            };
            if args.paths.iter().any(|p| p == "-") {
                return Err(failure(
                    "Usage",
                    "privacy commands require regular file paths",
                ));
            }
            if args.command == "privacy-wrap" {
                sac::v1::privacy::wrap_file(
                    Path::new(&args.paths[0]),
                    Path::new(&args.paths[1]),
                    &args.recipients,
                    budgets,
                )?;
            } else {
                sac::v1::privacy::open_file(
                    Path::new(&args.paths[0]),
                    Path::new(&args.paths[1]),
                    &args.identities,
                    budgets,
                )?;
            }
            return emit(
                &json!({"schema":"sac.privacy.v1","operation":args.command,"output":Path::new(&args.paths[1]).display().to_string()}),
            );
        }
        #[cfg(not(feature = "privacy-age"))]
        return Err(failure(
            "Unsupported",
            "build lacks the privacy-age feature",
        ));
    }
    if args.command == "pack" {
        if args.paths[1] != "-" && Path::new(&args.paths[1]).try_exists()? {
            return Err(failure("Io", "destination already exists"));
        }
        if args.live && args.paths[1] == "-" {
            return Err(failure(
                "Usage",
                "live output requires a seekable named destination",
            ));
        }
        let scratch = Scratch::create(&std::env::temp_dir())?;
        let path = scratch.path.join("builder.sac");
        let mut store = NativeStore::create_live(&path, incarnation()?)?;
        store.set_decoded_cache_budget(8 << 20);
        store.set_temporary_disk_budget(args.max_temp / 16)?;
        store.set_total_temporary_disk_budget(args.max_temp - args.max_temp / 4)?;
        let mut store = BoundedStore {
            inner: store,
            reserved: 12_288,
            limit: args.max_temp / 2,
        };
        let mut build_limits = limits(&args);
        build_limits.max_temp_bytes = args.max_temp / 4;
        build_limits.max_logical_bytes = build_limits.max_logical_bytes.min(args.max_input);
        build_limits.max_file_bytes = build_limits.max_file_bytes.min(args.max_input);
        let mut builder = ArchiveBuilder::bulk(&mut store, build_limits)?;
        builder.set_chunk_size(
            usize::try_from(args.chunk_size)
                .map_err(|_| failure("Usage", "chunk size exceeds host range"))?,
        )?;
        add_source(
            &mut builder,
            Path::new(&args.paths[0]),
            &fs::canonicalize(&scratch.path)?,
            &args,
        )?;
        let snapshot = builder.finish()?;
        let mut verify_limits = limits(&args);
        verify_limits.max_temp_bytes = available_temp(&args, occupied_store(&store.inner)?)?;
        ArchiveReader::open(&store, snapshot, verify_limits)?.verify()?;
        if args.live {
            // Copy only the selected closure; builder updates may leave dead pages.
            let destination = Path::new(&args.paths[1]);
            let parent = destination
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let installation = Scratch::create(parent)?;
            let staged = installation.path.join("output.sac");
            let occupied = occupied_store(&store.inner)?;
            let budget = native_staging_budget(
                &args,
                occupied
                    .checked_add(copy_limits(&args).max_temp_bytes)
                    .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
            )?;
            let mut output = NativeStore::create_live(&staged, incarnation()?)?;
            output.set_temporary_disk_budget(args.max_temp / 16)?;
            output.set_total_temporary_disk_budget(budget)?;
            let remaining = args
                .max_temp
                .saturating_sub(store.inner.file_len())
                .saturating_sub(store.inner.temporary_bytes()?)
                .saturating_sub(args.max_temp / 8);
            let mut output = BoundedStore {
                inner: output,
                reserved: 12_288,
                limit: args.max_output.min(remaining).saturating_sub(64 << 10),
            };
            let mut copy = sac::v1::ClosureCopy::new_with_disk_budget(args.max_temp / 16)?;
            let snapshot = copy.copy_root(&store, &mut output, snapshot)?;
            output.inner.publish(snapshot)?;
            drop(copy);
            drop(output);
            let mut validation_limits = limits(&args);
            validation_limits.max_temp_bytes = available_temp(
                &args,
                occupied
                    .checked_add(fs::metadata(&staged)?.len())
                    .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
            )?;
            NativeReader::open(&staged)?.validate_with_limits(&validation_limits)?;
            install_file(&staged, destination)?;
        } else {
            let occupied = store
                .inner
                .file_len()
                .checked_add(store.inner.temporary_bytes()?)
                .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?;
            write_archive(&args, occupied, |writer| {
                sac::v1::pack_snapshot_with_limits(&store, snapshot, writer, copy_limits(&args))?;
                Ok(())
            })?;
        }
        return Ok(());
    }
    if args.command == "inspect" {
        return inspect(&args);
    }
    if args.paths[0]
        .to_str()
        .is_some_and(|path| path.starts_with("http://") || path.starts_with("https://"))
    {
        if args.command != "read" {
            return Err(failure(
                "Usage",
                "HTTP sources currently support the read command",
            ));
        }
        #[cfg(feature = "http")]
        return read_http(&args);
        #[cfg(not(feature = "http"))]
        return Err(failure(
            "Unsupported",
            "HTTP reads require building sac with --features http",
        ));
    }
    if args.http_statistics {
        return Err(failure(
            "Usage",
            "--http-statistics requires an HTTP source",
        ));
    }
    let input = Input::open(&args.paths[0], &args)?;
    if args.command == "salvage" {
        return salvage(&args, input);
    }
    let source = NativeReader::open_file(input.file.try_clone()?)?;
    source.set_decoded_cache_budget(8 << 20);
    let snapshot = source
        .reader()
        .snapshot()
        .ok_or_else(|| failure("MissingDependency", "selected commit has no snapshot"))?;
    let spool = if input._scratch.is_some() {
        input.file.metadata()?.len()
    } else {
        0
    };
    let mut read_limits = limits(&args);
    read_limits.max_temp_bytes = read_limits.max_temp_bytes.saturating_sub(spool);
    let reader = ArchiveReader::open(&source, snapshot, read_limits)?;
    match args.command.as_str() {
        "list" => {
            let mut stdout = LimitedWriter {
                inner: io::stdout().lock(),
                written: 0,
                limit: args.max_output,
            };
            reader.visit_entries(&mut |entry| {
                serde_json::to_writer(&mut stdout, &entry_json(entry)).map_err(io::Error::other)?;
                stdout.write_all(b"\n")?;
                Ok(())
            })?;
        }
        "verify" => {
            let physical = source.validate_with_limits(reader.limits())?;
            let metadata_state =
                match sac::v1::metadata::MetadataReader::open(&source, snapshot, limits(&args)) {
                    Ok(Some(metadata)) => {
                        metadata.verify()?;
                        "verified"
                    }
                    Ok(None) => "absent",
                    Err(sac::v1::Error::Unsupported(_)) => "unsupported",
                    Err(error) => return Err(error.into()),
                };
            let _core = reader.verify_commit(
                source
                    .root()
                    .ok_or_else(|| failure("MissingDependency", "no selected commit"))?
                    .root,
            )?;
            let commit = source.get(
                source
                    .root()
                    .ok_or_else(|| failure("MissingDependency", "no selected commit"))?
                    .root,
            )?;
            let sac::v1::cbor::Value::Array(fields) = sac::v1::cbor::decode(&commit.bytes)? else {
                return Err(failure("Malformed", "commit body is not an array"));
            };
            let attestations = if let Some(sac::v1::cbor::Value::Uint(index)) = fields.get(1) {
                let reference = *commit
                    .children
                    .get(
                        usize::try_from(*index)
                            .map_err(|_| failure("Malformed", "attestation index overflow"))?,
                    )
                    .ok_or_else(|| failure("Malformed", "attestation child out of bounds"))?;
                sac::v1::attestation::assess_catalogue(&source.get(reference)?,snapshot.hash)?.into_iter().map(|outcome|json!({"index":outcome.index,"structure":outcome.structure.as_str(),"signature":"unaccepted","purpose":outcome.purpose,"snapshot":outcome.snapshot.map(|id|id.to_string()),"detail":outcome.detail})).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            emit(
                &json!({"schema":"sac.verification.v1","snapshot":snapshot.hash.to_string(),"physical":"verified","core":"verified","metadata_profile":metadata_state,"profile":"unchecked","whole_resource_digest":"unchecked","trust":"unaccepted","attestations":attestations,"objects":physical.objects.to_string(),"decoded_bytes":physical.decoded_bytes.to_string(),"recovery_diagnostics":source.reader().recovery_diagnostics}),
            )?;
        }
        "unpack" | "recover" => {
            // Recovery never scans/promotes an unselected live trailer.
            source.validate_with_limits(reader.limits())?;
            let report = reader.extract(Path::new(&args.paths[1]))?;
            emit(
                &json!({"schema":"sac.extraction-result.v1","snapshot":snapshot.hash.to_string(),"destination":Path::new(&args.paths[1]).display().to_string(),"report":{"entries":report.entries.to_string(),"files":report.files.to_string(),"logical_bytes":report.logical_bytes.to_string(),"mapped_entries":report.mapped_entries.to_string(),"report_path":report.report_path.display().to_string(),"physical_checked":report.physical_checked,"core_checked":report.core_checked,"profile_checked":report.profile_checked},"recovery_diagnostics":source.reader().recovery_diagnostics}),
            )?;
        }
        "extract" => {
            source.validate_with_limits(reader.limits())?;
            let report = reader.extract_tree(Path::new(&args.paths[1]))?;
            emit(
                &json!({"schema":"sac.tree-extraction.v1","snapshot":snapshot.hash.to_string(),"destination":Path::new(&args.paths[1]).display().to_string(),"entries":report.entries.to_string(),"files":report.files.to_string(),"logical_bytes":report.logical_bytes.to_string(),"recovery_diagnostics":source.reader().recovery_diagnostics}),
            )?;
        }
        "read" => read_resource(&reader, &args)?,
        "compact" | "recover-live" => {
            source.validate_with_limits(reader.limits())?;
            reader.verify()?;
            let commit = source
                .root()
                .ok_or_else(|| failure("MissingDependency", "no selected commit"))?
                .root;
            let object = source.get(commit)?;
            let fields = sac::v1::cbor::decode(&object.bytes)?;
            let sac::v1::cbor::Value::Array(fields) = fields else {
                return Err(failure("Malformed", "commit body is not an array"));
            };
            if fields.get(2) != Some(&sac::v1::cbor::Value::Null) && !args.strip_local {
                return Err(failure(
                    "Unsupported",
                    "commit has local authority; explicitly select --strip-local for portable compaction or fresh live recovery",
                ));
            }
            if args.command == "recover-live" {
                if args.paths[1] == "-" {
                    return Err(failure(
                        "Usage",
                        "live recovery requires a named seekable output",
                    ));
                }
                let destination = Path::new(&args.paths[1]);
                let parent = destination
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let installation = Scratch::create(parent)?;
                let staged = installation.path.join("output.sac");
                let budget = native_staging_budget(
                    &args,
                    spool
                        .checked_add(copy_limits(&args).max_temp_bytes)
                        .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
                )?;
                let mut output = NativeStore::create_live(&staged, incarnation()?)?;
                output.set_temporary_disk_budget(args.max_temp / 16)?;
                output.set_total_temporary_disk_budget(budget)?;
                let available = args
                    .max_temp
                    .saturating_sub(spool)
                    .saturating_sub(args.max_temp / 8);
                let mut output = BoundedStore {
                    inner: output,
                    reserved: 12_288,
                    limit: args.max_output.min(available).saturating_sub(64 << 10),
                };
                let mut copier = sac::v1::ClosureCopy::new_with_disk_budget(args.max_temp / 16)?;
                let mut portable = object;
                let mut children = vec![snapshot];
                let attestation = match &fields[1] {
                    sac::v1::cbor::Value::Uint(index) => {
                        let index = usize::try_from(*index)
                            .map_err(|_| failure("Malformed", "attestation index overflow"))?;
                        let reference = *portable.children.get(index).ok_or_else(|| {
                            failure("Malformed", "attestation child out of bounds")
                        })?;
                        children.push(reference);
                        sac::v1::cbor::Value::Uint(1)
                    }
                    sac::v1::cbor::Value::Null => sac::v1::cbor::Value::Null,
                    _ => return Err(failure("Malformed", "invalid attestation index")),
                };
                let mut copied = Vec::new();
                for child in children {
                    copied.push(copier.copy_root(&source, &mut output, child)?);
                }
                portable.bytes = sac::v1::cbor::encode(&sac::v1::cbor::Value::Array(vec![
                    sac::v1::cbor::Value::Uint(0),
                    attestation,
                    sac::v1::cbor::Value::Null,
                ]));
                let commit = output.put(1, 1, &portable.bytes, &copied)?;
                output.inner.publish_commit(commit)?;
                drop(copier);
                drop(output);
                let mut validation_limits = limits(&args);
                validation_limits.max_temp_bytes = available_temp(
                    &args,
                    spool
                        .checked_add(fs::metadata(&staged)?.len())
                        .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
                )?;
                NativeReader::open(&staged)?.validate_with_limits(&validation_limits)?;
                install_file(&staged, destination)?;
                emit(
                    &json!({"schema":"sac.live-recovery.v1","snapshot":snapshot.hash.to_string(),"generation":"1","recovery_diagnostics":source.reader().recovery_diagnostics}),
                )?;
            } else {
                write_archive(&args, spool, |writer| {
                    sac::v1::pack_commit_with_limits(&source, commit, writer, copy_limits(&args))?;
                    Ok(())
                })?;
            }
        }
        _ => return Err(failure("Usage", "unsupported command")),
    }
    Ok(())
}

fn recovery_command(args: &Args) -> Result<()> {
    use sac::v1::recovery::{self, RecoveryLimits, RecoveryOptions};
    if args.paths.iter().any(|p| p == "-") {
        return Err(failure(
            "Usage",
            "recovery records require regular file paths",
        ));
    }
    let limits = RecoveryLimits {
        max_source_bytes: args.max_input,
        max_record_bytes: args.max_input,
        max_output_bytes: args.max_output.min(args.max_temp),
        max_memory_bytes: args.max_memory,
        max_stripes: args.max_entries,
        max_duration: Duration::from_secs(args.max_seconds),
    };
    let info_json = |info: recovery::RecoveryInfo| {
        json!({
            "schema":"sac.recovery.v1", "source_bytes":info.source_bytes,
            "source_digest":hex::encode(info.source_digest), "stripes":info.stripes,
            "record_bytes":info.record_bytes, "block_size":info.options.block_size,
            "data_shards":info.options.data_shards, "parity_shards":info.options.parity_shards,
            "trust":"unaccepted"
        })
    };
    let mut input = Input::open(&args.paths[0], args)?;
    if args.command == "recovery-inspect" {
        if args.embedded_recovery {
            let info = recovery::embedded::inspect(&mut input.file, &limits)?;
            let mut result = info_json(info.recovery);
            result["storage"] = json!("embedded");
            result["protected_snapshot"] = json!(info.protected_snapshot.to_string());
            return emit(&result);
        }
        return emit(&info_json(recovery::inspect(&mut input.file, &limits)?));
    }
    if args.command == "recovery-embed" {
        let mut options = RecoveryOptions::with_percent(
            u16::try_from(args.recovery_percent)
                .map_err(|_| failure("Usage", "invalid recovery percentage"))?,
        )?;
        options.block_size = u32::try_from(args.recovery_block_size)
            .map_err(|_| failure("Usage", "invalid recovery block size"))?;
        let mut recovery_limits = limits.clone();
        recovery_limits.max_record_bytes = args.max_output;
        let info = recovery::embedded::embed_file(
            Path::new(&args.paths[0]),
            Path::new(&args.paths[1]),
            options,
            &recovery::embedded::EmbeddedLimits {
                recovery: recovery_limits,
                resources: crate::cli::limits(args),
                max_temp_bytes: args.max_temp,
            },
            args.strip_local,
        )?;
        let mut result = info_json(info.recovery);
        result["storage"] = json!("embedded");
        result["protected_snapshot"] = json!(info.protected_snapshot.to_string());
        return emit(&result);
    }
    let destination = Path::new(args.paths.last().unwrap());
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let scratch = Scratch::create(parent)?;
    let staged = scratch.path.join("recovery-output");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let result = if args.command == "recovery-create" {
        let percent = u16::try_from(args.recovery_percent)
            .map_err(|_| failure("Usage", "invalid recovery percentage"))?;
        let mut options = RecoveryOptions::with_percent(percent)?;
        options.block_size = u32::try_from(args.recovery_block_size)
            .map_err(|_| failure("Usage", "invalid recovery block size"))?;
        // Output quotas also bound the eventual sidecar, independently of its input cap.
        let create_limits = RecoveryLimits {
            max_record_bytes: limits.max_output_bytes,
            ..limits
        };
        info_json(recovery::create(
            &mut input.file,
            &mut output,
            options,
            &create_limits,
        )?)
    } else {
        let report = if args.embedded_recovery {
            recovery::embedded::repair(&mut input.file, &mut output, &limits)?
        } else {
            let mut records = Input::open(&args.paths[1], args)?;
            recovery::repair(&mut input.file, &mut records.file, &mut output, &limits)?
        };
        let mut result = info_json(report.info);
        result["repaired_data_shards"] = json!(report.repaired_data_shards);
        result["damaged_parity_shards"] = json!(report.damaged_parity_shards);
        result["degraded_metadata_copies"] = json!(report.degraded_metadata_copies);
        result
    };
    output.sync_all()?;
    drop(output);
    install_file(&staged, destination)?;
    emit(&result)
}

fn resource_path(path: &OsStr) -> Result<Vec<Vec<u8>>> {
    let bytes = os_bytes(path)?;
    let path: Vec<Vec<u8>> = bytes.split(|b| *b == b'/').map(<[u8]>::to_vec).collect();
    // The resource reader validates raw components, including traversal names.
    Ok(path)
}

fn inspect(args: &Args) -> Result<()> {
    let input = Input::open(&args.paths[0], args)?;
    let reader = sac::v1::NativeReader::open_file(input.file)?;
    emit(
        &json!({"schema":"sac.inspection.v1","snapshot":reader.reader().snapshot().map(|r|r.hash.to_string()),"generation":reader.root().map(|p|p.generation.to_string()),"admission":"root-integrity-only","recovery_diagnostics":reader.reader().recovery_diagnostics}),
    )
}

struct RawInput(std::sync::Mutex<File>);
impl sac::v1::ReadAt for RawInput {
    fn len(&self) -> sac::v1::Result<u64> {
        Ok(self
            .0
            .lock()
            .map_err(|_| io::Error::other("input lock poisoned"))?
            .metadata()?
            .len())
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> sac::v1::Result<()> {
        use std::io::{Seek, SeekFrom};
        let mut file = self
            .0
            .lock()
            .map_err(|_| io::Error::other("input lock poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(bytes)?;
        Ok(())
    }
}

fn salvage(args: &Args, input: Input) -> Result<()> {
    let spool = if input._scratch.is_some() {
        input.file.metadata()?.len()
    } else {
        0
    };
    let available = available_temp(args, spool)?;
    let budget = native_staging_budget(
        args,
        spool
            .checked_add(copy_limits(args).max_temp_bytes)
            .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
    )?;
    let scratch = Scratch::create(&std::env::temp_dir())?;
    let mut inner =
        sac::v1::NativeStore::create_live(scratch.path.join("repaired.sac"), incarnation()?)?;
    inner.set_temporary_disk_budget(args.max_temp / 16)?;
    inner.set_total_temporary_disk_budget(budget)?;
    inner.set_decoded_cache_budget(8 << 20);
    let mut destination = BoundedStore {
        inner,
        reserved: 12_288,
        limit: available / 2,
    };
    let source = RawInput(std::sync::Mutex::new(input.file.try_clone()?));
    let report = sac::v1::resources::salvage(
        &source,
        args.expected_snapshot.map(sac::v1::ObjectHash),
        &mut destination,
        copy_limits(args),
    )?;
    let mut verify_limits = limits(args);
    verify_limits.max_temp_bytes = available_temp(
        args,
        spool
            .checked_add(occupied_store(&destination.inner)?)
            .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?,
    )?;
    sac::v1::resources::ArchiveReader::open(&destination, report.snapshot, verify_limits)?
        .verify()?;
    let occupied = destination
        .inner
        .file_len()
        .checked_add(destination.inner.temporary_bytes()?)
        .and_then(|n| n.checked_add(spool))
        .ok_or_else(|| failure("LimitExceeded", "temporary byte count overflow"))?;
    write_archive(args, occupied, |writer| {
        sac::v1::pack_snapshot_with_limits(
            &destination,
            report.snapshot,
            writer,
            copy_limits(args),
        )?;
        Ok(())
    })?;
    writeln!(
        io::stderr().lock(),
        "{}",
        json!({"schema":"sac.salvage-result.v1","snapshot":report.snapshot.hash.to_string(),"report":{"scanned_bytes":report.scanned_bytes.to_string(),"candidates":report.candidates.to_string(),"authority":report.authority,"selected_commit":report.selected_commit.map(|hash| hash.to_string()),"attachments_preserved":report.attachments_preserved,"repaired":report.repaired},"source_preserved":true,"commit_attestations_preserved":false})
    )?;
    Ok(())
}

fn read_resource<S: sac::v1::ObjectStore + ?Sized>(
    reader: &sac::v1::resources::ArchiveReader<'_, S>,
    args: &Args,
) -> Result<()> {
    let path = resource_path(&args.paths[1])?;
    if args.length.is_none() && args.offset == 0 {
        let mut writer = LimitedWriter {
            inner: io::stdout().lock(),
            written: 0,
            limit: args.max_output,
        };
        reader.read_to(&path, &mut writer)?;
    } else {
        let length = args
            .length
            .ok_or_else(|| failure("Usage", "--offset requires --length"))?;
        if length > args.max_output || length > 16 << 20 {
            return Err(failure(
                "LimitExceeded",
                "range response must fit the 16 MiB buffer budget",
            ));
        }
        let bytes = reader.read_range(
            &path,
            args.offset,
            usize::try_from(length).map_err(|_| failure("LimitExceeded", "host range length"))?,
        )?;
        io::stdout().lock().write_all(&bytes)?;
    }
    Ok(())
}
#[cfg(feature = "http")]
fn read_http(args: &Args) -> Result<()> {
    use sac::v1::{
        PositionalStore, ReadAt,
        http::{HttpLimits, HttpSource},
        resources::ArchiveReader,
    };
    let url = args.paths[0]
        .to_str()
        .ok_or_else(|| failure("Usage", "HTTP URL must be UTF-8"))?;
    let policy = HttpLimits {
        request_timeout: Duration::from_secs(args.max_seconds.min(30)),
        max_wire_bytes: args.max_input,
        ..HttpLimits::interactive()
    };
    let source = HttpSource::open(url, policy)?;
    if source.len()? > args.max_input {
        return Err(failure(
            "LimitExceeded",
            "HTTP representation exceeds input byte budget",
        ));
    }
    let store = PositionalStore::open(source)?;
    let snapshot = store
        .reader()
        .snapshot()
        .ok_or_else(|| failure("MissingDependency", "selected commit has no snapshot"))?;
    let reader = ArchiveReader::open(&store, snapshot, limits(args))?;
    read_resource(&reader, args)?;
    if args.http_statistics {
        let stats = store.source.statistics();
        writeln!(
            io::stderr().lock(),
            "{}",
            json!({"schema":"sac.http-statistics.v1","discovery_requests":stats.discovery_requests,"range_requests":stats.range_requests,"logical_bytes":stats.logical_bytes,"requested_bytes":stats.requested_bytes,"response_bytes":stats.response_bytes,"cache_hits":stats.cache_hits,"cache_resident_bytes":stats.cache_resident_bytes})
        )?;
    }
    Ok(())
}

fn metadata_json(value: &sac::v1::cbor::Value) -> Json {
    use sac::v1::cbor::Value as V;
    match value {
        V::Uint(n) => json!(["uint", n.to_string()]),
        V::NInt(n) => json!(["nint", n.to_string()]),
        V::Bytes(bytes) => json!(["bytes", hex::encode(bytes)]),
        V::Text(text) => json!(["text", text]),
        V::Array(values) => json!([
            "array",
            values.iter().map(metadata_json).collect::<Vec<_>>()
        ]),
        V::Map(entries) => json!([
            "map",
            entries
                .iter()
                .map(|e| json!([metadata_json(&e.key), metadata_json(&e.value)]))
                .collect::<Vec<_>>()
        ]),
        V::Bool(b) => json!(["bool", b]),
        V::Null => json!(["null"]),
    }
}
fn metadata_from_json(value: Json) -> Result<sac::v1::cbor::Value> {
    use sac::v1::cbor::{self, Value as V};
    Ok(match value {
        Json::Null => V::Null,
        Json::Bool(b) => V::Bool(b),
        Json::Number(n) => {
            if let Some(n) = n.as_u64() {
                V::Uint(n)
            } else if let Some(n) = n.as_i64() {
                V::NInt(n.unsigned_abs() - 1)
            } else {
                return Err(failure(
                    "Usage",
                    "metadata JSON numbers must be integers; use CBOR for lossless binary values",
                ));
            }
        }
        Json::String(text) => V::Text(text),
        Json::Array(values) => V::Array(
            values
                .into_iter()
                .map(metadata_from_json)
                .collect::<Result<_>>()?,
        ),
        Json::Object(values) => {
            let mut entries = Vec::new();
            for (key, value) in values {
                entries.push((key, metadata_from_json(value)?));
            }
            cbor::text_map(
                entries
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.clone()))
                    .collect(),
            )
        }
    })
}
fn metadata_command(args: &Args) -> Result<()> {
    use sac::v1::metadata::{MAX_VALUE_BYTES, MetadataEditor, MetadataReader};
    use sac::v1::{NativeReader, NativeStore, ObjectStore, cbor};
    let key = || {
        args.paths
            .get(1)
            .and_then(|s| s.to_str())
            .ok_or_else(|| failure("Usage", "metadata key must be UTF-8"))
    };
    if matches!(args.command.as_str(), "metadata-set" | "metadata-remove") {
        if args.paths[0] == "-" {
            return Err(failure(
                "Usage",
                "metadata edits require a named live archive",
            ));
        }
        // Read and validate input before opening the archive for mutation.
        let bytes = if args.command == "metadata-set" {
            let ceiling = (MAX_VALUE_BYTES as u64)
                .min(args.max_input)
                .min(args.max_memory / 4);
            let mut input: Box<dyn Read> = if args.paths[2] == "-" {
                Box::new(io::stdin().lock())
            } else {
                Box::new(File::open(&args.paths[2])?)
            };
            let mut bytes = Vec::new();
            input.by_ref().take(ceiling + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > ceiling {
                return Err(failure("LimitExceeded", "metadata input byte budget"));
            }
            if args.metadata_json {
                bytes = cbor::encode(&metadata_from_json(serde_json::from_slice(&bytes)?)?);
            }
            Some(bytes)
        } else {
            None
        };
        let mut store = NativeStore::open(Path::new(&args.paths[0]), true)?;
        if store.file_len() > args.max_input {
            return Err(failure("LimitExceeded", "archive input byte budget"));
        }
        store.set_decoded_cache_budget(8 << 20);
        store.set_temporary_disk_budget(args.max_temp)?;
        store.set_file_byte_limit(
            store
                .file_len()
                .checked_add(args.max_output)
                .ok_or_else(|| failure("LimitExceeded", "metadata append bound"))?,
        )?;
        let snapshot = store
            .reader()
            .snapshot()
            .ok_or_else(|| failure("MissingDependency", "no selected snapshot"))?;
        let commit = store.get(
            store
                .root()
                .ok_or_else(|| failure("MissingDependency", "no selected commit"))?
                .root,
        )?;
        let cbor::Value::Array(fields) = cbor::decode(&commit.bytes)? else {
            return Err(failure("Malformed", "commit body"));
        };
        if fields[1] != cbor::Value::Null {
            return Err(failure(
                "Unsupported",
                "metadata changes alter snapshot identity; an attested snapshot requires an application-managed transaction",
            ));
        }
        if fields[2] != cbor::Value::Null && !args.strip_local {
            return Err(failure(
                "Unsupported",
                "metadata update has a local attachment; explicitly select --strip-local",
            ));
        }
        let mut editor = MetadataEditor::open(&mut store, snapshot, limits(args))?;
        let changed = match bytes {
            Some(bytes) => editor.set_encoded(key()?, &bytes)?,
            None => editor.remove(key()?)?,
        };
        let next = editor.finish()?;
        if changed {
            store.publish(next)?;
        }
        return emit(
            &json!({"schema":"sac.metadata-update.v1","key":key()?,"changed":changed,"snapshot":next.hash.to_string()}),
        );
    }
    let input = Input::open(&args.paths[0], args)?;
    let source = NativeReader::open_file(input.file.try_clone()?)?;
    source.set_decoded_cache_budget(8 << 20);
    let snapshot = source
        .reader()
        .snapshot()
        .ok_or_else(|| failure("MissingDependency", "no selected snapshot"))?;
    let mut policy = limits(args);
    if input._scratch.is_some() {
        policy.max_temp_bytes = policy
            .max_temp_bytes
            .saturating_sub(input.file.metadata()?.len());
    }
    let metadata = MetadataReader::open(&source, snapshot, policy)?;
    if args.command == "metadata-list" {
        if let Some(metadata) = metadata {
            let mut out = LimitedWriter {
                inner: io::stdout().lock(),
                written: 0,
                limit: args.max_output,
            };
            metadata.visit_keys(&mut |key, length| {
                serde_json::to_writer(
                    &mut out,
                    &json!({"key":key,"encoded_bytes":length.to_string()}),
                )
                .map_err(io::Error::other)?;
                out.write_all(b"\n")?;
                Ok(())
            })?;
        }
        return Ok(());
    }
    let metadata =
        metadata.ok_or_else(|| failure("MissingDependency", "snapshot has no metadata profile"))?;
    if args.command == "metadata-export" {
        let report = metadata.export(Path::new(&args.paths[1]))?;
        return emit(
            &json!({"schema":"sac.metadata-export.v1","snapshot":snapshot.hash.to_string(),"entries":report.entries.to_string(),"destination":Path::new(&args.paths[1]).display().to_string()}),
        );
    }
    let bytes = metadata
        .get_encoded(key()?)?
        .ok_or_else(|| failure("MissingDependency", "metadata key not found"))?;
    let mut out = LimitedWriter {
        inner: io::stdout().lock(),
        written: 0,
        limit: args.max_output,
    };
    if args.metadata_json {
        serde_json::to_writer(&mut out, &metadata_json(&cbor::decode(&bytes)?))?;
        out.write_all(b"\n")?;
    } else {
        out.write_all(&bytes)?;
    }
    Ok(())
}

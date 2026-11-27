use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use sac_registry::{DEFAULT_MAX_BYTES, Error, Reference, Registry, Release, Result, http, oci};
use std::{fs::File, net::SocketAddr, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(about = "Publish and retrieve immutable sealed SAC1 archives")]
struct Args {
    /// Local registry directory or an HTTP(S) endpoint.
    #[arg(
        long,
        global = true,
        env = "SAC_REGISTRY",
        default_value = ".sac-registry"
    )]
    registry: String,
    #[arg(long, global = true, default_value_t = DEFAULT_MAX_BYTES)]
    max_bytes: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish a sealed archive under an exact namespace/name@version.
    Publish {
        reference: Reference,
        archive: PathBuf,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show the exact release and its artifact identity.
    Resolve { reference: Reference },
    /// List releases, optionally selecting a declared profile and version.
    List {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, requires = "profile")]
        profile_version: Option<u32>,
        #[arg(long)]
        tag: Option<String>,
    },
    /// Retrieve and verify the exact sealed archive at a new path.
    Fetch {
        reference: Reference,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        sha256: Option<String>,
    },
    /// Serve a local registry, read-only unless --writable is supplied.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: SocketAddr,
        #[arg(long)]
        writable: bool,
    },
    /// Publish a local release as a manifest with shared blobs in an OCI repository.
    OciPush {
        reference: Reference,
        #[arg(long)]
        repository: String,
        /// Require an immutable named OCI release.
        #[arg(long, conflicts_with = "digest_only")]
        named: bool,
        /// Publish by the immutable OCI manifest digest, without probing tags.
        #[arg(long)]
        digest_only: bool,
    },
    /// Import an OCI release and verify its sealed archive before local publication.
    OciPull {
        reference: Reference,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        manifest_digest: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
    },
}

fn output(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer(std::io::stdout().lock(), value)?;
    println!();
    Ok(())
}

fn main() -> ExitCode {
    let args =
        if std::env::var_os("SAC_REGISTRY_COMMAND").is_some_and(|value| value == "sac registry") {
            let matches = Args::command().bin_name("sac registry").get_matches();
            Args::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
        } else {
            Args::parse()
        };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sac-registry: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<()> {
    if args.max_bytes == 0 {
        return Err(Error::Invalid(
            "maximum artifact size must be positive".into(),
        ));
    }
    let token = match std::env::var("SAC_REGISTRY_TOKEN") {
        Ok(token) => Some(token),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(Error::Invalid("SAC_REGISTRY_TOKEN must be UTF-8".into()));
        }
    };
    let token = token.as_deref();
    if args.registry.starts_with("https://") || args.registry.starts_with("http://") {
        return remote(args, token);
    }
    let path = if args.registry.starts_with("file://") {
        reqwest::Url::parse(&args.registry)
            .ok()
            .filter(|url| url.query().is_none() && url.fragment().is_none())
            .and_then(|url| url.to_file_path().ok())
            .ok_or_else(|| Error::Invalid("expected a local file:// registry URL".into()))?
    } else {
        PathBuf::from(&args.registry)
    };
    let registry = Registry::open(path, args.max_bytes)?;
    match args.command {
        Command::Publish {
            reference,
            archive,
            profile,
        } => output(&registry.publish(&reference, profile.as_deref(), File::open(archive)?)?),
        Command::Resolve { reference } => output(&registry.resolve(&reference)?),
        Command::List {
            profile,
            profile_version,
            tag,
        } => output(&registry.list(profile.as_deref(), profile_version, tag.as_deref())?),
        Command::Fetch {
            reference,
            output: path,
            sha256,
        } => {
            let release = registry.resolve(&reference)?;
            check_pin(&release, sha256.as_deref())?;
            output(&registry.fetch(&reference, path)?)
        }
        Command::Serve { listen, writable } => {
            if !listen.ip().is_loopback() && token.is_none() {
                return Err(Error::Invalid(
                    "non-loopback serving requires SAC_REGISTRY_TOKEN and a TLS reverse proxy"
                        .into(),
                ));
            }
            let app = http::router(registry, writable, token)?;
            tokio::runtime::Runtime::new()?.block_on(async move {
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("SAC Registry listening on {}", listener.local_addr()?);
                axum::serve(listener, app).await?;
                Ok(())
            })
        }
        Command::OciPush {
            reference,
            repository,
            named,
            digest_only,
        } => {
            let client = oci::Client::new(&repository, token)?;
            let publication = if named {
                client.push_with_naming(&registry, &reference, oci::Naming::RequireName)?
            } else if digest_only {
                client.push_with_naming(&registry, &reference, oci::Naming::DigestOnly)?
            } else {
                client.push(&registry, &reference)?
            };
            output(&publication)
        }
        Command::OciPull {
            reference,
            repository,
            manifest_digest,
            sha256,
        } => output(&oci::Client::new(&repository, token)?.pull_manifest(
            &registry,
            &reference,
            manifest_digest.as_deref(),
            sha256.as_deref(),
        )?),
    }
}

fn remote(args: Args, token: Option<&str>) -> Result<()> {
    let registry = http::Client::new(&args.registry, token)?;
    match args.command {
        Command::Publish {
            reference,
            archive,
            profile,
        } => output(&registry.publish(
            &reference,
            profile.as_deref(),
            File::open(archive)?,
            args.max_bytes,
        )?),
        Command::Resolve { reference } => output(&registry.resolve(&reference)?),
        Command::List {
            profile,
            profile_version,
            tag,
        } => output(&registry.list(profile.as_deref(), profile_version, tag.as_deref())?),
        Command::Fetch {
            reference,
            output: path,
            sha256,
        } => output(&registry.fetch(&reference, &path, args.max_bytes, sha256.as_deref())?),
        _ => Err(Error::Invalid(
            "this command requires a local registry directory".into(),
        )),
    }
}

fn check_pin(release: &Release, pin: Option<&str>) -> Result<()> {
    if pin.is_some_and(|pin| release.artifact.sha256 != pin) {
        return Err(Error::Integrity("release digest pin"));
    }
    Ok(())
}

//! Standalone entrypoint for the shared generic SAC tools.
fn main() -> std::process::ExitCode {
    sac::cli::main_with_args("sac", std::env::args_os().skip(1))
}

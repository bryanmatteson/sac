#!/bin/sh
# Local continuous integration for SAC.
#
# SAC has no hosted CI. Run this script on request, before you publish a
# change. Each job writes its output to target/ci/<job>.log. The script runs
# every selected job, prints a summary, and exits nonzero if a job failed.
#
#   tools/ci.sh              run all jobs
#   tools/ci.sh rust python  run the named jobs
#   tools/ci.sh --list       list the jobs
#
# Environment:
#   CARGO   cargo command for the ordinary jobs (default: cargo)
#   PYTHON  Python 3 interpreter with the packages in
#           tools/sac1-requirements.txt (default: python3)
#   RUST_TEST_THREADS  test threads in each test program (default: 1)
set -u

cd "$(dirname "$0")/.." || exit 2

CARGO="${CARGO:-cargo}"
PYTHON="${PYTHON:-python3}"

# Run the tests of each test program on one thread. Some tests start a child
# process. For a short time, the new child holds a copy of each file lock that
# the test program has open. A parallel test that closes a store and opens it
# again in that time gets a Busy error. The time is long on a loaded computer.
RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
export RUST_TEST_THREADS
ALL_JOBS="rust core-only features msrv fuzz-build package python"
FEATURES="trust compression native http privacy-age serde"
LOGS="target/ci"

describe() {
    case "$1" in
        rust) echo "format check, clippy and tests with all features" ;;
        core-only) echo "clippy and tests with no default features" ;;
        features) echo "tests with each optional feature alone" ;;
        msrv) echo "build with the minimum supported Rust version" ;;
        fuzz-build) echo "build the fuzz targets (nightly, cargo-fuzz)" ;;
        package) echo "build and list the crate package" ;;
        python) echo "independent Python reader and conformance vectors" ;;
        *) return 1 ;;
    esac
}

# Run one command and stop the job at the first failure.
step() {
    echo "+ $*"
    "$@"
}

job_rust() {
    step $CARGO fmt --all --check &&
        step $CARGO clippy --all-targets --all-features -- -D warnings &&
        step $CARGO test --all-features
}

job_core_only() {
    step $CARGO clippy --all-targets --no-default-features -- -D warnings &&
        step $CARGO test --no-default-features
}

# Each optional feature must build and pass its tests alone. A feature that
# depends on another feature by accident passes the all-features job and
# fails for the user who enables only that feature.
job_features() {
    for feature in $FEATURES; do
        step $CARGO test --no-default-features --features "$feature" || return 1
    done
}

job_msrv() {
    version=$(sed -n 's/^rust-version *= *"\(.*\)"$/\1/p' Cargo.toml | head -1)
    if [ -z "$version" ]; then
        echo "Cargo.toml has no rust-version"
        return 1
    fi
    if ! rustup run "$version" rustc --version >/dev/null 2>&1; then
        echo "Rust $version is not installed. Install it with:"
        echo "  rustup toolchain install $version --profile minimal"
        return 1
    fi
    step cargo "+$version" build --no-default-features &&
        step cargo "+$version" build --all-features
}

job_fuzz_build() {
    if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
        echo "cargo-fuzz or the nightly toolchain is not installed. Install them with:"
        echo "  rustup toolchain install nightly --profile minimal"
        echo "  cargo install cargo-fuzz --locked"
        return 1
    fi
    step cargo +nightly fuzz build --dev
}

# --allow-dirty lets the job run on a working tree with uncommitted changes.
job_package() {
    step $CARGO package --all-features --allow-dirty &&
        step $CARGO package --list --all-features --allow-dirty
}

job_python() {
    if ! $PYTHON -c 'import blake3, zstandard' >/dev/null 2>&1; then
        echo "$PYTHON does not have the required packages. Install them with:"
        echo "  $PYTHON -m pip install -r tools/sac1-requirements.txt"
        return 1
    fi
    step $PYTHON tools/generate_conformance.py --check &&
        step $PYTHON tools/test_sac1_recover.py &&
        step $PYTHON tools/test_sac1_recovery_records.py
}

if [ "${1:-}" = "--list" ]; then
    for job in $ALL_JOBS; do
        printf '%-11s %s\n' "$job" "$(describe "$job")"
    done
    exit 0
fi
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

jobs="${*:-$ALL_JOBS}"
for job in $jobs; do
    if ! describe "$job" >/dev/null; then
        echo "unknown job: $job (run tools/ci.sh --list)" >&2
        exit 2
    fi
done

mkdir -p "$LOGS"
failed=""
for job in $jobs; do
    log="$LOGS/$job.log"
    printf '==> %-11s %s\n' "$job" "$(describe "$job")"
    start=$(date +%s)
    if "job_$(echo "$job" | tr '-' '_')" >"$log" 2>&1; then
        echo "    ok ($(($(date +%s) - start)) s)"
    else
        echo "    FAILED ($(($(date +%s) - start)) s); last lines of $log:"
        tail -n 25 "$log" | sed 's/^/    | /'
        failed="$failed $job"
    fi
done

if [ -n "$failed" ]; then
    echo "FAILED:$failed"
    exit 1
fi
echo "All jobs passed: $jobs"

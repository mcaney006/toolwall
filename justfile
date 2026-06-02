# toolwall task runner.
#
# This is a Cargo workspace that emits multiple artifacts (8 library crates + the
# `toolwall` binary, and one test executable per crate under --all-targets), so
# cargo target selection must be explicit. Every recipe that operates on a single
# runnable artifact pins exactly one: `--package toolwall-cli --bin toolwall`.
# The whole-workspace gates (check/test/lint) intentionally cover every target.

# Canonical CLI package + binary. Change in one place if the layout moves.
pkg := "toolwall-cli"
bin := "toolwall"

# Show available recipes.
default:
    @just --list

# Run the CLI. Extra args pass through, e.g. `just run -- doctor`.
run *ARGS:
    cargo run --package {{pkg}} --bin {{bin}} -- {{ARGS}}

# Build the release CLI binary.
build:
    cargo build --package {{pkg}} --bin {{bin}} --release

# Type-check just the CLI binary (fast inner-loop check).
check:
    cargo check --package {{pkg}} --bin {{bin}}

# Type-check the entire workspace, all targets (lib, bins, tests).
check-all:
    cargo check --workspace --all-targets

# Run the whole test suite.
test:
    cargo test --workspace

# Lint everything; warnings are errors.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Install the `toolwall` binary from the CLI package.
install:
    cargo install --path crates/{{pkg}}

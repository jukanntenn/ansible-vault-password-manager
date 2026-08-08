//! trycmd snapshot suite.
//!
//! Declarative `.toml` cases under `tests/cmd/` exercise CLI output that does
//! not depend on a live keyring: help, version, config path, error exit codes.

#[test]
fn cli_tests() {
    trycmd::TestCases::new().case("tests/cmd/*.toml");
}

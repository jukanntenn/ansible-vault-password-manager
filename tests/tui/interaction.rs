//! TUI interaction tests over a pty — the inline-store contract.
//!
//! These drive the real `avpm tui` binary under a pty on an **isolated file
//! backend** ([`TuiSession::spawn_file`]): HOME is redirected so the OS keyring
//! is unreachable, and the master passphrase is supplied via the
//! `AVPM_MASTER_PASSPHRASE` env-var escape hatch (not an `rpassword` prompt,
//! which would conflict with `crossterm`'s termios setup over a pty). The TUI
//! then runs purely on an encrypted `store.age` in a temp dir — no keychain
//! dialogs, no real data touched — so the tests are deterministic and
//! cross-platform (identical on macOS and Linux).
//!
//! Together they prove the headline architecture change: every mutation (add,
//! delete) and view (show, search) happens **inline** inside the TUI's event
//! loop — a single process, no terminal teardown, no respawn. Assertions are on
//! the raw pty byte stream (`mark` / `bytes_since`); pure render logic is
//! covered by the `TestBackend` unit tests in `src/tui/app.rs`.

use super::harness::{Key, TuiSession};

/// Master passphrase for the file backend (its value is irrelevant; it just
/// decrypts the isolated `store.age`).
const MASTER_PW: &str = "tui-test-master";

/// T7 — add a vault-id via the in-TUI form, submit, and the list grows without
/// the TUI respawning; then delete it and the inline delete runs in the same
/// session. Core regression guard for the inline-store rebuild (previously each
/// operation tore the terminal down to a shell subprocess).
#[test]
fn inline_add_then_delete_in_single_session() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tui = TuiSession::spawn_file(dir.path(), MASTER_PW);

    // Sanity: the TUI started (title bar rendered — spawn_file already waited
    // for this, so it's present by now).
    assert!(tui.text().contains("Vault Secrets"), "TUI did not start");

    // Add a unique vault-id: [a] → fill the three fields → submit on the last.
    // The commit runs age (scrypt) encryption, which is deliberately slow, so
    // we poll for the success footer rather than asserting on a fixed settle.
    let id = "tui_inline_add_xyz";
    tui.key(Key::Char('a'));
    tui.type_str(id);
    tui.key(Key::Tab);
    tui.type_str("pw");
    tui.key(Key::Tab);
    tui.type_str("pw");
    tui.key(Key::Enter); // submit
    assert!(
        tui.wait_for("Added", std::time::Duration::from_secs(8)),
        "inline add should report success; text:\n{}",
        tui.text()
    );

    // The committed id now appears in the list.
    assert!(
        tui.text().contains(id),
        "list should contain the new id after inline add"
    );

    // Delete it: [d] → confirm with Enter. Runs inline (no respawn).
    tui.key(Key::Char('d'));
    tui.key(Key::Enter);
    assert!(
        tui.wait_for("Deleted", std::time::Duration::from_secs(8)),
        "inline delete should report success; text:\n{}",
        tui.text()
    );

    tui.quit();
}

/// T6 — after showing a vault's password, Space toggles reveal: the masked
/// dots are replaced by the plaintext password on screen. The toggle-on-press
/// behavior itself is unit-tested in `src/tui/app.rs`; this proves it surfaces
/// through the real crossterm flush path. We assert on the plaintext appearing
/// (not the footer hint word) because ratatui's diff renderer skips the one
/// cell that is unchanged between "reveal" and "hide", so the literal word
/// "hide" is never re-emitted as a contiguous run.
#[test]
fn toggle_reveal_flips_footer_hint() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tui = TuiSession::spawn_file(dir.path(), MASTER_PW);

    // Add one entry with a distinctive password, waiting for the (slow, scrypt)
    // commit. The id avoids "reveal"/"hide" so the show wait can't false-match.
    let id = "tui_toggle_id";
    let password = "topsecret99";
    tui.key(Key::Char('a'));
    tui.type_str(id);
    tui.key(Key::Tab);
    tui.type_str(password);
    tui.key(Key::Tab);
    tui.type_str(password);
    tui.key(Key::Enter); // submit
    assert!(
        tui.wait_for("Added", std::time::Duration::from_secs(8)),
        "add should complete before show"
    );

    // Show it (Enter on the selected row), then wait for the reveal hint. The
    // show path decrypts the store (scrypt), so poll rather than settle.
    tui.key(Key::Enter); // show password (reveal = false)
    assert!(
        tui.wait_for("reveal", std::time::Duration::from_secs(8)),
        "show popup should render the reveal hint"
    );
    // Masked: the plaintext must NOT be visible before the toggle.
    assert!(
        !tui.text().contains(password),
        "plaintext password leaked before reveal"
    );

    // Space toggles reveal on → the plaintext password replaces the mask dots.
    let mark = tui.mark();
    tui.key(Key::Space);
    tui.settle();
    let after_toggle = tui.text_since(mark);
    assert!(
        after_toggle.contains(password),
        "plaintext password should be visible after revealing:\n{after_toggle}"
    );

    tui.quit();
}

/// T11 — typing a search query filters the list: the matching entry stays and a
/// non-matching one is cleared from the render. The filter logic itself is
/// unit-tested (`App::filtered_items`); this proves it renders through the pty.
#[test]
fn search_filters_the_list() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tui = TuiSession::spawn_file(dir.path(), MASTER_PW);

    // Add two entries with distinct ids (no shared substring with the query),
    // waiting for each (slow, scrypt) commit before the next action. We wait
    // for the new id to appear as a *list row* (scoped to bytes since the
    // submit): a fresh row is always fully rendered, whereas the "Added"
    // footer message shares its "Added" prefix across commits and the diff
    // renderer skips those unchanged cells.
    for id in ["tui_keep_match", "tui_drop_other"] {
        tui.key(Key::Char('a'));
        tui.type_str(id);
        tui.key(Key::Tab);
        tui.type_str("p");
        tui.key(Key::Tab);
        tui.type_str("p");
        let mark = tui.mark();
        tui.key(Key::Enter); // submit
        assert!(
            tui.wait_for_since(mark, id, std::time::Duration::from_secs(10)),
            "add of {id} should complete (id should appear in the list) before continuing"
        );
    }

    // Search for "match": keeps tui_keep_match, drops tui_drop_other.
    let mark = tui.mark();
    tui.key(Key::Char('/'));
    tui.type_str("match");
    tui.settle();
    let after_search = tui.text_since(mark);
    assert!(
        after_search.contains("match"),
        "search box / matching entry should render 'match':\n{after_search}"
    );
    assert!(
        !after_search.contains("other"),
        "non-matching entry should be filtered out of the render:\n{after_search}"
    );

    tui.quit();
}

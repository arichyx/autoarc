//! Runtime configuration loaded from CLI args and the environment.

use std::sync::OnceLock;

/// Cached, parsed list of candidate passwords.
///
/// Populated by [`init_password_list`] from `main` on startup, or lazily by
/// [`get_password_list`] from the environment if init was never called
/// (e.g. during unit tests that poke extractors directly).
static PASSWORD_LIST: OnceLock<Vec<String>> = OnceLock::new();

/// Initialize the process-wide password list, preferring CLI input.
///
/// Resolution order (first non-empty wins):
/// 1. `cli_passwords` from the `-p / --password` flag.
/// 2. The `AUTOARC_PASSWORDS` environment variable (comma-separated).
/// 3. Empty list.
///
/// In all cases a single empty password is prepended so unencrypted archives
/// extract cleanly without any configuration, and so a unified list works
/// uniformly across encrypted and unencrypted archives in the same run.
///
/// Only the first call takes effect; subsequent calls are no-ops (documented
/// `OnceLock` semantics). Safe to call before spawning any work.
pub fn init_password_list(cli_passwords: Vec<String>) {
    PASSWORD_LIST.get_or_init(|| resolve(Some(cli_passwords)));
}

/// Returns the memoized password list.
///
/// If [`init_password_list`] was never called, this lazy-initializes from
/// `AUTOARC_PASSWORDS` only (the CLI path requires explicit init from `main`).
pub fn get_password_list() -> &'static Vec<String> {
    PASSWORD_LIST.get_or_init(|| resolve(None))
}

// ---------------------------------------------------------------------------
// Internal helpers (exposed to `tests` module only).
// ---------------------------------------------------------------------------

/// Core resolution logic shared by `init_*` and the lazy path.
///
/// `cli` is `Some` when a deliberate init from CLI input happened (even if
/// the vec is empty, meaning "user didn't pass -p, fall through to env").
/// `None` means no CLI context is available, so go straight to env.
fn resolve(cli: Option<Vec<String>>) -> Vec<String> {
    let source: Vec<String> = match cli {
        Some(list) if !list.is_empty() => sanitize(list),
        _ => parse_env(),
    };
    with_empty_prefix(source)
}

/// Parse `AUTOARC_PASSWORDS` into an exact list (apart from empty separators).
fn parse_env() -> Vec<String> {
    let raw = std::env::var("AUTOARC_PASSWORDS").unwrap_or_default();
    sanitize(raw.split(',').map(|s| s.to_string()).collect())
}

/// Preserve password bytes exactly while dropping empty separators.
///
/// Leading and trailing whitespace can be part of a real archive password and
/// must not be normalised.
fn sanitize(list: Vec<String>) -> Vec<String> {
    list.into_iter().filter(|s| !s.is_empty()).collect()
}

/// Ensure the empty password is present at position 0 so unencrypted archives
/// succeed on the first try regardless of how passwords were supplied.
fn with_empty_prefix(mut parsed: Vec<String>) -> Vec<String> {
    if !parsed.iter().any(|p| p.is_empty()) {
        parsed.insert(0, String::new());
    }
    parsed
}

#[cfg(test)]
mod tests {
    // NOTE: we can't unit-test `get_password_list()` / `init_password_list()`
    // directly because both use a process-wide `OnceLock` that's latched by
    // the first caller in the test binary. The helpers below *are* the
    // production resolution logic, so testing them is equivalent.
    use super::{resolve, sanitize, with_empty_prefix};

    // --- sanitize ------------------------------------------------------------

    #[test]
    fn sanitize_preserves_whitespace_and_drops_only_empty_values() {
        let got = sanitize(vec![
            "  alpha  ".into(),
            "".into(),
            " beta".into(),
            "   ".into(),
        ]);
        assert_eq!(
            got,
            vec![
                "  alpha  ".to_string(),
                " beta".to_string(),
                "   ".to_string()
            ]
        );
    }

    // --- with_empty_prefix ---------------------------------------------------

    #[test]
    fn with_empty_prefix_prepends_when_missing() {
        assert_eq!(
            with_empty_prefix(vec!["secret".into()]),
            vec![String::new(), "secret".to_string()]
        );
    }

    #[test]
    fn with_empty_prefix_idempotent_when_already_present() {
        let input = vec![String::new(), "secret".into()];
        assert_eq!(with_empty_prefix(input.clone()), input);
    }

    // --- resolve (no env side effects; only the None + Some(empty) branches) -

    #[test]
    fn resolve_with_cli_passwords_uses_them_and_prepends_empty() {
        let got = resolve(Some(vec!["secret".into(), "hunter2".into()]));
        assert_eq!(
            got,
            vec![String::new(), "secret".to_string(), "hunter2".to_string()]
        );
    }

    #[test]
    fn resolve_with_cli_passwords_preserves_whitespace_and_drops_empties() {
        let got = resolve(Some(vec!["  alpha  ".into(), "".into(), " beta".into()]));
        assert_eq!(
            got,
            vec![String::new(), "  alpha  ".to_string(), " beta".to_string()]
        );
    }

    #[test]
    fn resolve_with_cli_whitespace_passwords_keeps_them_exactly() {
        let got = resolve(Some(vec!["   ".into(), "\t".into()]));
        assert_eq!(
            got,
            vec![String::new(), "   ".to_string(), "\t".to_string()]
        );
    }

    #[test]
    fn resolve_with_empty_cli_vec_means_no_cli_flag() {
        // User didn't pass -p; `resolve` should go to env (whatever it
        // happens to be). We only assert that the empty password is
        // present \u2014 the env contents aren't our business here.
        let got = resolve(Some(vec![]));
        assert!(
            got.iter().any(|p| p.is_empty()),
            "empty password must always be tried first"
        );
    }

    #[test]
    fn resolve_with_none_means_lazy_env_path() {
        let got = resolve(None);
        assert!(
            got.iter().any(|p| p.is_empty()),
            "empty password must always be tried first"
        );
    }
}

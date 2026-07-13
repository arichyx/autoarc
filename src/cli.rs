//! Command-line argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Top-level CLI entry point.
///
/// The common case — "extract every archive in this directory" — is the
/// default action at the top level, so users type `autoarc <DIR>` (not
/// `autoarc autoarc <DIR>`). Introspection helpers live under real
/// subcommands (`autoarc type`, `autoarc lsar`).
#[derive(Debug, Parser)]
#[command(
    name = "autoarc",
    about = "Concurrent multi-format archive extractor with password trial-and-error",
    version,
    // `autoarc <DIR>` works without naming a subcommand; `autoarc type FILE`
    // dispatches to the subcommand. When a subcommand is present the top-level
    // flags/args are ignored.
    subcommand_negates_reqs = true,
)]
pub struct Args {
    /// Directory to scan for archives.
    ///
    /// Defaults to the current working directory (`.`) when omitted.
    /// Ignored when a subcommand (`type`, `lsar`, …) is used.
    #[arg(default_value = ".")]
    pub dir: PathBuf,

    /// Maximum directory depth to scan for archives.
    ///
    /// `1` (the default) only inspects the immediate contents of `dir`.
    /// `2` also enters direct subdirectories, and so on. A value of `0`
    /// is treated the same as `--recursive`.
    #[arg(short, long, default_value_t = 1)]
    pub depth: usize,

    /// Shortcut for unlimited recursion (overrides `--depth`).
    #[arg(short, long, default_value_t = false)]
    pub recursive: bool,

    /// Glob patterns of paths to skip during the initial directory scan.
    ///
    /// Repeatable; a path is ignored when it matches **any** pattern. Each
    /// `--ignore` occurrence is exactly one pattern — comma-separated lists
    /// are *not* split here (a glob may contain a comma inside `{a,b}`
    /// alternation, e.g. `--ignore '**/*.{tmp,bak}'`).
    ///
    /// Patterns are matched against the path relative to `<DIR>` and are
    /// fully anchored — the whole relative path must match. With shell-style
    /// globbing where `*` stays within a single path component:
    ///
    /// - `*` never crosses `/`
    /// - `**` crosses any number of directory separators
    /// - `{a,b}` alternation and `[abc]` character classes are supported
    ///
    /// ```text
    /// --ignore scratch              # skip top-level scratch/ and its subtree
    /// --ignore '**/node_modules'    # skip node_modules/ at any depth
    /// --ignore '*.tmp'              # skip *.tmp at the top level only
    /// --ignore '**/*.tmp'           # skip *.tmp at any depth
    /// ```
    ///
    /// Matching a directory prunes its entire subtree. Only the **initial**
    /// scan is affected — archives produced *by* extraction are still queued
    /// recursively, regardless of `--ignore` (same scoping rule as
    /// `--depth`).
    ///
    /// At the default `--depth 1` the scanner never enters subdirectories,
    /// so directory patterns like `scratch` have no effect there; raise
    /// `--depth` (or pass `--recursive`) for directory ignoring to apply.
    ///
    /// Multi-volume archive sets (`.zip` + `.z01` + …, or `.7z.001` + …) are
    /// grouped by scanning the filesystem for sibling parts *after* this
    /// filter runs, so ignoring only *some* parts of a set (e.g.
    /// `--ignore '*.z01'`) is unreliable — ignore the whole set instead
    /// (e.g. `--ignore 'name.*'`).
    #[arg(short = 'i', long, value_name = "GLOB")]
    pub ignore: Vec<String>,

    /// Print the extraction plan and exit without touching the filesystem.
    #[arg(short = 'n', long, default_value_t = false)]
    pub dry_run: bool,

    /// Skip the interactive confirmation prompt (assume "yes").
    ///
    /// Has no effect when stdin is not a TTY — in that case no prompt is
    /// shown and execution always proceeds.
    #[arg(short, long, default_value_t = false)]
    pub yes: bool,

    /// Maximum number of archives to extract in parallel.
    ///
    /// `0` (the default) means "auto" — use
    /// [`std::thread::available_parallelism`] (falling back to `4`). Use
    /// `-j 1` to force strictly sequential extraction. Parallelism is a
    /// per-invocation knob and is *not* configurable via an environment
    /// variable.
    #[arg(short = 'j', long, default_value_t = 0)]
    pub jobs: usize,

    /// Candidate password(s) to try against encrypted archives.
    ///
    /// Repeatable and comma-separated — all of the following build the
    /// list `[hunter2, correct horse, s3cret]`:
    ///
    /// ```text
    /// -p hunter2 -p "correct horse" -p s3cret
    /// -p hunter2,"correct horse",s3cret
    /// --password hunter2,"correct horse" -p s3cret
    /// ```
    ///
    /// When this flag is **not** given, autoarc falls back to the
    /// `AUTOARC_PASSWORDS` environment variable (same comma-separated
    /// format); when neither is set, only the empty password is tried.
    /// The empty password is always tried first regardless of source.
    ///
    /// Security note: passwords on the command line may be visible to
    /// other processes via `ps(1)` and to your shell history. Prefer
    /// `AUTOARC_PASSWORDS` (e.g. via `.env`) for long-lived secrets.
    #[arg(
        short = 'p',
        long = "password",
        value_name = "PASSWORD",
        value_delimiter = ','
    )]
    pub passwords: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Introspection subcommands. The main extraction flow lives at the top level.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print the detected archive/video file type for a single file.
    Type { filepath: PathBuf },

    /// Run `lsar` against a single archive and print its entry list.
    Lsar { filepath: PathBuf },
}

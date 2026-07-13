# autoarc

A concurrent, multi-format archive extractor for batch unpacking encrypted archives
with a list of candidate passwords.

`autoarc` walks a target directory, recursively unpacks every supported archive it
finds, automatically tries each password from `-p / --password` (or
`AUTOARC_PASSWORDS` as a fallback), and shows live progress for each task with a
final summary.

## Platform support

> ⚠️ **Only tested on macOS.** The author develops on macOS and does not own a
> Windows machine, so **Windows is not tested and not guaranteed to work.**
> Linux *should* work since all dependencies are cross-platform, but has not
> been exercised regularly. Bug reports / PRs from Linux and Windows users
> are very welcome.

## Prerequisites

| Tool | Required? | Purpose | Install |
|---|---|---|---|
| Rust toolchain (`cargo`, edition 2024, rustc ≥ 1.85) | yes | Build & install `autoarc` | <https://rustup.rs> |
| `unar` + `lsar` | yes for split archives (`.z01`, `.001`), SFX `.exe` archives, and the `autoarc lsar` subcommand | Subprocess fallback backend | macOS: `brew install unar`<br>Debian/Ubuntu: `sudo apt install unar`<br>Arch: `sudo pacman -S unarchiver` |
| `file` | optional | Fallback MIME sniffer for MPEG-TS detection and plain-text classification (`infer` doesn't cover those) | preinstalled on macOS / most Linux distros |

The ZIP, RAR, and 7z backends are pure-Rust crates — they have no external runtime
dependency, so if you only deal with single-volume archives in those formats you
can skip installing `unar` entirely.

## Installation

From crates.io (once published):

```bash
cargo install autoarc
```

From source:

```bash
git clone https://github.com/arichyx/autoarc.git
cd autoarc
cargo install --path .
```

> `cargo install` only pulls the Rust binary. You still need `unar` / `lsar`
> on your `PATH` for multi-volume and SFX archives — see **Prerequisites**
> above.

## Configuration

`autoarc` tries candidate passwords for encrypted archives in this order:

1. The `-p / --password` CLI flag (repeatable, comma-separated).
2. The `AUTOARC_PASSWORDS` environment variable (comma-separated) when the
   flag is **not** given.
3. The empty password only — which is also always tried first, regardless
   of source, so unencrypted archives extract cleanly without any setup.

For long-lived secrets, the most convenient source is a `.env` file at the
project root; see [`.env.example`](.env.example):

```bash
cp .env.example .env
# then edit .env and add your candidate passwords
```

For one-off runs, pass them on the command line:

```bash
autoarc <DIR> -p hunter2 -p "correct horse" -p s3cret
autoarc <DIR> -p 'hunter2,"correct horse",s3cret'
```

> **Security note:** passwords on the command line may be visible to other
> processes via `ps(1)` and end up in your shell history. Prefer
> `AUTOARC_PASSWORDS` via `.env` for long-lived secrets.

| Variable             | Required | Description                                                                                |
|----------------------|----------|--------------------------------------------------------------------------------------------|
| `AUTOARC_PASSWORDS`  | no       | Fallback password list when `-p / --password` is not given. Unset = try no-password only.  |
| `RUST_LOG`           | no       | Tracing filter (`info`, `debug`, ...). Defaults to `warn`.                                 |

Parallelism (`-j / --jobs`) is intentionally a CLI-only knob — it's a
per-invocation setting, not a persistent secret, so it does **not** read
from `.env` or any environment variable.

## Usage

### CLI

```bash
# Extract every supported archive in <DIR> (top level only)
autoarc <DIR>

# Recurse into subdirectories up to N levels
autoarc <DIR> --depth 3

# Recurse without limit
autoarc <DIR> --recursive
autoarc <DIR> -r

# Skip paths matching a glob during the initial scan (repeatable)
autoarc <DIR> --ignore scratch             # skip top-level scratch/ subtree
autoarc <DIR> -i '**/node_modules'         # skip node_modules/ at any depth
autoarc <DIR> -i '*.tmp' -i '*.bak'        # skip top-level temp/backup files

# Preview the plan without touching anything (dry-run)
autoarc <DIR> --dry-run
autoarc <DIR> -n

# Skip the interactive [Y/n] confirmation prompt
autoarc <DIR> --yes
autoarc <DIR> -y

# Cap parallelism (useful when extraction pins too many cores)
autoarc <DIR> --jobs 4
autoarc <DIR> -j 1        # strictly sequential

# Pass candidate passwords on the command line (repeatable + comma-separated)
autoarc <DIR> -p hunter2 -p "correct horse"
autoarc <DIR> -p 'hunter2,"correct horse",s3cret'

# Inspect a single file's detected type
autoarc type ./mystery.bin

# List the entries of an archive (uses `lsar`)
autoarc lsar ./bundle.zip
```

#### Recursion modes

| Flag                    | Meaning                                                     |
|-------------------------|-------------------------------------------------------------|
| (none)                  | `--depth 1` — only the immediate contents of `<DIR>`       |
| `--depth N` / `-d N`    | Walk up to `N` directory levels (`N ≥ 1`)                  |
| `--depth 0`             | Unlimited recursion (alias for `--recursive`)               |
| `--recursive` / `-r`    | Unlimited recursion                                         |

#### Ignoring paths

`--ignore` / `-i` takes a **glob pattern** and skips any matching path during
the initial scan. Repeatable; a path is ignored if it matches **any** pattern.
Patterns are matched against the path relative to `<DIR>` and are fully
anchored (the whole relative path must match), with shell-style globbing where
`*` stays within one path component:

- `*` matches within a single path segment (never crosses `/`)
- `**` crosses any number of directory separators
- `{a,b}` alternation and `[abc]` character classes are supported

| Pattern              | Effect                                                        |
|----------------------|---------------------------------------------------------------|
| `scratch`            | Skip the top-level `scratch/` folder and its entire subtree   |
| `**/node_modules`    | Skip any `node_modules/` directory, at any depth              |
| `*.tmp`              | Skip `*.tmp` files at the top level only                      |
| `**/*.tmp`           | Skip `*.tmp` files at any depth                               |
| `**/*.{tmp,bak}`     | Skip `*.tmp` or `*.bak` at any depth (one pattern)            |

Matching a directory prunes its whole subtree. Only the **initial** scan is
affected — archives produced *by* extraction are still queued recursively,
regardless of `--ignore` (same scoping rule as `--depth`). Patterns use `/` as
the separator; comma-separated lists are **not** split (each `--ignore` is
exactly one pattern, so `{a,b}` alternation works). At the default
`--depth 1` the scanner never enters subdirectories, so directory patterns
have no effect there — raise `--depth` (or pass `-r`) for directory ignoring
to apply.

#### Plan preview & confirmation

Before extracting, autoarc prints an extraction plan:

```
Plan: 5 archives (2 multi-volume), 12.4 GiB total — /tmp/in (depth=3)
  [zip  ] movie.zip                           (1.2 GiB)
  [multi] big.z01                             (8.1 GiB, 2 parts)
  [rar  ] sub/photos.rar                      (340.0 MiB)
  [7z   ] sub/data.7z                         (980.0 MiB)
  [multi] sub/seven.7z.001                    (2.4 GiB, 3 parts)

Note: 4 video file(s) will be renamed in place.

Continue? [Y/n]
```

- **Multi-volume archives** (`foo.z01` + `foo.zip` + `foo.z02`…, or
  `foo.7z.001` + `foo.7z.002`…) are fused into a single plan row with a
  `N parts` annotation, so each logical archive shows up exactly once.
- `--dry-run` (`-n`) prints the plan and exits without modifying anything.
- `--yes` (`-y`) skips the prompt; useful for automation.
- The prompt is **automatically skipped when stdin is not a TTY** (e.g. when
  the output is piped or run in CI), so existing scripts keep working.

When `depth == 1` (the default), only the immediate contents of `<DIR>` are
scanned. When `depth > 1` (or `--recursive`), autoarc descends into
subdirectories while pruning its own `_out/` output folders from the walk to
avoid re-processing previous runs. In either mode, archives are extracted
**in place** — each archive gets a sibling directory whose name is the full
filename with every `.` replaced by `_` plus the `_out` suffix (so `foo.zip`
→ `foo_zip_out/`, `foo.7z` → `foo_7z_out/`), and the original archive is
never moved.

### `just` recipes

A [`justfile`](justfile) provides shortcuts; extra args are forwarded to the
binary:

```bash
just run                                # uses default ./archives
just run /path/to/archives              # custom dir, depth=1
just run /path/to/archives -r           # custom dir, unlimited recursion
just run /path/to/archives -d 3         # custom dir, depth=3
just run /path/to/archives -n           # dry-run preview
just run /path/to/archives -y           # skip confirmation
just debug /path/to/archives -r         # same with RUST_LOG=debug
just type ./mystery.bin

# Development helpers
just fmt           # apply rustfmt to every source file
just fmt-check     # verify the tree is rustfmt-clean (CI-friendly)
just lint          # strict clippy: every warning is an error
just check         # one-shot: fmt-check + lint + release build
```

## Features

- Concurrent extraction powered by [`tokio`]
- Native handling of `zip`, `rar`, and `7z`
- Subprocess fallback to `unar` / `lsar` for split archives (`.z01`, `.001`)
  and SFX `.exe` payloads
- Recursive: nested archives produced by extraction are queued automatically
- Multi-password trial-and-error per archive (stops on first match)
- Live `indicatif` progress bars + a coloured run summary
- Archives are extracted **in place** next to the originals — each archive
  gets a sibling `_out/` directory named after the full filename with every
  `.` replaced by `_` (so `foo.zip` → `foo_zip_out/`, `foo.7z` →
  `foo_7z_out/`); sibling archives sharing a stem never collide. Originals
  are never moved.
- Detected videos (`.mp4`, `.ts`) inside archives get their extension corrected
  in-place; audio / PDF / Office / text files are counted and reported but
  never modified

## Supported formats

| Extension          | Backend            |
|--------------------|--------------------|
| `.zip`             | `zip` crate        |
| `.rar`             | `unrar` crate      |
| `.7z`              | `sevenz_rust2`     |
| `.z01`, `.001`     | `unar` subprocess  |
| `.exe` (SFX)       | `unar` subprocess  |

## Behaviour

Given `autoarc /tmp/in` (default `--depth 1`):

```
/tmp/in/
├── foo.zip              # original, untouched
├── foo_zip_out/...      # extracted contents, sibling of the archive
├── bar.rar
└── bar_rar_out/...
```

If `foo.zip` and `foo.7z` both live in the same directory, they get
`foo_zip_out/` and `foo_7z_out/` respectively — no collision.

With `--depth N > 1` or `--recursive`, subdirectories are walked too; the
layout inside each directory is the same:

```
/tmp/in/
├── sub/foo.zip
├── sub/foo_zip_out/...
└── sub/nested/bar.rar
    └── bar_rar_out/...
```

- Archives are always extracted **in place** — autoarc never moves or
  backs up your originals. If you want a safety copy, make it yourself
  before running.
- The depth limit only applies to the **initial** scan. Archives produced *by
  extraction itself* are always queued recursively, regardless of `--depth`.
- Multi-volume archives are handled as a single logical unit and extracted in
  place so their `.z02`, `.z03`, ... siblings remain reachable.
- Videos found during the scan are renamed in-place to enforce the canonical
  extension.
- During recursive scans, directories named `*_out` are skipped to avoid
  re-processing previous runs' artefacts, and any path matching a `--ignore`
  glob is pruned in the same pass (a matched directory takes its whole
  subtree with it).

## Logging

The default log level is `warn`; set `RUST_LOG=info` (or `debug`) to see more.
Log lines are routed above the live progress bars so the UI never tears.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.

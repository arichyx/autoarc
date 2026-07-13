//! Thin binary front-end. All real work lives in the [`autoarc`] library crate.

use anyhow::Result;
use autoarc::cli::{Args, Commands};
use autoarc::config;
use autoarc::extractors::unar::lsar;
use autoarc::fs::get_file_type;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    // Load `.env` if present; it's optional and any failure is fine.
    dotenvy::dotenv().ok();

    let args = Args::parse();

    match args.command {
        Some(Commands::Type { filepath }) => {
            let mime = infer::get_from_path(&filepath);
            println!("MIME: {mime:?}");
            println!("type: {:?}", get_file_type(&filepath));
        }
        Some(Commands::Lsar { filepath }) => {
            for entry in lsar(&filepath)? {
                println!("{}", entry.display());
            }
        }
        None => {
            // Default top-level action: extract every archive under `args.dir`
            // (which defaults to `.` — the current working directory).
            // `--recursive` and `--depth 0` both mean "no limit".
            let max_depth = if args.recursive || args.depth == 0 {
                usize::MAX
            } else {
                args.depth
            };
            // Initialize the password list once, preferring `-p / --password`
            // CLI input and falling back to `AUTOARC_PASSWORDS`. Must happen
            // before any extractor task reads it via `get_password_list()`.
            config::init_password_list(args.passwords);
            autoarc::runner::run(
                args.dir,
                max_depth,
                args.dry_run,
                args.yes,
                args.jobs,
                args.ignore,
            )
            .await?
        }
    }

    Ok(())
}

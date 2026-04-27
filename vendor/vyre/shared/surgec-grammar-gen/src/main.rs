//! CLI entry point for surgec-grammar-gen.
//!
//! Emits the C11 DFA lexer + LR(1) action/goto tables as binary blobs
//! suitable for uploading to the GPU as ReadOnly storage buffers.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use surgec_grammar_gen::{
    c11_lexer::build_c11_lexer_dfa, dfa::DfaBuilder, lr::smoke_grammar, DfaTable, PackedBlob,
};

/// Command-line interface.
#[derive(Parser)]
#[command(
    name = "surgec-grammar-gen",
    version,
    about = "Compile C11 grammar into GPU-ready lexer + LR tables."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit lexer + LR tables to disk.
    Emit {
        /// Output directory.
        #[arg(long, default_value = "./rules/c11")]
        out_dir: PathBuf,
        /// Use a 4-state stub lexer DFA (fast, for smoke tests only).
        #[arg(long, default_value_t = false)]
        smoke_lexer: bool,
        /// `bin` (default) or `json` sidecar metadata next to `.bin` files.
        #[arg(long, value_enum, default_value_t = EmitFormat::Bin)]
        format: EmitFormat,
    },
    /// Print a hex dump of the lexer DFA blob to stdout.
    DumpLexer {
        /// Same as emit: use stub lexer DFA instead of full C11 table.
        #[arg(long, default_value_t = false)]
        smoke_lexer: bool,
    },
    /// Print a hex dump of the LR tables blob to stdout.
    DumpLr,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum EmitFormat {
    /// Only `.bin` files.
    #[default]
    Bin,
    /// `.bin` plus `.json` sidecars (metadata, not a second wire format).
    Json,
}

fn lexer_dfa_table(smoke: bool) -> DfaTable {
    if smoke {
        DfaBuilder::new(4, 32).build()
    } else {
        build_c11_lexer_dfa()
    }
}

fn write_json_sidecar(path: &PathBuf, label: &str, blob: &PackedBlob) {
    let j = json!({
        "format": "surgec-grammar-gen-sidecar-v0",
        "label": label,
        "kind": format!("{:?}", blob.kind),
        "byte_length": blob.bytes.len(),
    });
    if let Ok(s) = serde_json::to_string_pretty(&j) {
        let _ = fs::write(path, s);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Emit {
            out_dir,
            smoke_lexer,
            format,
        } => {
            let dfa = lexer_dfa_table(smoke_lexer);
            let lr = smoke_grammar();

            fs::create_dir_all(&out_dir)?;

            let lexer_blob = PackedBlob::from_dfa(&dfa);
            let lr_blob = PackedBlob::from_lr(&lr);

            let lexer_path = out_dir.join("c11_lexer_dfa.bin");
            let lr_path = out_dir.join("c11_lr_tables.bin");
            fs::write(&lexer_path, &lexer_blob.bytes)?;
            fs::write(&lr_path, &lr_blob.bytes)?;

            if format == EmitFormat::Json {
                write_json_sidecar(
                    &out_dir.join("c11_lexer_dfa.json"),
                    "lexer_dfa",
                    &lexer_blob,
                );
                write_json_sidecar(&out_dir.join("c11_lr_tables.json"), "lr_tables", &lr_blob);
            }

            println!(
                "wrote {} bytes {} + {} bytes {} to {} (smoke_lexer={})",
                lexer_blob.bytes.len(),
                lexer_path.display(),
                lr_blob.bytes.len(),
                lr_path.display(),
                out_dir.display(),
                smoke_lexer
            );
        }
        Command::DumpLexer { smoke_lexer } => {
            let dfa = lexer_dfa_table(smoke_lexer);
            let blob = PackedBlob::from_dfa(&dfa);
            for (i, chunk) in blob.bytes.chunks(16).enumerate() {
                print!("{:08x}  ", i * 16);
                for b in chunk {
                    print!("{b:02x} ");
                }
                println!();
            }
        }
        Command::DumpLr => {
            let lr = smoke_grammar();
            let blob = PackedBlob::from_lr(&lr);
            for (i, chunk) in blob.bytes.chunks(16).enumerate() {
                print!("{:08x}  ", i * 16);
                for b in chunk {
                    print!("{b:02x} ");
                }
                println!();
            }
        }
    }

    Ok(())
}

//! fm-vangogh: recover and decrypt FileMaker Encryption At Rest (EAR) files you own.

use fm_vangogh::{crack, ear, gpu};

mod ui;

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use clap::{Parser, Subcommand};

/// The curated default wordlist is embedded, so `crack` works with no files alongside.
const DEFAULT_WORDLIST: &str = include_str!("../wordlists/common.txt");

#[derive(Parser)]
#[command(name = "fm-vangogh", version, about = "Recover and decrypt FileMaker EAR files you own")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect EAR and show salt, hint, and sector count
    Info { file: PathBuf },
    /// Show compute capabilities: CPU threads and visible GPU adapters
    Devices,
    /// Decrypt with a known password
    Decrypt {
        file: PathBuf,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Search for the password
    Crack {
        file: PathBuf,
        /// Wordlist file (default: the built-in common list)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,
        /// Apply rule mutations to each wordlist entry
        #[arg(long)]
        mods: bool,
        /// Brute force by length over --charset
        #[arg(long)]
        mask: bool,
        /// Mask charset: lower|upper|digits|alnum|all or literal characters
        #[arg(long, default_value = "alnum")]
        charset: String,
        #[arg(long, default_value_t = 1)]
        min: usize,
        #[arg(long, default_value_t = 4)]
        max: usize,
        /// Worker threads (default: all cores)
        #[arg(short, long)]
        jobs: Option<usize>,
        /// Use the GPU backend (wgpu: Metal on macOS, Vulkan on NVIDIA/Linux)
        #[arg(long)]
        gpu: bool,
        /// On success, write <file>_DECRYPTED.fmp12 and <file>_password.txt next to the input
        #[arg(long)]
        decrypt: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Devices => {
            let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
            println!("cpu threads : {threads}");
            let gpus = gpu::devices();
            if gpus.is_empty() {
                println!("gpu adapters: none found (CPU only)");
            } else {
                println!("gpu adapters:");
                for g in gpus {
                    println!("  {g}");
                }
            }
        }
        Cmd::Info { file } => {
            let data = std::fs::read(&file)?;
            if !ear::is_encrypted(&data) {
                println!("{}: not EAR-encrypted (magic is not HBAMe)", file.display());
                std::process::exit(1);
            }
            let hint = ear::read_hint(&data);
            println!("file     : {}", file.display());
            println!("encrypted: yes (HBAMe)");
            println!("sectors  : {}", data.len() / ear::SECTOR);
            println!("salt     : {}", hex(&ear::read_salt(&data)));
            println!("hint     : {}", if hint.is_empty() { "(none found)".into() } else { hint });
        }
        Cmd::Decrypt { file, password, out } => {
            match ear::decrypt_file(&file, &password, out.as_deref(), true) {
                Ok((written, key)) => {
                    println!("decrypted -> {}", written.display());
                    println!("key = {}", hex(&key));
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Crack { file, wordlist, mods, mask, charset, min, max, jobs, gpu, decrypt } => {
            let data = std::fs::read(&file)?;
            if !ear::is_encrypted(&data) {
                eprintln!("error: not an EAR file (magic is not HBAMe)");
                std::process::exit(2);
            }
            let salt = ear::read_salt(&data);
            let hint = ear::read_hint(&data);
            let hint = if hint.is_empty() { None } else { Some(hint) };

            let words: Vec<String> = if mask {
                Vec::new()
            } else {
                let text = match &wordlist {
                    Some(p) => std::fs::read_to_string(p)?,
                    None => DEFAULT_WORDLIST.to_string(),
                };
                text.lines().map(|l| l.trim_end().to_string()).filter(|l| !l.is_empty()).collect()
            };

            let opts = crack::Opts { mods, mask, charset: charset.clone(), min, max };
            let fancy = ui::fancy();
            let threads = jobs
                .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
            let (engine, driver) = if gpu {
                match gpu::header_engine() {
                    Some((e, d)) if !d.is_empty() => (e, Some(d)),
                    Some((e, _)) => (e, None),
                    None => ("GPU".to_string(), None),
                }
            } else {
                (format!("CPU ({threads} threads)"), None)
            };
            let total = estimate_total(&words, mods, mask, &charset, min, max);

            if fancy {
                ui::header(&file.display().to_string(), hint.as_deref(), &engine, driver.as_deref(), total);
            } else if let Some(h) = &hint {
                println!("hint: {h}");           // the file's own cleartext password hint
            }

            let counter = Arc::new(AtomicU64::new(0));
            let reporter = if fancy {
                Some(ui::Reporter::start(counter.clone(), total))
            } else {
                None
            };
            let found = if gpu {
                gpu::crack_gpu_with(&data, &salt, &words, hint.as_deref(), &opts, &counter)?
            } else {
                crack::crack_with(&data, &salt, &words, hint.as_deref(), &opts, jobs, &counter)
            };
            if let Some(r) = reporter {
                r.stop();
            }

            match found {
                Some(pw) => {
                    let mut rows = vec![("password".into(), pw.clone())];
                    if decrypt {
                        let (written, key) = ear::decrypt_file(&file, &pw, None, false)?;
                        let pw_path = write_password(&file, &pw)?;
                        rows.push(("key".into(), format!("{}\u{2026}", &hex(&key)[..16])));
                        rows.push(("decrypted".into(), written.display().to_string()));
                        rows.push(("saved pw".into(), pw_path.display().to_string()));
                        if fancy {
                            ui::success(&rows);
                        }
                        println!("password: {pw}");
                        println!("decrypted -> {}", written.display());
                        println!("password  -> {}", pw_path.display());
                    } else {
                        if fancy {
                            ui::success(&rows);
                        }
                        println!("password: {pw}");
                    }
                }
                None => {
                    if fancy {
                        ui::fail();
                    }
                    println!("not found");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

fn write_password(input: &std::path::Path, pw: &str) -> anyhow::Result<PathBuf> {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy().to_string();
    let dir = input.parent().unwrap_or_else(|| std::path::Path::new("."));
    let target = ear::new_path(&dir.join(format!("{stem}_password.txt")));
    std::fs::write(&target, format!("{pw}\n"))?;
    Ok(target)
}

/// Total candidate count when it can be known cheaply (for a progress ETA):
/// exact for a pure mask or a plain wordlist; unknown (None) once --mods is on.
fn estimate_total(words: &[String], mods: bool, mask: bool, charset: &str, min: usize, max: usize) -> Option<u64> {
    if mask && words.is_empty() {
        let cl = charset_len(charset) as u64;
        if cl == 0 {
            return None;
        }
        let mut sum = 0u64;
        for n in min..=max {
            sum = sum.saturating_add(cl.saturating_pow(n as u32));
        }
        Some(sum)
    } else if !mods {
        Some(words.len() as u64)
    } else {
        None
    }
}

fn charset_len(name: &str) -> usize {
    match name {
        "lower" | "upper" => 26,
        "digits" => 10,
        "alnum" => 36,
        "all" => 75,
        literal => literal.chars().count(),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

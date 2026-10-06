//! Candidate generation and the CPU search.

use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use itertools::Itertools;

use crate::ear;

#[derive(Clone)]
pub struct Opts {
    pub mods: bool,
    pub mask: bool,
    pub charset: String,
    pub min: usize,
    pub max: usize,
}

const SUFFIXES: &[&str] = &["", "!", "1", "2", "123", "!23", "2024", "2025"];

fn charset(name: &str) -> Vec<char> {
    let s = match name {
        "lower" => "abcdefghijklmnopqrstuvwxyz",
        "upper" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits" => "0123456789",
        "alnum" => "abcdefghijklmnopqrstuvwxyz0123456789",
        "all" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+",
        literal => literal,
    };
    s.chars().collect()
}

fn leet(word: &str) -> String {
    word.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '@', 'e' => '3', 'i' => '1', 'o' => '0', 's' => '$', 't' => '7', other => other,
        })
        .collect()
}

fn capitalize(word: &str) -> String {
    let mut c = word.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
        None => String::new(),
    }
}

/// Rule mutations of one base word (case, leet, appended digits/years/suffixes).
pub fn mods(word: &str) -> Vec<String> {
    let mut bases = vec![
        word.to_string(),
        word.to_lowercase(),
        word.to_uppercase(),
        capitalize(word),
        leet(word),
    ];
    bases.sort();
    bases.dedup();
    let mut out = Vec::new();
    for b in &bases {
        for suf in SUFFIXES {
            out.push(format!("{b}{suf}"));
        }
        for y in 1990..=2035 {
            out.push(format!("{b}{y}"));
        }
    }
    out
}

/// A few cheap candidates from the file's cleartext hint.
pub fn hint_candidates(hint: &str) -> Vec<String> {
    let mut out = vec![hint.to_string()];
    for tok in hint.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.is_empty() {
            continue;
        }
        for v in [tok.to_string(), tok.to_lowercase(), tok.to_uppercase(), capitalize(tok)] {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

/// The full candidate stream: hint seeds, then the wordlist (optionally mutated),
/// then the mask brute force. Lazy, so a huge mask does not allocate up front.
pub fn candidates<'a>(
    words: &'a [String],
    hint: Option<&'a str>,
    opts: &'a Opts,
) -> Box<dyn Iterator<Item = String> + Send + 'a> {
    let hint_iter = hint.map(hint_candidates).unwrap_or_default().into_iter();

    let use_mods = opts.mods;
    let word_iter = words.iter().flat_map(move |w| {
        if use_mods { mods(w).into_iter() } else { vec![w.clone()].into_iter() }
    });

    let (lo, hi) = if opts.mask { (opts.min, opts.max) } else { (1usize, 0usize) };
    let cs = charset(&opts.charset);
    let mask_iter = (lo..=hi).flat_map(move |n| {
        let cs = cs.clone();
        (0..n)
            .map(move |_| cs.clone().into_iter())
            .multi_cartesian_product()
            .map(|chars| chars.into_iter().collect::<String>())
    });

    Box::new(hint_iter.chain(word_iter).chain(mask_iter))
}

fn run_pool<F: FnOnce() -> Option<String> + Send>(jobs: Option<usize>, f: F) -> Option<String> {
    match jobs {
        Some(n) if n > 0 => match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
            Ok(pool) => pool.install(f),
            Err(_) => f(),
        },
        _ => f(),
    }
}

/// Search for the EAR password on the CPU. Returns the password or None.
pub fn crack(
    data: &[u8],
    salt: &[u8],
    words: &[String],
    hint: Option<&str>,
    opts: &Opts,
    jobs: Option<usize>,
) -> Option<String> {
    let counter = AtomicU64::new(0);
    crack_with(data, salt, words, hint, opts, jobs, &counter)
}

/// Like `crack`, but increments `counter` once per candidate checked so a caller
/// can display live progress.
pub fn crack_with(
    data: &[u8],
    salt: &[u8],
    words: &[String],
    hint: Option<&str>,
    opts: &Opts,
    jobs: Option<usize>,
    counter: &AtomicU64,
) -> Option<String> {
    run_pool(jobs, || {
        candidates(words, hint, opts)
            .par_bridge()
            .find_any(|pw| {
                counter.fetch_add(1, Ordering::Relaxed);
                ear::check_password(data, salt, pw)
            })
    })
}

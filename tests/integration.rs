//! End-to-end tests: every search modifier against EAR fixtures with known
//! passwords (made with FMDeveloperTool --enableEncryption), on both the CPU and
//! GPU engines. GPU tests skip gracefully when no adapter is present (e.g. CI).

use std::path::PathBuf;

use fm_vangogh::{crack, ear, gpu};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn fx(name: &str) -> Vec<u8> {
    std::fs::read(root().join("tests/fixtures").join(name)).expect("fixture present")
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn plain() -> crack::Opts {
    crack::Opts { mods: false, mask: false, charset: "alnum".into(), min: 1, max: 4 }
}
fn words(path: &str, take: usize) -> Vec<String> {
    std::fs::read_to_string(root().join(path)).unwrap().lines().take(take).map(String::from).collect()
}

const PW_KEY: &str = "2b52ac8cb5729838279fc4f2eaa11083893d4facfed0ee9d19a05612153faa95";

/// Every search case the suite exercises: (fixture, wordlist, options, expected).
/// Covers plain wordlist, mods (year + leet), mask, and long passwords (one over
/// the GPU's 32-char cap, forcing its CPU fallback; one just under it).
fn cases() -> Vec<(&'static str, Vec<String>, crack::Opts, &'static str)> {
    let w = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    vec![
        ("ear_plain.fmp12", w(&["letmein", "sunshine", "dragon"]), plain(), "sunshine"),
        ("ear_dragon.fmp12", w(&["dragon"]), crack::Opts { mods: true, ..plain() }, "Dragon2024"),
        ("ear_leet.fmp12", w(&["password"]), crack::Opts { mods: true, ..plain() }, "p@$$w0rd"),
        ("ear_mask.fmp12", vec![], crack::Opts { mask: true, charset: "ab12".into(), min: 4, max: 4, mods: false }, "ab12"),
        ("ear_long.fmp12", w(&["x", "the-quick-brown-fox-jumps-over-lazy-dog", "y"]), plain(), "the-quick-brown-fox-jumps-over-lazy-dog"),
        ("ear_longfit.fmp12", w(&["x", "correcthorsebatterystaple", "y"]), plain(), "correcthorsebatterystaple"),
    ]
}

// ---- protocol basics ----

#[test]
fn detect_salt_and_key() {
    let data = fx("ear_password.fmp12");
    assert!(ear::is_encrypted(&data));
    assert_eq!(hex(&ear::derive_key("password", &ear::read_salt(&data))), PW_KEY);
}

#[test]
fn hints_read_across_files() {
    assert_eq!(ear::read_hint(&fx("ear_dragon.fmp12")), "big lizard, which year?");
    assert_eq!(ear::read_hint(&fx("ear_long.fmp12")), "a pangram, dashed");
}

#[test]
fn check_password_true_false() {
    let data = fx("ear_password.fmp12");
    let salt = ear::read_salt(&data);
    assert!(ear::check_password(&data, &salt, "password"));
    assert!(!ear::check_password(&data, &salt, "nope"));
}

#[test]
fn decrypt_roundtrip_and_wrong_pw() {
    let dir = tempdir();
    let src = root().join("tests/fixtures/ear_password.fmp12");
    let (written, key) = ear::decrypt_file(&src, "password", Some(&dir.join("out.fmp12")), true).unwrap();
    assert_eq!(hex(&key), PW_KEY);
    assert_eq!(&std::fs::read(&written).unwrap()[0x0f..0x14], b"HBAM7");
    assert!(ear::decrypt_file(&src, "wrong", Some(&dir.join("bad.fmp12")), true).is_err());
    assert!(!dir.join("bad.fmp12").exists());
}

// ---- CPU: one test per search type ----

#[test]
fn cpu_cracks_every_type() {
    for (file, wl, opts, expected) in cases() {
        let data = fx(file);
        let salt = ear::read_salt(&data);
        let got = crack::crack(&data, &salt, &wl, None, &opts, None);
        assert_eq!(got.as_deref(), Some(expected), "CPU failed on {file}");
    }
}

#[test]
fn cpu_not_found() {
    let data = fx("ear_password.fmp12");
    let salt = ear::read_salt(&data);
    assert_eq!(crack::crack(&data, &salt, &["alpha".into(), "beta".into()], None, &plain(), Some(1)), None);
}

#[test]
fn cpu_file_wordlist() {
    let data = fx("ear_password.fmp12");
    let salt = ear::read_salt(&data);
    let wl = words("wordlists/common.txt", usize::MAX);
    assert_eq!(crack::crack(&data, &salt, &wl, None, &plain(), None).as_deref(), Some("password"));
}

// ---- GPU: the same types, sequentially (one context at a time) ----

#[test]
fn gpu_cracks_every_type() {
    // Probe once; if there is no adapter (CI), skip the whole test.
    let probe = fx("ear_password.fmp12");
    let psalt = ear::read_salt(&probe);
    if gpu::derive_keys_gpu(&psalt, &["password".into()]).is_err() {
        eprintln!("skipping GPU suite (no adapter)");
        return;
    }
    for (file, wl, opts, expected) in cases() {
        let data = fx(file);
        let salt = ear::read_salt(&data);
        let got = gpu::crack_gpu(&data, &salt, &wl, None, &opts).expect("gpu crack");
        assert_eq!(got.as_deref(), Some(expected), "GPU failed on {file}");
    }
    eprintln!("GPU cracked every type (incl. long-password CPU fallback)");
}

#[test]
fn gpu_keys_match_cpu() {
    let probe = fx("ear_password.fmp12");
    let psalt = ear::read_salt(&probe);
    if gpu::derive_keys_gpu(&psalt, &["password".into()]).is_err() {
        eprintln!("skipping GPU key check (no adapter)");
        return;
    }
    for (file, pw) in [("ear_password.fmp12", "password"), ("ear_longfit.fmp12", "correcthorsebatterystaple")] {
        let data = fx(file);
        let salt = ear::read_salt(&data);
        let keys = gpu::derive_keys_gpu(&salt, &[pw.to_string()]).unwrap();
        assert_eq!(keys[0], ear::derive_key(pw, &salt), "GPU key mismatch for {pw}");
    }
}

// ---- generators ----

#[test]
fn generators() {
    let m = crack::mods("summer");
    assert!(m.contains(&"Summer2024".to_string()) && m.contains(&"summer!".to_string()));
    let n = crack::candidates(&[], None, &crack::Opts { mods: false, mask: true, charset: "digits".into(), min: 1, max: 2 }).count();
    assert_eq!(n, 110);
}

fn tempdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("fmv_test_{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

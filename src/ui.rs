//! Terminal UI for the crack command: lipgloss-style bordered boxes and one
//! live-updating status line. All decoration goes to stderr; stdout stays clean
//! and machine-readable. No full-screen TUI: output scrolls normally.

use std::io::{stderr, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use owo_colors::OwoColorize;

const SPIN: [&str; 10] = [
    "\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283c}", "\u{2834}", "\u{2826}", "\u{2827}",
    "\u{2807}", "\u{280f}",
];

#[derive(Clone, Copy)]
pub enum Accent {
    Cyan,
    Green,
    Dim,
}

/// True when stderr is a terminal, so decoration is worth drawing.
pub fn fancy() -> bool {
    stderr().is_terminal()
}

fn vlen(s: &str) -> usize {
    // Display columns, so wide chars (e.g. the lock emoji) are counted as 2 and
    // the box borders line up.
    unicode_width::UnicodeWidthStr::width(s)
}

#[cfg(test)]
mod tests {
    use super::vlen;
    #[test]
    fn emoji_counts_as_two_columns() {
        assert_eq!(vlen("\u{1f510} fm-vangogh"), 13);
        assert_eq!(vlen("plain"), 5);
    }
}

fn pad(s: &str, w: usize) -> String {
    let n = vlen(s);
    if n >= w {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(w - n))
    }
}

fn colored(s: &str, a: Accent) -> String {
    match a {
        Accent::Cyan => s.cyan().to_string(),
        Accent::Green => s.green().to_string(),
        Accent::Dim => s.dimmed().to_string(),
    }
}

/// Draw a bordered box to stderr. `accent` colours the border and title.
fn draw(title: &str, rows: &[(String, String)], accent: Accent) {
    let label_w = rows.iter().map(|(l, _)| vlen(l)).max().unwrap_or(0);
    // (plain_content, colored_content) with equal visible length.
    let body: Vec<(String, String)> = rows
        .iter()
        .map(|(l, v)| {
            let plain = format!("{}  {}", pad(l, label_w), v);
            let col = format!("{}  {}", pad(l, label_w).dimmed(), v);
            (plain, col)
        })
        .collect();
    let inner = vlen(title).max(body.iter().map(|(p, _)| vlen(p)).max().unwrap_or(0));

    let b = |s: &str| colored(s, accent);
    let hbar = "\u{2500}".repeat(inner + 2);
    let mut e = stderr();
    let _ = writeln!(e, "{}{}{}", b("\u{250c}"), b(&hbar), b("\u{2510}"));
    let _ = writeln!(e, "{} {}{} {}", b("\u{2502}"), title.bold(), " ".repeat(inner - vlen(title)), b("\u{2502}"));
    let _ = writeln!(e, "{}{}{}", b("\u{251c}"), b(&hbar), b("\u{2524}"));
    for (plain, col) in &body {
        let _ = writeln!(e, "{} {}{} {}", b("\u{2502}"), col, " ".repeat(inner - vlen(plain)), b("\u{2502}"));
    }
    let _ = writeln!(e, "{}{}{}", b("\u{2514}"), b(&hbar), b("\u{2518}"));
}

pub fn header(file: &str, hint: Option<&str>, engine: &str, driver: Option<&str>, total: Option<u64>) {
    let mut rows = vec![
        ("file".into(), file.to_string()),
        ("engine".into(), engine.to_string()),
    ];
    if let Some(d) = driver {
        rows.push(("driver".into(), d.to_string()));
    }
    rows.push(("hint".into(), hint.unwrap_or("(none)").to_string()));
    if let Some(t) = total {
        rows.push(("candidates".into(), group(t)));
    }
    draw("\u{1f510} fm-vangogh", &rows, Accent::Cyan);
}

pub fn success(rows: &[(String, String)]) {
    draw("\u{2714} found", rows, Accent::Green);
}

pub fn fail() {
    draw(
        "\u{2717} not found",
        &[("result".into(), "no password in the search space".into())],
        Accent::Dim,
    );
}

/// Group a number with thousands separators.
pub fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn human_secs(s: f64) -> String {
    // Break a duration into years/days/hours/mins/secs, dropping leading zero
    // units (a mask space can be years out, so seconds alone is not enough).
    let mut t = s.max(0.0) as u64;
    let y = t / 31_536_000; t %= 31_536_000;      // 365-day years
    let d = t / 86_400; t %= 86_400;
    let h = t / 3_600; t %= 3_600;
    let m = t / 60;
    let sec = t % 60;
    let mut parts = Vec::new();
    let mut started = false;
    for (v, label) in [(y, "y"), (d, "d"), (h, "h"), (m, "m"), (sec, "s")] {
        if v > 0 || started {
            parts.push(format!("{v}{label}"));
            started = true;
        }
    }
    if parts.is_empty() { "0s".into() } else { parts.join(" ") }
}

#[cfg(test)]
mod dur_tests {
    use super::human_secs;
    #[test]
    fn breakdown() {
        assert_eq!(human_secs(45.0), "45s");
        assert_eq!(human_secs(125.0), "2m 5s");
        assert_eq!(human_secs(3661.0), "1h 1m 1s");
        assert_eq!(human_secs(90_000.0), "1d 1h 0m 0s");
        assert_eq!(human_secs(31_536_000.0 + 86_400.0), "1y 1d 0h 0m 0s");
    }
}

/// A background thread that rewrites one status line on stderr until stopped.
pub struct Reporter {
    done: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Reporter {
    pub fn start(counter: Arc<AtomicU64>, total: Option<u64>) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut frame = 0usize;
            let mut e = stderr();
            while !d.load(Ordering::Relaxed) {
                let n = counter.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64().max(0.001);
                let rate = n as f64 / secs;
                let tail = match total {
                    Some(t) if rate > 0.0 && t >= n => {
                        let eta = (t - n) as f64 / rate;
                        format!("{:>5.1}%  eta {}", 100.0 * n as f64 / t as f64, human_secs(eta))
                    }
                    _ => human_secs(secs),
                };
                let line = format!(
                    "{} {}  {}/s  {}",
                    SPIN[frame % SPIN.len()].cyan(),
                    group(n).bold(),
                    group(rate as u64),
                    tail.dimmed()
                );
                let _ = write!(e, "\r\u{1b}[2K{line}");
                let _ = e.flush();
                frame += 1;
                thread::sleep(Duration::from_millis(90));
            }
            let _ = write!(e, "\r\u{1b}[2K");
            let _ = e.flush();
        });
        Reporter { done, handle: Some(handle) }
    }

    pub fn stop(mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

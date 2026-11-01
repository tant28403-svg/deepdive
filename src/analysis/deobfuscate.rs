use base64::Engine;
use regex::Regex;
use std::sync::OnceLock;

/// Attempt to extract and decode embedded payloads from content.
/// Returns decoded strings (UTF-8) that should be re-scanned.
pub fn deobfuscate(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    // 1. Base64 strings (long runs).
    let b64re = Regex::new(r"[A-Za-z0-9+/]{24,}={0,2}").unwrap();
    for m in b64re.find_iter(content) {
        let s = m.as_str();
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
            if let Ok(text) = String::from_utf8(bytes) {
                if is_interesting(&text) {
                    out.push(text);
                }
            }
        }
    }
    // 2. Hex escape sequences \x41\x42...
    let hexre = Regex::new(r"(\\x[0-9a-fA-F]{2}){6,}").unwrap();
    for m in hexre.find_iter(content) {
        let s = m.as_str();
        let mut bytes = Vec::new();
        let mut i = 0;
        let chars: Vec<char> = s.chars().collect();
        while i + 3 < chars.len() || i + 3 == chars.len() - 1 {
            if i + 3 < chars.len() && chars[i] == '\\' && chars[i + 1] == 'x' {
                let hex = &s[i + 2..i + 4];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    bytes.push(b);
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
        // Recompute properly.
        bytes.clear();
        let mut i = 0;
        while i < s.len() {
            if i + 3 < s.len() && s.as_bytes()[i] == b'\\' && s.as_bytes()[i + 1] == b'x' {
                if let Ok(b) = u8::from_str_radix(&s[i + 2..i + 4], 16) {
                    bytes.push(b);
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
        if !bytes.is_empty() {
            if let Ok(text) = String::from_utf8(bytes) {
                if is_interesting(&text) {
                    out.push(text);
                }
            }
        }
    }
    // 3. Char code arrays: fromCharCode(65, 66, ...)
    let charcode_re = Regex::new(r"fromCharCode\s*\(([^)]+)\)").unwrap();
    for cap in charcode_re.captures_iter(content) {
        let nums = &cap[1];
        let mut bytes = Vec::new();
        for part in nums.split(',') {
            let p = part.trim();
            if let Ok(n) = p.parse::<u32>() {
                if n < 256 {
                    bytes.push(n as u8);
                } else {
                    // unicode codepoint -> encode
                    if let Some(c) = char::from_u32(n) {
                        let mut buf = [0u8; 4];
                        let s = c.encode_utf8(&mut buf);
                        // store as text via a separate; for simplicity push char
                        bytes.extend_from_slice(s.as_bytes());
                    }
                }
            }
        }
        if !bytes.is_empty() {
            if let Ok(text) = String::from_utf8(bytes) {
                if is_interesting(&text) {
                    out.push(text);
                }
            }
        }
    }
    // Dedup.
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

fn is_interesting(text: &str) -> bool {
    if text.len() < 8 {
        return false;
    }
    // Must contain some printable chars and look like code/text.
    let printable = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    if (printable as f64 / text.len() as f64) < 0.7 {
        return false;
    }
    // Avoid re-pushing identical base content.
    true
}

/// Recursively deobfuscate up to `depth` layers.
pub fn deobfuscate_deep(content: &str, depth: usize) -> Vec<String> {
    let mut all = Vec::new();
    let mut current = vec![content.to_string()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for c in &current {
            for d in deobfuscate(c) {
                all.push(d.clone());
                next.push(d);
            }
        }
        if next.is_empty() {
            break;
        }
        current = next;
    }
    all
}

#[allow(dead_code)]
static _RE: OnceLock<Regex> = OnceLock::new();

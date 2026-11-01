use crate::types::{Finding, Severity, Verdict};

pub fn score(findings: &[Finding]) -> u8 {
    let mut total: u32 = 0;
    for f in findings {
        let base = match f.severity {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Info => 1,
        };
        total += (base as f32 * f.confidence) as u32;
    }
    total.min(100) as u8
}

pub fn verdict(score: u8, findings: &[Finding]) -> Verdict {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return Verdict::Unsafe;
    }
    match score {
        0..=10 => Verdict::Safe,
        11..=40 => Verdict::Review,
        41..=70 => Verdict::Unsafe,
        _ => Verdict::Block,
    }
}

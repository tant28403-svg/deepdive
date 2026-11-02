//! Disassembly and control-flow heuristics for PE and ELF images.
//!
//! This is intentionally coarse: it decodes executable sections and flags
//! patterns that are expensive to hide (indirect control flow, anti-analysis
//! instructions) rather than trying to reconstruct full functions.

use crate::types::{Finding, Location, Severity};
use std::path::Path;

const MAX_INSTRUCTIONS: usize = 500_000;

/// Decode PE/ELF executable sections and emit heuristic findings.
pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let Some((bitness, sections)) = executable_sections(bytes) else {
        return Vec::new();
    };
    if sections.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for (name, range) in sections {
        let code = &bytes[range];
        if code.is_empty() {
            continue;
        }
        findings.extend(analyze(path, code, bitness, &name));
    }
    findings
}

pub fn analyze(path: &Path, code: &[u8], bitness: u32, section: &str) -> Vec<Finding> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut total: u64 = 0;
    let mut indirect: u64 = 0;
    let mut anti_analysis: u64 = 0;

    while decoder.can_decode() && (total as usize) < MAX_INSTRUCTIONS {
        let insn = decoder.decode();
        total += 1;
        match insn.mnemonic() {
            Mnemonic::Call | Mnemonic::Jmp => {
                if matches!(insn.op0_kind(), OpKind::Register | OpKind::Memory) {
                    indirect += 1;
                }
            }
            Mnemonic::Rdtsc
            | Mnemonic::Cpuid
            | Mnemonic::Int3
            | Mnemonic::Int
            | Mnemonic::In
            | Mnemonic::Out
            | Mnemonic::Hlt
            | Mnemonic::Rdmsr
            | Mnemonic::Wrmsr
            | Mnemonic::Ud2 => anti_analysis += 1,
            _ => {}
        }
    }

    let mut findings = Vec::new();
    if anti_analysis > 0 {
        findings.push(finding(
            path,
            "disasm.anti-analysis",
            Severity::Medium,
            0.6,
            format!(
                "Section {} contains {} anti-analysis instruction(s) (rdtsc/cpuid/int/hlt/msr)",
                section, anti_analysis
            ),
        ));
    }
    if indirect >= 20 && (indirect as f64) / (total.max(1) as f64) > 0.15 {
        findings.push(finding(
            path,
            "disasm.indirect-control-flow",
            Severity::Medium,
            0.55,
            format!(
                "Section {} has {} indirect call/jump(s) out of {} instructions; consistent with dynamic API resolution or obfuscation",
                section, indirect, total
            ),
        ));
    }
    findings
}

fn finding(
    path: &Path,
    rule: &str,
    severity: Severity,
    confidence: f32,
    message: String,
) -> Finding {
    Finding {
        id: format!("{}-{}", rule, path.display()),
        severity,
        confidence,
        rule: rule.to_string(),
        category: "disasm".to_string(),
        location: Location {
            path: path.to_string_lossy().to_string(),
            line: None,
            column: None,
        },
        message,
        snippet: None,
        tags: vec!["disasm".to_string()],
    }
}

/// Return the bitness and `(section name, byte range)` of executable content.
type Sections = Vec<(String, std::ops::Range<usize>)>;

fn executable_sections(bytes: &[u8]) -> Option<(u32, Sections)> {
    match goblin::Object::parse(bytes).ok()? {
        goblin::Object::PE(pe) => {
            let bitness = match pe.header.coff_header.machine {
                0x8664 => 64,
                0x14c => 32,
                _ => return None,
            };
            let mut sections = Vec::new();
            for section in &pe.sections {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                if size == 0 || start.saturating_add(size) > bytes.len() {
                    continue;
                }
                sections.push((section_name(&section.name), start..start + size));
            }
            Some((bitness, sections))
        }
        goblin::Object::Elf(elf) => {
            let bitness = if elf.is_64 { 64 } else { 32 };
            const SHF_EXECINSTR: u64 = 0x4;
            let mut sections = Vec::new();
            for header in &elf.section_headers {
                if header.sh_flags & SHF_EXECINSTR == 0 || header.sh_size == 0 {
                    continue;
                }
                let start = header.sh_offset as usize;
                let size = header.sh_size as usize;
                if start.saturating_add(size) > bytes.len() {
                    continue;
                }
                let name = elf
                    .shdr_strtab
                    .get_at(header.sh_name)
                    .unwrap_or("")
                    .to_string();
                sections.push((name, start..start + size));
            }
            Some((bitness, sections))
        }
        _ => None,
    }
}

fn section_name(raw: &[u8; 8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn flags_indirect_calls() {
        // 24x `call rax` (0x48 0xFF 0xD0) plus a nop.
        let mut code = Vec::new();
        for _ in 0..24 {
            code.extend_from_slice(&[0x48, 0xFF, 0xD0]);
        }
        code.push(0x90);
        let findings = analyze(&PathBuf::from("a.exe"), &code, 64, ".text");
        assert!(findings
            .iter()
            .any(|f| f.rule == "disasm.indirect-control-flow"));
    }

    #[test]
    fn flags_anti_analysis_instructions() {
        let code = [0x0F, 0x31, 0x0F, 0xA2]; // rdtsc, cpuid
        let findings = analyze(&PathBuf::from("a.exe"), &code, 64, ".text");
        let anti = findings
            .iter()
            .find(|f| f.rule == "disasm.anti-analysis")
            .expect("anti-analysis finding");
        assert_eq!(anti.severity, Severity::Medium);
    }

    #[test]
    fn benign_code_is_quiet() {
        let code = [0x48, 0x89, 0xE5, 0x90, 0xC3]; // mov rbp,rsp; nop; ret
        assert!(analyze(&PathBuf::from("a.exe"), &code, 64, ".text").is_empty());
    }
}

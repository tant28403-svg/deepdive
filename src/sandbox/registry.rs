//! Read-only snapshots of common Windows persistence keys. Values created or
//! changed during a sandbox run are reported as `RegistryChange`s.

#[cfg(windows)]
use crate::sandbox::telemetry::{RegistryChange, RegistryChangeKind};
#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
};

#[cfg(windows)]
const PERSISTENCE_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

/// Map of `"<key>\\<value>"` to its data.
#[cfg(windows)]
pub fn capture_persistence() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for key in PERSISTENCE_KEYS {
        for (name, data) in enum_values(key) {
            out.insert(format!("{}\\{}", key, name), data);
        }
    }
    out
}

#[cfg(windows)]
pub fn diff(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<RegistryChange> {
    let mut out = Vec::new();
    for (key, data) in after {
        match before.get(key) {
            None => out.push(change(key, Some(data.clone()), RegistryChangeKind::Created)),
            Some(previous) if previous != data => out.push(change(
                key,
                Some(data.clone()),
                RegistryChangeKind::Modified,
            )),
            _ => {}
        }
    }
    for key in before.keys() {
        if !after.contains_key(key) {
            out.push(change(key, None, RegistryChangeKind::Deleted));
        }
    }
    out
}

#[cfg(windows)]
fn change(key: &str, value: Option<String>, kind: RegistryChangeKind) -> RegistryChange {
    RegistryChange {
        key: key.to_string(),
        value,
        kind,
        timestamp_ms: 0,
    }
}

#[cfg(windows)]
fn enum_values(subkey: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();

    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if status.is_err() {
        return out;
    }

    let mut index = 0u32;
    loop {
        let mut name_buf = vec![0u16; 512];
        let mut name_len = name_buf.len() as u32;
        let mut data_buf = vec![0u8; 4096];
        let mut data_len = data_buf.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                None,
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if status.is_err() {
            break;
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let data = decode(&data_buf[..data_len as usize]);
        out.push((name, data));
        index += 1;
    }

    let _ = unsafe { RegCloseKey(hkey) };
    out
}

/// Registry data is usually a NUL-terminated UTF-16 string; fall back to hex.
#[cfg(windows)]
pub fn decode(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.len().is_multiple_of(2) {
        let (pairs, _) = bytes.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
        let printable = units[..end]
            .iter()
            .all(|u| matches!(char::from_u32(*u as u32), Some(c) if !c.is_control()));
        if end > 0 && printable {
            return String::from_utf16_lossy(&units[..end]);
        }
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf16_and_hex() {
        let text: Vec<u8> = "hello\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode(&text), "hello");
        assert_eq!(decode(&[0x01, 0x00, 0x02, 0x00]), "01000200");
    }

    #[test]
    fn diff_reports_created_modified_deleted() {
        let mut before = BTreeMap::new();
        before.insert("k\\a".to_string(), "1".to_string());
        before.insert("k\\b".to_string(), "1".to_string());
        let mut after = BTreeMap::new();
        after.insert("k\\a".to_string(), "2".to_string());
        after.insert("k\\c".to_string(), "3".to_string());

        let changes = diff(&before, &after);
        assert_eq!(changes.len(), 3);
        assert!(changes
            .iter()
            .any(|c| c.kind == RegistryChangeKind::Modified));
        assert!(changes
            .iter()
            .any(|c| c.kind == RegistryChangeKind::Created));
        assert!(changes
            .iter()
            .any(|c| c.kind == RegistryChangeKind::Deleted));
    }
}

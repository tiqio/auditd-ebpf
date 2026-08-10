use sha2::{Digest, Sha256};

#[must_use]
pub fn policy_digest(lines: impl IntoIterator<Item = String>) -> String {
    let mut lines: Vec<_> = lines.into_iter().collect();
    lines.sort();
    let mut digest = Sha256::new();
    for line in lines {
        digest.update(line.as_bytes());
        digest.update(b"\n");
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

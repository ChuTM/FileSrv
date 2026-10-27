use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn random_secret() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    STANDARD.encode(buf)
}

pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// AES-256-GCM seal with the server secret (key = SHA-256(server_secret)).
pub fn seal(server_secret: &[u8], plaintext: &[u8]) -> String {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let key = Sha256::digest(server_secret);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("seal");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    STANDARD.encode(out)
}

pub fn open(server_secret: &[u8], sealed: &str) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let raw = STANDARD.decode(sealed).ok()?;
    if raw.len() < 12 {
        return None;
    }
    let (nonce, ct) = raw.split_at(12);
    let key = Sha256::digest(server_secret);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .ok()
}

/// Canonical string signed by an App with its secret.
pub fn app_canonical(method: &str, path: &str, query: &str, body_hash: &str, ts: &str, nonce: &str) -> String {
    format!("{method}\n{path}\n{query}\n{body_hash}\n{ts}\n{nonce}")
}

pub fn app_signature(secret: &[u8], canonical: &str) -> String {
    hex::encode(hmac_sha256(secret, canonical.as_bytes()))
}

// ---------------- JWT (HS256) ----------------

fn b64url(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(input).ok()
}

pub fn jwt_encode(secret: &[u8], iss: &str, sub: &str, exp: i64) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = format!(r#"{{"iss":"{iss}","sub":"{sub}","exp":{exp}}}"#);
    let payload = b64url(payload.as_bytes());
    let signing = format!("{header}.{payload}");
    let sig = b64url(&hmac_sha256(secret, signing.as_bytes()));
    format!("{signing}.{sig}")
}

pub struct JwtClaims {
    pub iss: String,
    pub sub: String,
    pub exp: i64,
}

/// Parse a JWT without verifying (returns raw parts for signature check later).
fn jwt_parts(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let sig = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let _hdr_json: serde_json::Value = serde_json::from_slice(&b64url_decode(header)?).ok()?;
    let _pay_json: serde_json::Value = serde_json::from_slice(&b64url_decode(payload)?).ok()?;
    Some((header, payload, sig))
}

pub fn jwt_decode_public(token: &str) -> Option<JwtClaims> {
    let (_, payload, _) = jwt_parts(token)?;
    let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(payload)?).ok()?;
    Some(JwtClaims {
        iss: claims.get("iss")?.as_str()?.to_string(),
        sub: claims.get("sub")?.as_str()?.to_string(),
        exp: claims.get("exp")?.as_i64()?,
    })
}

pub fn jwt_verify_signature(secret: &[u8], token: &str) -> bool {
    let (header, payload, sig) = match jwt_parts(token) {
        Some(p) => p,
        None => return false,
    };
    let signing = format!("{header}.{payload}");
    let expect = b64url(&hmac_sha256(secret, signing.as_bytes()));
    constant_time_eq(expect.as_bytes(), sig.as_bytes())
}

pub fn jwt_decode(secret: &[u8], token: &str) -> Option<JwtClaims> {
    if !jwt_verify_signature(secret, token) {
        return None;
    }
    jwt_decode_public(token)
}

// ---------------- Blob envelope encryption (at-rest) ----------------
//
// Layout of an encrypted blob file (self-contained header):
//   [0..4]   magic b"TSFS"
//   [4]      format version (1)
//   [5..17]  dek_nonce  (12 bytes) — nonce for the KEK-sealed DEK
//   [17..65] sealed_dek (48 bytes) = AES-256-GCM(KEK, dek_nonce, DEK[32])
//   [65..77] body_nonce (12 bytes) — nonce for the payload
//   [77..]   ciphertext = AES-256-GCM(DEK, body_nonce, plaintext) (+tag)
//
// KEY-MANAGEMENT POLICY (operator responsibility, documented here and in the
// runbook): every blob uses its own random 256-bit DEK, sealed under the KEK.
// The KEK is derived as SHA-256(SERVER_SECRET) — the same derivation as seal().
// SERVER_SECRET lives ONLY in the deployment environment and is NEVER copied
// into any backup (DB dumps, blob archives, volume snapshots, CI fixtures).
// Because the sealed DEK travels with the blob header, a stolen backup
// without SERVER_SECRET contains ciphertext that cannot be opened. Key
// material is never logged; DEKs are generated in-process and never leave
// the blob header.

/// Magic bytes identifying a v1 envelope blob. Legacy plaintext blobs (written
/// before encryption existed) do not start with these bytes and are served
/// through the legacy plaintext path.
pub const BLOB_MAGIC: &[u8; 4] = b"TSFS";

const BLOB_VERSION: u8 = 1;
const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// magic(4) + version(1) + dek_nonce(12) + sealed_dek(32+16) + body_nonce(12)
const BLOB_HEADER_LEN: usize = 4 + 1 + 12 + DEK_LEN + 16 + 12;

/// True if the leading bytes of a blob look like an envelope-encrypted file.
pub fn looks_like_encrypted_blob(head: &[u8]) -> bool {
    head.len() >= 5 && &head[..4] == BLOB_MAGIC && head[4] == BLOB_VERSION
}

fn kek(server_secret: &[u8]) -> [u8; 32] {
    Sha256::digest(server_secret).into()
}

/// Encrypt one blob's plaintext into the self-contained envelope format.
pub fn blob_encrypt(server_secret: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let mut dek = [0u8; DEK_LEN];
    rand::thread_rng().fill_bytes(&mut dek);
    let mut dek_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut dek_nonce);
    let mut body_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut body_nonce);

    let wrapped = Aes256Gcm::new_from_slice(&kek(server_secret))
        .expect("32-byte KEK")
        .encrypt(Nonce::from_slice(&dek_nonce), &dek[..])
        .expect("seal dek");
    let body = Aes256Gcm::new_from_slice(&dek)
        .expect("32-byte DEK")
        .encrypt(Nonce::from_slice(&body_nonce), plaintext)
        .expect("seal body");

    let mut out = Vec::with_capacity(BLOB_HEADER_LEN + body.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.push(BLOB_VERSION);
    out.extend_from_slice(&dek_nonce);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&body);
    out
}

/// Open an envelope blob with the KEK derived from SERVER_SECRET. Returns None
/// on any structural/authentication failure (tampering, wrong secret, or a
/// truncated file) — callers fall back to the legacy plaintext path only when
/// the file does NOT carry the magic; an authenticated-but-corrupt encrypted
/// blob is an error, never silently-plaintext.
pub fn blob_decrypt(server_secret: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if blob.len() < BLOB_HEADER_LEN || !looks_like_encrypted_blob(&blob[..5]) {
        return None;
    }
    let dek_nonce = &blob[5..17];
    let wrapped = &blob[17..65];
    let body_nonce = &blob[65..77];
    let body = &blob[77..];
    let dek = Aes256Gcm::new_from_slice(&kek(server_secret))
        .ok()?
        .decrypt(Nonce::from_slice(dek_nonce), wrapped)
        .ok()?;
    if dek.len() != DEK_LEN {
        return None;
    }
    Aes256Gcm::new_from_slice(&dek)
        .ok()?
        .decrypt(Nonce::from_slice(body_nonce), body)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_jwt_roundtrip() {
        let key = b"test-secret";
        let tok = jwt_encode(key, "app:1", "u_1", 2000000000);
        let claims = jwt_decode(key, &tok).unwrap();
        assert_eq!(claims.iss, "app:1");
        assert_eq!(claims.sub, "u_1");

        // wrong key must fail
        assert!(jwt_decode(b"other", &tok).is_none());
        // tampered signature must fail
        let mut bad = tok.clone();
        bad.pop();
        bad.push('x');
        assert!(jwt_decode(key, &bad).is_none());
    }

    #[test]
    fn seal_open_roundtrip() {
        let s = seal(b"server-key", b"app-secret-plaintext");
        assert_eq!(
            open(b"server-key", &s).unwrap(),
            b"app-secret-plaintext".to_vec()
        );
        assert!(open(b"wrong-key", &s).is_none());
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn blob_envelope_roundtrip() {
        let pt = b"the quick brown fox - 0123456789";
        let env = blob_encrypt(b"server-secret", pt);
        // Self-contained header present
        assert!(looks_like_encrypted_blob(&env));
        assert_eq!(&env[..4], b"TSFS");
        // Different random DEK per blob: two envelopes must differ byte-for-byte
        let env2 = blob_encrypt(b"server-secret", pt);
        assert_ne!(env, env2, "per-blob DEK/nonces must be random");
        // Opens with the right secret
        assert_eq!(blob_decrypt(b"server-secret", &env).unwrap(), pt);
        assert_eq!(blob_decrypt(b"server-secret", &env2).unwrap(), pt);
    }

    #[test]
    fn blob_envelope_rejects_wrong_secret_and_tampering() {
        let pt = b"payload";
        let mut env = blob_encrypt(b"server-secret", pt);
        assert!(blob_decrypt(b"wrong-secret", &env).is_none());
        // Flip a bit in the ciphertext body -> authentication failure
        let last = env.len() - 1;
        env[last] ^= 0x01;
        assert!(blob_decrypt(b"server-secret", &env).is_none());
        // Truncated -> rejected
        let env = blob_encrypt(b"server-secret", pt);
        assert!(blob_decrypt(b"server-secret", &env[..env.len() - 5]).is_none());
    }

    #[test]
    fn plaintext_does_not_look_encrypted() {
        assert!(!looks_like_encrypted_blob(b"plaintext legacy blob"));
        assert!(!looks_like_encrypted_blob(b""));
        assert!(!looks_like_encrypted_blob(b"TS"));
        // Wrong version byte is not an encrypted blob
        let mut env = blob_encrypt(b"s", b"x");
        env[4] = 9;
        assert!(!looks_like_encrypted_blob(&env));
    }
}

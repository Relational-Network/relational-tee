// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Encryption at rest, above the storage traits.
//!
//! Every storage key is derived from `storage-root`'s private scalar with
//! HKDF-SHA256 (salt `relational-tee/storage-root`, the label as info).
//! Labels carry a version so keys can rotate.
//!
//! - **Blobs:** a random 256-bit data key (DEK) and 96-bit nonce per object,
//!   AES-256-GCM. Stored as `"RSB1"` ‖ header length (u32, big-endian) ‖
//!   header (JSON) ‖ ciphertext and tag. The header carries the DEK wrapped
//!   with AES-256 key wrap (RFC 3394) under the blob KEK, or, for datasets,
//!   a `dek_ref` naming the row that holds it, so deleting that row erases an
//!   immutable blob. The AAD binds the container, path and header, so
//!   objects can't be moved or re-headed.
//! - **Table rows:** sensitive fields go in one binary `payload` property:
//!   nonce ‖ AES-256-GCM ciphertext and tag, with an AAD binding the table,
//!   partition key, row key and payload schema version.
//! - **Log lines:** `{ "v": 1, "id", "n", "ct" }`, with an AAD binding the
//!   container, path and event ID.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_kw::KekAes256;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::store::{Container, StoreError, Table};
use crate::tee::EcKey;

type HmacSha256 = Hmac<Sha256>;

const SALT: &[u8] = b"relational-tee/storage-root";
const BLOB_MAGIC: &[u8; 4] = b"RSB1";
const BLOB_AAD: &[u8] = b"relational-tee/blob/v1";
const TABLE_AAD: &[u8] = b"relational-tee/table/v1";
const LOG_AAD: &[u8] = b"relational-tee/log/v1";
const BLOB_KEK_LABEL: &str = "blob-kek-v1";

/// The keys derived from `storage-root`. They zeroize on drop.
pub struct StorageKeys {
    blob_kek: Zeroizing<[u8; 32]>,
    table_payload: Zeroizing<[u8; 32]>,
    index_hmac: Zeroizing<[u8; 32]>,
    audit_hmac: Zeroizing<[u8; 32]>,
    log_enc: Zeroizing<[u8; 32]>,
    cursor_hmac: Zeroizing<[u8; 32]>,
}

fn derive(ikm: &[u8], label: &str) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), ikm)
        .expand(label.as_bytes(), key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn hmac_hex(key: &[u8; 32], message: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_verify(key: &[u8; 32], message: &[u8], tag_hex: &str) -> bool {
    let Ok(tag) = hex::decode(tag_hex) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.verify_slice(&tag).is_ok()
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// `prefix ‖ 0x00 ‖ part ‖ 0x00 ‖ part …`
fn aad(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for part in parts {
        out.push(0);
        out.extend_from_slice(part);
    }
    out
}

fn integrity(what: &str) -> StoreError {
    StoreError::Integrity(what.to_string())
}

#[derive(Serialize, Deserialize)]
struct BlobHeader {
    alg: String,
    kek: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_dek: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dek_ref: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LogLine {
    v: u8,
    id: String,
    n: String,
    ct: String,
}

impl StorageKeys {
    /// Derive every storage key from `storage-root`.
    pub fn derive(storage_root: &EcKey) -> Self {
        let ikm = Zeroizing::new(storage_root.secret().to_bytes());
        Self {
            blob_kek: derive(&ikm, BLOB_KEK_LABEL),
            table_payload: derive(&ikm, "table-payload-v1"),
            index_hmac: derive(&ikm, "index-hmac-v1"),
            audit_hmac: derive(&ikm, "audit-hmac-v1"),
            log_enc: derive(&ikm, "log-enc-v1"),
            cursor_hmac: derive(&ikm, "cursor-hmac-v1"),
        }
    }

    /// `h(x)`: hex HMAC-SHA256 under the index key, so identifiers such as
    /// user IDs never appear in partition or row keys.
    pub fn index_hash(&self, value: &str) -> String {
        hmac_hex(&self.index_hmac, value.as_bytes())
    }

    /// The integrity tag of an audit or revocation event: hex HMAC-SHA256
    /// under the audit key.
    pub fn audit_tag(&self, canonical: &[u8]) -> String {
        hmac_hex(&self.audit_hmac, canonical)
    }

    pub fn audit_tag_valid(&self, canonical: &[u8], tag: &str) -> bool {
        hmac_verify(&self.audit_hmac, canonical, tag)
    }

    /// The tag of a pagination cursor.
    pub fn cursor_tag(&self, payload: &[u8]) -> String {
        hmac_hex(&self.cursor_hmac, payload)
    }

    pub fn cursor_tag_valid(&self, payload: &[u8], tag: &str) -> bool {
        hmac_verify(&self.cursor_hmac, payload, tag)
    }

    fn wrap(&self, dek: &[u8; 32]) -> Vec<u8> {
        KekAes256::from(*self.blob_kek)
            .wrap_vec(dek)
            .expect("a 32-byte key wraps")
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, StoreError> {
        let dek = Zeroizing::new(
            KekAes256::from(*self.blob_kek)
                .unwrap_vec(wrapped)
                .map_err(|_| integrity("the data key doesn't unwrap"))?,
        );
        let mut out = Zeroizing::new([0u8; 32]);
        if dek.len() != 32 {
            return Err(integrity("the data key has the wrong length"));
        }
        out.copy_from_slice(&dek);
        Ok(out)
    }

    /// Encrypt an object stored at `container/path` under a fresh DEK,
    /// wrapped in its own header.
    pub fn seal_blob(&self, container: Container, path: &str, plaintext: &[u8]) -> Vec<u8> {
        let dek = Zeroizing::new(random::<32>());
        let wrapped = Some(URL_SAFE_NO_PAD.encode(self.wrap(&dek)));
        self.seal_with(container, path, plaintext, &dek, wrapped, None)
    }

    /// Encrypt an object under a fresh DEK kept outside it: the header names
    /// `dek_ref`, and the caller stores the returned wrapped DEK there.
    pub fn seal_detached(
        &self,
        container: Container,
        path: &str,
        dek_ref: &str,
        plaintext: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let dek = Zeroizing::new(random::<32>());
        let sealed = self.seal_with(container, path, plaintext, &dek, None, Some(dek_ref.into()));
        (sealed, self.wrap(&dek))
    }

    fn seal_with(
        &self,
        container: Container,
        path: &str,
        plaintext: &[u8],
        dek: &[u8; 32],
        wrapped_dek: Option<String>,
        dek_ref: Option<String>,
    ) -> Vec<u8> {
        let nonce = random::<12>();
        let header = BlobHeader {
            alg: "A256GCM".into(),
            kek: BLOB_KEK_LABEL.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            wrapped_dek,
            dek_ref,
        };
        let header = serde_json::to_vec(&header).expect("header serializes");
        let aad = aad(
            BLOB_AAD,
            &[container.name().as_bytes(), path.as_bytes(), &header],
        );
        let ciphertext = Aes256Gcm::new_from_slice(dek)
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption doesn't fail");

        let mut out = Vec::with_capacity(8 + header.len() + ciphertext.len());
        out.extend_from_slice(BLOB_MAGIC);
        out.extend_from_slice(&(header.len() as u32).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt an object sealed by [`seal_blob`](Self::seal_blob) for the
    /// same `container/path`.
    pub fn open_blob(
        &self,
        container: Container,
        path: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.open_with(container, path, sealed, None)
    }

    /// Decrypt an object sealed by [`seal_detached`](Self::seal_detached),
    /// given the wrapped DEK stored at its `dek_ref`. The worker never reads
    /// datasets back yet.
    #[cfg(test)]
    pub fn open_detached(
        &self,
        container: Container,
        path: &str,
        sealed: &[u8],
        wrapped_dek: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.open_with(container, path, sealed, Some(wrapped_dek))
    }

    fn open_with(
        &self,
        container: Container,
        path: &str,
        sealed: &[u8],
        detached_dek: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if sealed.len() < 8 || &sealed[..4] != BLOB_MAGIC {
            return Err(integrity("not a sealed object"));
        }
        let header_len = u32::from_be_bytes(sealed[4..8].try_into().expect("4 bytes")) as usize;
        let header_end = 8usize
            .checked_add(header_len)
            .filter(|end| *end <= sealed.len())
            .ok_or_else(|| integrity("truncated object header"))?;
        let header_bytes = &sealed[8..header_end];
        let header: BlobHeader =
            serde_json::from_slice(header_bytes).map_err(|_| integrity("bad object header"))?;
        if header.alg != "A256GCM" || header.kek != BLOB_KEK_LABEL {
            return Err(integrity("unsupported object header"));
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(&header.nonce)
            .ok()
            .filter(|n| n.len() == 12)
            .ok_or_else(|| integrity("bad object nonce"))?;
        let wrapped = match (detached_dek, &header.wrapped_dek, &header.dek_ref) {
            (None, Some(w), None) => URL_SAFE_NO_PAD
                .decode(w)
                .map_err(|_| integrity("bad wrapped data key"))?,
            (Some(w), None, Some(_)) => w.to_vec(),
            _ => {
                return Err(integrity(
                    "object's data key isn't where the reader expects it",
                ))
            }
        };
        let dek = self.unwrap(&wrapped)?;
        let aad = aad(
            BLOB_AAD,
            &[container.name().as_bytes(), path.as_bytes(), header_bytes],
        );
        Aes256Gcm::new_from_slice(dek.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed[header_end..],
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| integrity("object doesn't decrypt at this path"))
    }

    fn row_aad(table: Table, pk: &str, rk: &str, version: u32) -> Vec<u8> {
        aad(
            TABLE_AAD,
            &[
                table.name().as_bytes(),
                pk.as_bytes(),
                rk.as_bytes(),
                version.to_string().as_bytes(),
            ],
        )
    }

    /// Encrypt a row payload for `table`, `pk` and `rk`.
    pub fn seal_row(
        &self,
        table: Table,
        pk: &str,
        rk: &str,
        version: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let nonce = random::<12>();
        let aad = Self::row_aad(table, pk, rk, version);
        let ciphertext = Aes256Gcm::new_from_slice(self.table_payload.as_ref())
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption doesn't fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt a row payload sealed for the same table and keys.
    pub fn open_row(
        &self,
        table: Table,
        pk: &str,
        rk: &str,
        version: u32,
        payload: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if payload.len() < 12 + 16 {
            return Err(integrity("row payload is truncated"));
        }
        let aad = Self::row_aad(table, pk, rk, version);
        Aes256Gcm::new_from_slice(self.table_payload.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&payload[..12]),
                Payload {
                    msg: &payload[12..],
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| integrity("row payload doesn't decrypt for these keys"))
    }

    /// One encrypted log line (with its trailing newline) for an event
    /// appended to `container/path`.
    pub fn seal_log_line(
        &self,
        container: Container,
        path: &str,
        event_id: &str,
        plaintext: &[u8],
    ) -> String {
        let nonce = random::<12>();
        let aad = aad(
            LOG_AAD,
            &[
                container.name().as_bytes(),
                path.as_bytes(),
                event_id.as_bytes(),
            ],
        );
        let ciphertext = Aes256Gcm::new_from_slice(self.log_enc.as_ref())
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption doesn't fail");
        let line = LogLine {
            v: 1,
            id: event_id.to_string(),
            n: URL_SAFE_NO_PAD.encode(nonce),
            ct: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let mut text = serde_json::to_string(&line).expect("log line serializes");
        text.push('\n');
        text
    }

    /// Decrypt one log line read from `container/path`: its event ID and plaintext.
    #[cfg(test)]
    pub fn open_log_line(
        &self,
        container: Container,
        path: &str,
        line: &str,
    ) -> Result<(String, Zeroizing<Vec<u8>>), StoreError> {
        let line: LogLine = serde_json::from_str(line).map_err(|_| integrity("bad log line"))?;
        let nonce = URL_SAFE_NO_PAD
            .decode(&line.n)
            .ok()
            .filter(|n| n.len() == 12)
            .ok_or_else(|| integrity("bad log line nonce"))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&line.ct)
            .map_err(|_| integrity("bad log line ciphertext"))?;
        let aad = aad(
            LOG_AAD,
            &[
                container.name().as_bytes(),
                path.as_bytes(),
                line.id.as_bytes(),
            ],
        );
        let plaintext = Aes256Gcm::new_from_slice(self.log_enc.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| integrity("log line doesn't decrypt at this path"))?;
        Ok((line.id, Zeroizing::new(plaintext)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;

    fn keys() -> StorageKeys {
        StorageKeys::derive(&fixed_key(1))
    }

    #[test]
    fn derivation_is_pinned() {
        // HKDF-SHA256(salt "relational-tee/storage-root", ikm = the scalar
        // 0x42 00…00 01, info = label), computed independently.
        let k = keys();
        assert_eq!(
            hex::encode(k.blob_kek.as_ref()),
            "b1412950e3d2a39e5644e9f42abbc0776655cdbeb80b3d6eb72a80c5c548ef07"
        );
        assert_eq!(
            hex::encode(k.index_hmac.as_ref()),
            "3c051f8d7a0f291acfa74ffe442b148edd089f24cb39cbf32c2a4b1d1cf9ce60"
        );
        assert_eq!(
            k.index_hash("user-1"),
            "5cae7ade181cdb0bb1d43fd3a3d1c7e8077cd23e97963daebd60ba7b66fb9c2e"
        );
    }

    #[test]
    fn blobs_open_only_at_their_own_path() {
        let k = keys();
        let sealed = k.seal_blob(Container::Datasets, "pool/a.csv.enc", b"a,b\n1,2\n");
        assert_eq!(&sealed[..4], b"RSB1");
        let opened = k
            .open_blob(Container::Datasets, "pool/a.csv.enc", &sealed)
            .expect("opens");
        assert_eq!(opened.as_slice(), b"a,b\n1,2\n");

        // Moving the object, even to another container, breaks the AAD.
        assert!(k
            .open_blob(Container::Datasets, "pool/b.csv.enc", &sealed)
            .is_err());
        assert!(k
            .open_blob(Container::Wallets, "pool/a.csv.enc", &sealed)
            .is_err());

        // So do a flipped ciphertext bit and a swapped header.
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(k
            .open_blob(Container::Datasets, "pool/a.csv.enc", &flipped)
            .is_err());
        let other = k.seal_blob(Container::Datasets, "pool/a.csv.enc", b"x");
        let header_len = u32::from_be_bytes(sealed[4..8].try_into().unwrap()) as usize;
        let mut swapped = other[..8 + header_len].to_vec();
        swapped.extend_from_slice(&sealed[8 + header_len..]);
        assert!(k
            .open_blob(Container::Datasets, "pool/a.csv.enc", &swapped)
            .is_err());

        // Another environment's storage root can't open it.
        let other_env = StorageKeys::derive(&fixed_key(2));
        assert!(other_env
            .open_blob(Container::Datasets, "pool/a.csv.enc", &sealed)
            .is_err());
    }

    #[test]
    fn detached_keys_open_only_with_their_own_wrapped_dek() {
        let k = keys();
        let path = "Pool1/r1.csv.enc";
        let (sealed, wrapped) =
            k.seal_detached(Container::Datasets, path, "records/Pool1/rec:r1", b"csv");
        assert_eq!(
            k.open_detached(Container::Datasets, path, &sealed, &wrapped)
                .unwrap()
                .as_slice(),
            b"csv"
        );
        // Without its key the object can't be opened at all.
        assert!(k.open_blob(Container::Datasets, path, &sealed).is_err());
        let (_, other) = k.seal_detached(Container::Datasets, path, "records/Pool1/rec:r2", b"x");
        assert!(k
            .open_detached(Container::Datasets, path, &sealed, &other)
            .is_err());
        // A self-contained object doesn't take an outside key either.
        let inline = k.seal_blob(Container::Datasets, path, b"csv");
        assert!(k
            .open_detached(Container::Datasets, path, &inline, &wrapped)
            .is_err());
    }

    #[test]
    fn row_payloads_are_bound_to_their_keys() {
        let k = keys();
        let sealed = k.seal_row(Table::Wallets, "wallet", "w1", 1, b"{}");
        assert_eq!(
            k.open_row(Table::Wallets, "wallet", "w1", 1, &sealed)
                .unwrap()
                .as_slice(),
            b"{}"
        );
        assert!(k
            .open_row(Table::Wallets, "wallet", "w2", 1, &sealed)
            .is_err());
        assert!(k
            .open_row(Table::Pools, "wallet", "w1", 1, &sealed)
            .is_err());
        assert!(k
            .open_row(Table::Wallets, "wallet", "w1", 2, &sealed)
            .is_err());
    }

    #[test]
    fn log_lines_are_bound_to_their_blob_and_event() {
        let k = keys();
        let line = k.seal_log_line(Container::Audit, "2026/09/29/10/w.jsonl", "e1", b"event");
        assert!(line.ends_with('\n'));
        let (id, plain) = k
            .open_log_line(Container::Audit, "2026/09/29/10/w.jsonl", line.trim_end())
            .expect("opens");
        assert_eq!((id.as_str(), plain.as_slice()), ("e1", b"event".as_slice()));
        assert!(k
            .open_log_line(Container::Audit, "2026/09/29/11/w.jsonl", line.trim_end())
            .is_err());
        let renamed = line.replace("\"id\":\"e1\"", "\"id\":\"e2\"");
        assert!(k
            .open_log_line(
                Container::Audit,
                "2026/09/29/10/w.jsonl",
                renamed.trim_end()
            )
            .is_err());
    }
}

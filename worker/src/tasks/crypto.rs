//! The keys of a task, and what is sealed with them.
//!
//! ```text
//! project key (keystore)   task-key:v1:{project_uuid}:{owner}
//!   task key               HMAC-SHA256(project key, "task:" || id)
//!     seal key             HMAC-SHA256(task key, "seal")     XChaCha20-Poly1305
//!     reply key pair       HMAC-SHA256(task key, "reply:" || n) as a P-256 scalar
//! content key              32 random bytes, per task        AES-256-GCM
//! ```
//!
//! **Sealed** ([`seal`], [`open`]): for the enclave alone — the task's sealed
//! copy and the outcome it leaves. `0x01 || nonce (24) || ciphertext || tag`,
//! XChaCha20-Poly1305, bound to the task's id and to what the bytes are.
//!
//! **For a browser** — the content, its key wrapped to a device, and what the
//! owner's page sends back — is what WebCrypto has: AES-256-GCM, and ECDH on
//! P-256 with HKDF-SHA256.
//!
//! * Content ([`encrypt_content`]): `0x01 || nonce (12) || ciphertext || tag`
//!   under the content key, bound to the task's id. A file of the task
//!   ([`encrypt_file`]) is the same under the same key, bound to the task's
//!   id and the file's place: `{id}:file:{n}`.
//! * To a public key ([`seal_to`], [`open_from`]): `0x01 || ephemeral public
//!   key (65, uncompressed) || nonce (12) || ciphertext || tag`. The AES key
//!   is `HKDF-SHA256(ikm = ECDH x-coordinate, salt = ephemeral public key ||
//!   recipient public key, info)`, and `info` names the purpose and the task,
//!   so a blob made for one task or one purpose opens for no other.
//!
//! Every failure to open is [`DECRYPTION_FAILED`] and nothing more.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use zeroize::Zeroizing;

/// What every failure to open says.
pub const DECRYPTION_FAILED: &str = "decryption failed";

/// How a P-256 public key is written: the curve, and the uncompressed point
/// in base64url without padding.
pub const P256_PREFIX: &str = "p256:";

const FORMAT: u8 = 0x01;
const XNONCE_LEN: usize = 24;
const GCM_NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const POINT_LEN: usize = 65;

/// What a sealed blob is, bound into it beside the task's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealed {
    /// The task's sealed copy: envelope, state and content key.
    Task,
    /// What the project left for the preparer.
    Outcome,
}

impl Sealed {
    fn label(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Outcome => "outcome",
        }
    }
}

/// What a blob encrypted to a public key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A task's content key, to a device of the owner.
    DeviceCopy,
    /// What the owner supplies with an answer, to the task's reply key.
    Answer,
    /// The reason of a rejection, to the task's reply key.
    Rejection,
}

impl Purpose {
    fn info(self, task: &str) -> Vec<u8> {
        let label = match self {
            Self::DeviceCopy => "outlayer-task:v1:device-copy:",
            Self::Answer => "outlayer-task:v1:answer:",
            Self::Rejection => "outlayer-task:v1:rejection:",
        };
        [label.as_bytes(), task.as_bytes()].concat()
    }
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    crate::encryption_keys::hmac_sha256(key, &parts.concat())
}

/// The keys of one task, derived from the project's key for its owner.
pub struct TaskKeys {
    seal: Zeroizing<[u8; 32]>,
    reply: p256::SecretKey,
}

impl TaskKeys {
    pub fn derive(project_key: &[u8; 32], task: &str) -> Self {
        let task_key = hmac(project_key, &[b"task:", task.as_bytes()]);
        let seal = hmac(&task_key, &[b"seal"]);
        // A scalar outside the curve's order is passed over; the next counter
        // gives another. For P-256 that is one draw in 2^32.
        let reply = (0u32..)
            .find_map(|n| p256::SecretKey::from_slice(hmac(&task_key, &[b"reply:", &n.to_be_bytes()]).as_ref()).ok())
            .expect("a scalar within the order is found");
        Self { seal, reply }
    }

    /// The public half of the reply key, as the task carries it.
    pub fn reply_pubkey(&self) -> String {
        write_pubkey(&self.reply.public_key())
    }

    /// Seal `plaintext` for the enclave, as `what` of `task`.
    pub fn seal(&self, what: Sealed, task: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let mut nonce = [0u8; XNONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "the host has no randomness for a nonce".to_string())?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(self.seal.as_ref()));
        let aad = sealed_aad(what, task);
        let sealed = cipher
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| "sealing failed".to_string())?;
        Ok([&[FORMAT][..], &nonce, &sealed].concat())
    }

    /// Open what [`Self::seal`] made as the same `what` of the same `task`.
    pub fn open(&self, what: Sealed, task: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        if blob.len() < 1 + XNONCE_LEN + TAG_LEN || blob[0] != FORMAT {
            return Err(DECRYPTION_FAILED.to_string());
        }
        let (nonce, sealed) = blob[1..].split_at(XNONCE_LEN);
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(self.seal.as_ref()));
        let aad = sealed_aad(what, task);
        cipher
            .decrypt(chacha20poly1305::XNonce::from_slice(nonce), Payload { msg: sealed, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| DECRYPTION_FAILED.to_string())
    }

    /// Open what the owner's page encrypted to the reply key for `purpose`.
    pub fn open_reply(&self, purpose: Purpose, task: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        open_from(&self.reply, purpose, task, blob)
    }
}

fn sealed_aad(what: Sealed, task: &str) -> Vec<u8> {
    [b"outlayer-task:v1:", what.label().as_bytes(), b":", task.as_bytes()].concat()
}

/// A fresh content key.
pub fn content_key() -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(key.as_mut())
        .map_err(|_| "the host has no randomness for a key".to_string())?;
    Ok(key)
}

fn gcm_nonce() -> Result<[u8; GCM_NONCE_LEN], String> {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| "the host has no randomness for a nonce".to_string())?;
    Ok(nonce)
}

/// The content of `task` under its content key.
pub fn encrypt_content(key: &[u8; 32], task: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_under(key, task.as_bytes(), plaintext)
}

/// What a file of a task is bound to: the task, and its place among the
/// task's files.
fn file_aad(task: &str, at: usize) -> Vec<u8> {
    format!("{task}:file:{at}").into_bytes()
}

/// The file at `at` of `task` under the task's content key, in the content's
/// own format. A file opens as that file of that task and as nothing else.
pub fn encrypt_file(key: &[u8; 32], task: &str, at: usize, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_under(key, &file_aad(task, at), plaintext)
}

/// Open what [`encrypt_file`] made.
pub fn decrypt_file(key: &[u8; 32], task: &str, at: usize, blob: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_under(key, &file_aad(task, at), blob)
}

fn encrypt_under(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = gcm_nonce()?;
    let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key));
    let sealed = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "encryption failed".to_string())?;
    Ok([&[FORMAT][..], &nonce, &sealed].concat())
}

fn decrypt_under(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 1 + GCM_NONCE_LEN + TAG_LEN || blob[0] != FORMAT {
        return Err(DECRYPTION_FAILED.to_string());
    }
    let (nonce, sealed) = blob[1..].split_at(GCM_NONCE_LEN);
    let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|_| DECRYPTION_FAILED.to_string())
}

/// What [`encrypt_content`] made — the owner's page does this; here for the
/// tests that stand in for it.
#[cfg(test)]
pub fn decrypt_content(key: &[u8; 32], task: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_under(key, task.as_bytes(), blob)
}

/// A public key as it is written: [`P256_PREFIX`] and the uncompressed point.
pub fn write_pubkey(key: &p256::PublicKey) -> String {
    let point = key.to_encoded_point(false);
    format!("{P256_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.as_bytes()))
}

/// A public key as written, checked to be a point on the curve.
pub fn read_pubkey(written: &str) -> Result<p256::PublicKey, String> {
    let point = written.strip_prefix(P256_PREFIX).ok_or("the key is not written `p256:…`")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(point.as_bytes())
        .map_err(|_| "the key is not base64url".to_string())?;
    if bytes.len() != POINT_LEN || bytes[0] != 0x04 {
        return Err("the key is not an uncompressed point of 65 bytes".to_string());
    }
    p256::PublicKey::from_sec1_bytes(&bytes).map_err(|_| "the key is not a point on P-256".to_string())
}

fn ecies_key(
    shared: &p256::ecdh::SharedSecret,
    ephemeral: &[u8],
    recipient: &[u8],
    purpose: Purpose,
    task: &str,
) -> Zeroizing<[u8; 32]> {
    let salt = [ephemeral, recipient].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared.raw_secret_bytes().as_slice())
        .expand(&purpose.info(task), key.as_mut())
        .expect("32 bytes are within HKDF's output");
    key
}

/// Encrypt `plaintext` to `recipient` for `purpose` of `task`.
pub fn seal_to(recipient: &p256::PublicKey, purpose: Purpose, task: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
    let ephemeral_point = ephemeral.public_key().to_encoded_point(false);
    let recipient_point = recipient.to_encoded_point(false);
    let shared = ephemeral.diffie_hellman(recipient);
    let key = ecies_key(&shared, ephemeral_point.as_bytes(), recipient_point.as_bytes(), purpose, task);
    let nonce = gcm_nonce()?;
    let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key.as_ref()));
    let sealed = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &[] })
        .map_err(|_| "encryption failed".to_string())?;
    Ok([&[FORMAT][..], ephemeral_point.as_bytes(), &nonce, &sealed].concat())
}

/// Open what [`seal_to`] — or the owner's page, by the same construction —
/// encrypted to the public half of `secret` for the same purpose and task.
pub fn open_from(secret: &p256::SecretKey, purpose: Purpose, task: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let failed = || DECRYPTION_FAILED.to_string();
    if blob.len() < 1 + POINT_LEN + GCM_NONCE_LEN + TAG_LEN || blob[0] != FORMAT {
        return Err(failed());
    }
    let (ephemeral_point, rest) = blob[1..].split_at(POINT_LEN);
    let (nonce, sealed) = rest.split_at(GCM_NONCE_LEN);
    let ephemeral = p256::PublicKey::from_sec1_bytes(ephemeral_point).map_err(|_| failed())?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let recipient_point = secret.public_key().to_encoded_point(false);
    let key = ecies_key(&shared, ephemeral_point, recipient_point.as_bytes(), purpose, task);
    let cipher = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key.as_ref()));
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: sealed, aad: &[] })
        .map(Zeroizing::new)
        .map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT_KEY: [u8; 32] = [7u8; 32];

    fn device() -> p256::SecretKey {
        p256::SecretKey::random(&mut rand::rngs::OsRng)
    }

    #[test]
    fn a_tasks_keys_are_its_own() {
        let (a, again, b) = (
            TaskKeys::derive(&PROJECT_KEY, "run-0"),
            TaskKeys::derive(&PROJECT_KEY, "run-0"),
            TaskKeys::derive(&PROJECT_KEY, "run-1"),
        );
        assert_eq!(a.reply_pubkey(), again.reply_pubkey());
        assert_ne!(a.reply_pubkey(), b.reply_pubkey());
        let other_project = TaskKeys::derive(&[8u8; 32], "run-0");
        assert_ne!(a.reply_pubkey(), other_project.reply_pubkey());
        assert!(read_pubkey(&a.reply_pubkey()).is_ok());
    }

    /// Pinned: a change to the derivation changes every task's keys, and what
    /// was sealed no longer opens.
    #[test]
    fn the_reply_key_of_a_task_is_pinned() {
        assert_eq!(TaskKeys::derive(&PROJECT_KEY, "run-0").reply_pubkey(), PINNED_REPLY_KEY);
    }

    const PINNED_REPLY_KEY: &str =
        "p256:BNuauRGLIM1_y5TyuGFWUuc1DchdnxTyepLoto5HgpAfSTZvN20m27RBD-OekVO1ERM9WATr--6-ko7G9MDcbaI";

    #[test]
    fn what_is_sealed_opens_as_the_same_thing_of_the_same_task_and_as_nothing_else() {
        let keys = TaskKeys::derive(&PROJECT_KEY, "run-0");
        let blob = keys.seal(Sealed::Task, "run-0", b"the envelope").unwrap();
        assert_eq!(keys.open(Sealed::Task, "run-0", &blob).unwrap().as_slice(), b"the envelope");
        assert_ne!(blob, keys.seal(Sealed::Task, "run-0", b"the envelope").unwrap(), "a fresh nonce every time");

        let refused = |r: Result<Zeroizing<Vec<u8>>, String>| assert_eq!(r.unwrap_err(), DECRYPTION_FAILED);
        refused(keys.open(Sealed::Outcome, "run-0", &blob));
        refused(keys.open(Sealed::Task, "run-1", &blob));
        // Another task's keys, on a copy put in this task's place.
        refused(TaskKeys::derive(&PROJECT_KEY, "run-1").open(Sealed::Task, "run-1", &blob));
        refused(TaskKeys::derive(&[8u8; 32], "run-0").open(Sealed::Task, "run-0", &blob));
        let mut changed = blob.clone();
        *changed.last_mut().unwrap() ^= 1;
        refused(keys.open(Sealed::Task, "run-0", &changed));
        refused(keys.open(Sealed::Task, "run-0", &blob[..blob.len() - 1]));
        refused(keys.open(Sealed::Task, "run-0", &blob[..10]));
        refused(keys.open(Sealed::Task, "run-0", &[]));
        let mut another_format = blob.clone();
        another_format[0] = 0x02;
        refused(keys.open(Sealed::Task, "run-0", &another_format));
    }

    #[test]
    fn content_opens_under_its_key_for_its_task() {
        let key = content_key().unwrap();
        let blob = encrypt_content(&key, "run-0", b"{\"title\":\"Send\"}").unwrap();
        assert_eq!(decrypt_content(&key, "run-0", &blob).unwrap(), b"{\"title\":\"Send\"}");
        assert!(decrypt_content(&key, "run-1", &blob).is_err());
        assert!(decrypt_content(&content_key().unwrap(), "run-0", &blob).is_err());
        assert_eq!(blob.len(), 1 + 12 + 16 + 16);
    }

    #[test]
    fn a_file_opens_as_that_file_of_that_task_and_as_nothing_else() {
        let key = content_key().unwrap();
        let blob = encrypt_file(&key, "run-0", 1, b"%PDF-1.7").unwrap();
        assert_eq!(decrypt_file(&key, "run-0", 1, &blob).unwrap(), b"%PDF-1.7");
        assert!(decrypt_file(&key, "run-0", 0, &blob).is_err(), "another place among the files");
        assert!(decrypt_file(&key, "run-1", 1, &blob).is_err(), "another task");
        assert!(decrypt_content(&key, "run-0", &blob).is_err(), "a file is not the content");
        assert!(decrypt_file(&content_key().unwrap(), "run-0", 1, &blob).is_err());
        assert!(decrypt_file(&key, "run-0", 1, &blob[..blob.len() - 1]).is_err());
    }

    #[test]
    fn a_blob_for_a_key_opens_with_its_private_half_for_its_purpose_and_task() {
        let (mine, theirs) = (device(), device());
        let blob = seal_to(&mine.public_key(), Purpose::DeviceCopy, "run-0", &[9u8; 32]).unwrap();
        assert_eq!(blob.len(), 1 + 65 + 12 + 32 + 16);
        assert_eq!(open_from(&mine, Purpose::DeviceCopy, "run-0", &blob).unwrap().as_slice(), &[9u8; 32]);

        let refused = |r: Result<Zeroizing<Vec<u8>>, String>| assert_eq!(r.unwrap_err(), DECRYPTION_FAILED);
        refused(open_from(&theirs, Purpose::DeviceCopy, "run-0", &blob));
        refused(open_from(&mine, Purpose::Answer, "run-0", &blob));
        refused(open_from(&mine, Purpose::DeviceCopy, "run-1", &blob));
        refused(open_from(&mine, Purpose::DeviceCopy, "run-0", &blob[..blob.len() - 1]));
        refused(open_from(&mine, Purpose::DeviceCopy, "run-0", b"not ciphertext"));
        let mut off_curve = blob.clone();
        off_curve[2] ^= 1;
        refused(open_from(&mine, Purpose::DeviceCopy, "run-0", &off_curve));
    }

    #[test]
    fn what_the_page_writes_to_the_reply_key_the_task_opens() {
        let keys = TaskKeys::derive(&PROJECT_KEY, "run-0");
        let reply = read_pubkey(&keys.reply_pubkey()).unwrap();
        let answer = seal_to(&reply, Purpose::Answer, "run-0", b"ipfs://photo").unwrap();
        assert_eq!(keys.open_reply(Purpose::Answer, "run-0", &answer).unwrap().as_slice(), b"ipfs://photo");
        assert!(keys.open_reply(Purpose::Rejection, "run-0", &answer).is_err());
        assert!(TaskKeys::derive(&PROJECT_KEY, "run-1").open_reply(Purpose::Answer, "run-1", &answer).is_err());
    }

    /// The device of the golden vectors: the scalar `01 02 … 20`.
    fn golden_device() -> p256::SecretKey {
        p256::SecretKey::from_slice(&core::array::from_fn::<u8, 32, _>(|i| (i as u8) + 1)).unwrap()
    }

    const GOLDEN_TASK: &str = "run-0";
    const GOLDEN_DOCUMENT: &str = r#"{"display":{"fields":[],"title":"Send an email"},"id":"run-0"}"#;

    /// `cargo test --lib tasks::crypto -- --ignored --nocapture
    /// print_fresh_golden_vectors` when a format changes; the output is
    /// `tests/lib/tasks_golden.json`.
    #[test]
    #[ignore]
    fn print_fresh_golden_vectors() {
        let content_key = [9u8; 32];
        let golden = serde_json::json!({
            "task": GOLDEN_TASK,
            "document": GOLDEN_DOCUMENT,
            "hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(GOLDEN_DOCUMENT.as_bytes())),
            "content_key": hex::encode(content_key),
            "device_pubkey": write_pubkey(&golden_device().public_key()),
            "device_copy": hex::encode(seal_to(&golden_device().public_key(), Purpose::DeviceCopy, GOLDEN_TASK, &content_key).unwrap()),
            "content": hex::encode(encrypt_content(&content_key, GOLDEN_TASK, GOLDEN_DOCUMENT.as_bytes()).unwrap()),
            "reply_pubkey": TaskKeys::derive(&PROJECT_KEY, GOLDEN_TASK).reply_pubkey(),
        });
        println!("{}", serde_json::to_string_pretty(&golden).unwrap());
    }

    /// The bytes the page's test opens with WebCrypto
    /// (`tests/lib/tasks_page.test.mjs`), and the answer the page sealed for
    /// this host to open.
    #[test]
    fn the_golden_vectors_the_page_also_opens() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/lib/tasks_golden.json")).expect("the golden vectors");
        let bytes = |member: &str| hex::decode(golden[member].as_str().unwrap()).unwrap();
        assert_eq!(golden["device_pubkey"], write_pubkey(&golden_device().public_key()));
        assert_eq!(golden["reply_pubkey"], TaskKeys::derive(&PROJECT_KEY, GOLDEN_TASK).reply_pubkey());
        let key = open_from(&golden_device(), Purpose::DeviceCopy, GOLDEN_TASK, &bytes("device_copy")).unwrap();
        assert_eq!(key.as_slice(), &[9u8; 32]);
        let document = decrypt_content(&[9u8; 32], GOLDEN_TASK, &bytes("content")).unwrap();
        assert_eq!(document, GOLDEN_DOCUMENT.as_bytes());

        let answer = hex::decode(ANSWER_FROM_THE_PAGE).unwrap();
        let opened = TaskKeys::derive(&PROJECT_KEY, GOLDEN_TASK).open_reply(Purpose::Answer, GOLDEN_TASK, &answer).unwrap();
        assert_eq!(opened.as_slice(), b"ipfs://photo#sha256=abc");
    }

    /// Sealed by the page (`TASKS_PRINT=1 node --test tests/lib/tasks_page.test.mjs`).
    const ANSWER_FROM_THE_PAGE: &str = "01047fb3d41b9d5d9a30495e11c08eba67f71ff24387b2fc9d898905e0c94d224687e9e7fa50cc498e75667beac21f235a9d28b79ae4ed4e452a5e9049ce06059d3527276ff907eddd51c6ad119df03f3e8b2c907b548ac987cca04b3bec50edeaeaad14c03896610a82dd8a6fa2b2cd7dd2d89503";

    #[test]
    fn a_key_is_read_only_as_a_point_on_the_curve() {
        let key = device().public_key();
        assert_eq!(read_pubkey(&write_pubkey(&key)).unwrap(), key);
        let encode = |bytes: &[u8]| format!("p256:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
        let mut off = vec![0x04u8];
        off.extend_from_slice(&[7u8; 64]);
        assert!(read_pubkey(&encode(&off)).unwrap_err().contains("not a point"));
        assert!(read_pubkey(&encode(&[2u8; 33])).unwrap_err().contains("uncompressed"));
        assert!(read_pubkey("ed25519:abc").unwrap_err().contains("p256"));
        assert!(read_pubkey("p256:***").unwrap_err().contains("base64url"));
    }
}

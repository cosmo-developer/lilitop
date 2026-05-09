# CyberDarkNet Crypto Internals: How End-to-End Encryption Works

> **TL;DR** — The server is a blind courier. It stores ciphertext it cannot read, routes packets it cannot inspect, and verifies signatures it did not produce. All keys that matter live only on client devices. Here is exactly how.

---

## The Problem This Solves

Traditional chat servers are trusted third parties. Even with HTTPS, the server decrypts your message, stores it in plaintext, and re-encrypts it for the recipient. If the server is compromised — by a hacker, a subpoena, or a rogue admin — every message is exposed.

CyberDarkNet inverts this. The server only ever sees:
- **Ciphertext blobs** (BYTEA columns it cannot interpret)
- **Public keys** (by definition, meant to be public)
- **Message metadata** (sender device ID, conversation ID, timestamps)

The private keys never leave the client. The server does not have them. Even if you hand an attacker root access to the database, they get encrypted noise.

---

## Key Types in Play

Two fundamentally different key types are used, each for a different job.

### Ed25519 Keys — Identity and Signing

Ed25519 is a **digital signature** algorithm. A private key signs data; anyone with the corresponding public key can verify the signature. It proves *who created something*, not *who can read something*.

**Used for:**
- Device identity: each device registers an `identity_key` (Ed25519 public key)
- Signed prekeys: the device signs its X25519 prekey so recipients know it wasn't swapped by the server
- Federation: servers sign their handshake and relay packets to prevent impersonation

```rust
// src/crypto/keys.rs
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,    // private — never leaves device
    pub verifying_key: VerifyingKey // public — uploaded to server
}
```

The server **stores** Ed25519 public keys but **cannot produce** valid signatures with them. A compromised server cannot forge device identity.

### X25519 Keys — Key Agreement (Diffie-Hellman)

X25519 is an **elliptic-curve Diffie-Hellman** function. Two parties each have a private/public keypair. They exchange public keys and independently compute the same shared secret, without the shared secret ever being transmitted.

**Used for:**
- `identity_key` (X25519): long-term device DH key
- `signed_prekey` (X25519): medium-term DH key, rotated periodically
- `one_time_prekeys` (X25519): single-use DH keys, consumed one per session

```rust
// src/crypto/keys.rs
impl X25519KeyPair {
    pub fn diffie_hellman(&self, their_pub: &[u8; 32]) -> [u8; 32] {
        x25519(self.secret, *their_pub) // both sides compute same result
    }
}
```

The server stores **only the public halves**. The private halves stay on the device. Without private keys, DH outputs cannot be computed.

---

## Phase 1: Device Registration

When a device first connects, it uploads a **prekey bundle** — a collection of public keys:

```
POST /api/v1/devices/register
{
  "identity_key":              "<Ed25519 public, base64>",
  "signed_prekey":             "<X25519 public, base64>",
  "signed_prekey_signature":   "<Ed25519 sig of signed_prekey, base64>",
  "one_time_prekeys": [
    { "key_id": 1, "public_key": "<X25519 public, base64>" },
    { "key_id": 2, "public_key": "<X25519 public, base64>" },
    ...
  ]
}
```

The server performs one critical check before storing:

```rust
// src/api/devices.rs — verify_device_keys()
verify_signed_prekey(
    &req.identity_key,           // Ed25519 verifying key
    &req.signed_prekey,          // X25519 public key (as bytes)
    &req.signed_prekey_signature // Ed25519 sig of those bytes
)
```

This confirms the `signed_prekey` was produced by the same device that owns the `identity_key`. The server cannot fake this relationship — it does not have the Ed25519 private key needed to produce the signature.

After this, the server stores public keys in PostgreSQL and **discards nothing** — it never had the private keys to begin with.

---

## Phase 2: Session Initiation — X3DH

Before Alice can send Bob a message, they need a shared secret. They have never talked before. The server cannot learn the secret. This is solved by **Extended Triple Diffie-Hellman (X3DH)**, the same algorithm Signal uses.

### Alice fetches Bob's prekey bundle

```
GET /api/v1/devices/{bob_device_id}/prekey-bundle
→ {
    identity_key, signed_prekey, signed_prekey_signature,
    one_time_prekey  // consumed — server marks it used
  }
```

The server pops one one-time prekey and marks it used. One-time prekeys are single-use; replaying them is impossible.

### Alice runs X3DH locally

```rust
// src/crypto/x3dh.rs — initiate()
pub fn initiate(
    alice_identity_priv: [u8; 32],   // Alice's private key — never sent
    alice_ephemeral_priv: [u8; 32],  // fresh random key — never sent
    bob_bundle: &PrekeyBundle,       // what server returned
) -> ([u8; 32], X3DHMessage)         // (shared_secret, what to send Bob)
```

Four DH operations are combined:

| Operation | Alice's key | Bob's key | Why |
|-----------|------------|-----------|-----|
| DH1 | Identity (private) | Signed prekey (public) | Authenticates Alice |
| DH2 | Ephemeral (private) | Identity (public) | Authenticates Bob |
| DH3 | Ephemeral (private) | Signed prekey (public) | Forward secrecy |
| DH4 | Ephemeral (private) | One-time prekey (public) | Deniability + extra secrecy |

```rust
let dh1 = x25519(alice_identity_priv, bob_spk);
let dh2 = x25519(alice_ephemeral_priv, bob_ik);
let dh3 = x25519(alice_ephemeral_priv, bob_spk);
let dh4 = x25519(alice_ephemeral_priv, bob_opk); // if one-time prekey exists
```

These four outputs are concatenated and fed into HKDF-SHA256:

```rust
// src/crypto/kdf.rs — x3dh_kdf()
pub fn x3dh_kdf(dh_outputs: &[&[u8; 32]]) -> [u8; 32] {
    let mut ikm = F.to_vec(); // 32×0xFF padding prefix (per X3DH spec)
    for dh in dh_outputs { ikm.extend_from_slice(*dh); }
    hkdf_sha256(&[0u8; 32], &ikm, b"cyberdarknet-x3dh-v1")
}
```

Alice now has a 32-byte `shared_secret`. She sends Bob her public ephemeral key and identity key (the `X3DHMessage`). The server relays this header alongside the ciphertext.

### Bob reconstructs the same secret

```rust
// src/crypto/x3dh.rs — respond()
pub fn respond(
    bob_identity_priv: [u8; 32],       // Bob's private key
    bob_signed_prekey_priv: [u8; 32],  // Bob's prekey private
    bob_one_time_prekey_priv: Option<[u8; 32]>,
    alice_msg: &X3DHMessage,           // Alice's public keys from header
) -> [u8; 32]                          // same shared_secret
```

Bob runs the DH operations in reverse order but arrives at the same 32-byte secret. The server **watched the key exchange** but cannot compute any of the DH outputs — it only ever saw public keys.

---

## Phase 3: Ongoing Messages — Double Ratchet

X3DH establishes one shared secret. But using the same key for every message is dangerous: if one key leaks, all past and future messages are exposed. The **Double Ratchet** solves this by deriving a new encryption key for every single message.

### Two interlocked ratchets

**Symmetric ratchet (chain key → message key):**

```rust
// src/crypto/kdf.rs — kdf_ck()
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let msg_key = hmac_sha256(chain_key, &[0x01]); // key for this message
    let new_ck  = hmac_sha256(chain_key, &[0x02]); // advance the chain
    (new_ck, msg_key)
}
```

Each call advances the chain and produces a one-use message key. Knowing message key #5 does not let you derive message key #4 (HMAC is one-way).

**DH ratchet (root key refresh):**

```rust
// src/crypto/kdf.rs — kdf_rk()
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let derived = hkdf_sha256(root_key, dh_output, b"cyberdarknet-ratchet-v1");
    let new_rk = hkdf_sha256(&derived, &[0x01], RATCHET_INFO);
    let new_ck = hkdf_sha256(&derived, &[0x02], RATCHET_INFO);
    (new_rk, new_ck)
}
```

Every time the conversation direction flips (Alice sends, then Bob replies), a new DH exchange happens. This rotates the root key. An attacker who steals the root key at time T cannot decrypt messages from before T (**forward secrecy**) and cannot predict keys after T is rotated (**break-in recovery**).

### Message encryption

Each message is encrypted with AES-256-GCM using the per-message key from `kdf_ck`:

```rust
// src/crypto/aes.rs
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    // random 12-byte nonce per message
    OsRng.fill_bytes(&mut nonce_bytes);
    // output: nonce(12) || ciphertext+tag
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
}
```

The server receives and stores only this `nonce || ciphertext` blob. The 16-byte GCM authentication tag is included in the ciphertext — if anyone tampers with the blob, decryption fails with an authentication error.

---

## What the Server Stores vs What It Knows

| Data | Stored in DB | Server can read it? |
|------|-------------|---------------------|
| Message content | `messages.payload` — BYTEA ciphertext | No — no decryption key |
| Ed25519 identity keys | `devices.identity_key` | Yes, but these are **public** by design |
| X25519 prekeys (public) | `devices.signed_prekey`, `one_time_prekeys` | Yes, but **public** — DH requires private half |
| Ed25519 private keys | Never uploaded | N/A — never transmitted |
| X25519 private keys | Never uploaded | N/A — never transmitted |
| Session shared secret | Never transmitted | N/A — derived locally |
| Message keys | Never transmitted | N/A — derived locally |
| Ratchet state | Never transmitted | N/A — maintained on client |
| User passwords | `users.password_hash` (Argon2id) | Hash only — not reversible |
| JWT secrets | Memory only (`TOKEN_SECRET` env var) | Yes — but these only prove auth, not decrypt messages |

---

## The Server's One Cryptographic Power

The server **does** have one keypair: an Ed25519 key used exclusively for **federation packet signing**.

```rust
// src/main.rs — loaded from SERVER_PRIVATE_KEY env var
server_keys: Arc<Ed25519KeyPair>
```

This key signs outbound federation packets so peer servers can verify authenticity:

```
canonical bytes = packet_id | source | destination | timestamp | nonce | payload_json
signature = Ed25519.sign(server_private_key, canonical_bytes)
```

This proves *which server* sent a packet. It says nothing about message content — the messages inside packets are already ciphertext the signing server also cannot read.

---

## Key Flow Summary

```
DEVICE SIDE                              SERVER SIDE
───────────────────────────────────────  ──────────────────────────────────────

[Registration]
Generate Ed25519 keypair (IK)
Generate X25519 keypair (SPK)
Sign SPK with IK private key
Generate N × X25519 one-time prekeys
                                    ──→  Store: IK_pub, SPK_pub, sig, OTPKs
                                         Verify: sig(IK_priv, SPK_pub) valid?
                                         ✓ store  ✗ reject

[Alice starts conversation with Bob]
                                    ←──  Serve Bob's prekey bundle
                                         (IK_pub, SPK_pub, one OTPK_pub)
                                         Mark OTPK as used

Compute X3DH locally:
  dh1 = x25519(Alice_IK_priv, Bob_SPK_pub)
  dh2 = x25519(Alice_EK_priv, Bob_IK_pub)
  dh3 = x25519(Alice_EK_priv, Bob_SPK_pub)
  dh4 = x25519(Alice_EK_priv, Bob_OTPK_pub)
  shared_secret = HKDF(dh1‖dh2‖dh3‖dh4)

Init Double Ratchet with shared_secret
Encrypt msg with ratchet message key
  → ciphertext = AES-256-GCM(msg_key, plaintext)
  → header = { Alice_IK_pub, Alice_EK_pub, ratchet_pub, n }

                                    ──→  Store ciphertext (BYTEA)
                                         pg_notify → deliver to Bob's WebSocket
                                         Server sees: encrypted blob + header

[Bob receives]
                                    ←──  Deliver ciphertext + X3DH header

Reconstruct X3DH:
  dh1 = x25519(Bob_SPK_priv, Alice_IK_pub)
  dh2 = x25519(Bob_IK_priv, Alice_EK_pub)
  dh3 = x25519(Bob_SPK_priv, Alice_EK_pub)
  dh4 = x25519(Bob_OTPK_priv, Alice_EK_pub)
  shared_secret = HKDF(dh1‖dh2‖dh3‖dh4)   ← same as Alice's

Init Double Ratchet, decrypt ciphertext
  plaintext = AES-256-GCM-Decrypt(msg_key, ciphertext)
```

At no point does the server compute or observe:
- Any DH private key
- Any DH output
- The shared secret
- Any ratchet chain key or message key
- The plaintext

---

## Why Even a Compromised Server Cannot Decrypt

**Scenario:** An attacker gains full read access to the PostgreSQL database.

They get:
- All ciphertext blobs — useless without message keys
- All public prekeys — useless for decryption (public keys cannot reverse DH)
- Password hashes (Argon2id) — not reversible in any practical timeframe
- JWT tokens (if not expired) — let them impersonate a user to fetch ciphertext, which is still ciphertext

They do not get:
- Any Ed25519 private key (stored only on devices, never sent)
- Any X25519 private key (same)
- Ratchet state (same)
- The X3DH shared secret (derived locally and never transmitted)

**Scenario:** An attacker compromises the running server process.

They additionally get:
- `TOKEN_SECRET` — can forge JWTs, impersonate users going forward
- `SERVER_PRIVATE_KEY` — can sign fake federation packets

They still cannot decrypt existing stored messages. The keys needed are on client devices, not in server memory.

**Scenario:** An attacker runs a man-in-the-middle at the network level.

They can swap prekey bundles in transit — unless clients verify the Ed25519 signature on the signed prekey. The signature ties the X25519 prekey to the device's long-term identity key. Swapping the prekey without knowing the Ed25519 private key produces an invalid signature, and the initiating client rejects it.

---

## Algorithms and Libraries Used

| Purpose | Algorithm | Rust crate |
|---------|-----------|------------|
| Identity signing | Ed25519 | `ed25519-dalek` |
| DH key agreement | X25519 | `x25519-dalek` |
| Key derivation | HKDF-SHA256 | `ring` |
| Chain key advance | HMAC-SHA256 | `ring` |
| Message encryption | AES-256-GCM | `aes-gcm` |
| Password hashing | Argon2id | `argon2` |
| Session auth | HS256 JWT | `jsonwebtoken` |

---

## The Hard Invariants (Enforced in Code)

From [`CLAUDE.md`](CLAUDE.md):

> **Never add a decrypt endpoint.** The server stores only ciphertext.

> **Never log** ciphertext, encryption keys, tokens, or private key material.

> `sender_device_id` is `NULL` for federated messages — the server explicitly cannot attribute plaintext to a sender it relayed for.

The architecture is designed so that adding decryption capability would require client-side changes (uploading private keys), not server-side changes. There is no server-side code path to decrypt — the keys do not exist there.

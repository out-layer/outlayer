# Best Practices: OutLayer + NEAR Integration

This guide covers patterns for building applications on NEAR OutLayer, based on the near.email production implementation.

## Table of Contents
1. [WASI: Identifying the Caller Account](#1-wasi-identifying-the-caller-account)
2. [Frontend: Wallet Selector Integration](#2-frontend-wallet-selector-integration)
3. [Payment Keys for Better UX](#3-payment-keys-for-better-ux)
4. [NEP-413 Sign Message for Authentication](#4-nep-413-sign-message-for-authentication)

---

## 1. WASI: Identifying the Caller Account

OutLayer provides the signer's NEAR account ID via the `outlayer` SDK. When a user calls your WASI module through a blockchain transaction, `env::signer_account_id()` returns their account.

### Rust WASI Code

```rust
use outlayer::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the account that signed the transaction
    let signer = env::signer_account_id()
        .ok_or("No signer - must be called via NEAR transaction")?;

    println!("Called by: {}", signer);

    // Use signer for access control, data isolation, etc.
    let user_data = load_user_data(&signer)?;

    Ok(())
}
```

### Key Points
- `env::signer_account_id()` returns `Option<String>`
- Returns `None` when called via HTTPS API without payment key
- Returns the NEAR account ID (e.g., `alice.near`) when called via blockchain transaction
- For HTTPS API calls with Payment Key, the key owner's account is used

### Dependencies (Cargo.toml)

```toml
[dependencies]
outlayer = "0.2"  # OutLayer SDK for WASI P2
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

---

## 2. Frontend: Wallet Selector Integration

### Critical: Avoid Popup Blocking

**Problem**: Multiple consecutive wallet calls (e.g., sign + send) trigger browser popup blockers with error:
```
Popup window blocked. Please allow popups for this site.
```

**Solution**: Only make ONE wallet call per user action. Let the user initiate each action.

### Setup Wallet Selector

```typescript
import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupModal } from '@near-wallet-selector/modal-ui';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';
import { setupHereWallet } from '@near-wallet-selector/here-wallet';
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet';
import type { WalletSelector } from '@near-wallet-selector/core';
import { actionCreators } from '@near-js/transactions';

const NETWORK_ID = process.env.NEXT_PUBLIC_NETWORK_ID || 'mainnet';
const OUTLAYER_CONTRACT = NETWORK_ID === 'testnet'
  ? 'outlayer.testnet'
  : 'outlayer.near';

let selector: WalletSelector | null = null;
let modal: ReturnType<typeof setupModal> | null = null;

export async function initWalletSelector(): Promise<WalletSelector> {
  if (selector) return selector;

  selector = await setupWalletSelector({
    network: NETWORK_ID as 'mainnet' | 'testnet',
    modules: [
      setupMyNearWallet(),
      setupHereWallet(),
      setupMeteorWallet(),
    ],
  });

  // IMPORTANT: Omit contractId to prevent wallets from creating
  // a function call access key during sign-in (saves gas)
  modal = setupModal(selector, {});

  return selector;
}

export function showModal() {
  modal?.show();
}
```

### Call OutLayer via Transaction

```typescript
export async function callOutLayer(
  action: string,
  params: Record<string, any>
): Promise<any> {
  if (!selector) throw new Error('Wallet not initialized');

  const wallet = await selector.wallet();
  const accounts = selector.store.getState().accounts;

  if (accounts.length === 0) throw new Error('Not connected');

  // Build input data for WASI module
  const inputData = JSON.stringify({ action, ...params });

  // IMPORTANT: Use actionCreators, not raw objects!
  const functionCallAction = actionCreators.functionCall(
    'request_execution',
    {
      source: {
        Project: {
          project_id: 'your-account.near/your-project',
          version_key: null,
        },
      },
      input_data: inputData,
      resource_limits: {
        max_instructions: 2000000000,
        max_memory_mb: 512,
        max_execution_seconds: 120,
      },
      response_format: 'Json',
    },
    BigInt('300000000000000'),      // 300 TGas
    BigInt('100000000000000000000000') // 0.1 NEAR deposit
  );

  // Single wallet call - user approves once
  const result = await wallet.signAndSendTransaction({
    receiverId: OUTLAYER_CONTRACT,
    actions: [functionCallAction],
  });

  // Parse result from transaction
  return parseTransactionResult(result);
}

function parseTransactionResult(result: any): any {
  let successValue: string | null = null;

  if (result?.receipts_outcome) {
    for (const receipt of result.receipts_outcome) {
      if (receipt?.outcome?.status?.SuccessValue) {
        successValue = receipt.outcome.status.SuccessValue;
        break;
      }
    }
  }

  if (!successValue) {
    throw new Error('No result from OutLayer execution');
  }

  const decoded = atob(successValue);
  const response = JSON.parse(decoded);

  if (!response.success) {
    throw new Error(response.error || 'Unknown error');
  }

  return response;
}
```

### UI Pattern: One Action Per Click

```tsx
// GOOD: Each button triggers exactly one wallet interaction
function EmailApp() {
  const [emails, setEmails] = useState([]);

  async function handleCheckMail() {
    // Single wallet call - user clicks button, approves transaction
    const result = await callOutLayer('get_emails', {});
    setEmails(result.inbox);
  }

  async function handleSendEmail(to: string, body: string) {
    // Single wallet call - user clicks send, approves transaction
    await callOutLayer('send_email', { to, body });
  }

  return (
    <div>
      <button onClick={handleCheckMail}>Check Mail</button>
      <button onClick={() => handleSendEmail(to, body)}>Send</button>
    </div>
  );
}

// BAD: Multiple wallet calls in sequence - WILL BE BLOCKED
async function badPattern() {
  const sig1 = await wallet.signMessage({...}); // First popup
  const sig2 = await wallet.signMessage({...}); // BLOCKED!
}
```

### Dependencies (package.json)

```json
{
  "dependencies": {
    "@near-wallet-selector/core": "^8.9.0",
    "@near-wallet-selector/modal-ui": "^8.9.0",
    "@near-wallet-selector/my-near-wallet": "^8.9.0",
    "@near-wallet-selector/here-wallet": "^8.9.0",
    "@near-wallet-selector/meteor-wallet": "^8.9.0",
    "@near-js/transactions": "^1.2.0"
  }
}
```

---

## 3. Payment Keys for Better UX

Payment Keys allow users to interact with OutLayer via HTTPS API instead of blockchain transactions. Benefits:
- No transaction approval popups
- Faster response times
- Larger payload support (10MB vs ~1.5MB)
- Pre-paid execution costs

### Create Payment Keys

Users create Payment Keys at the OutLayer Dashboard. Format: `owner:nonce:secret`

Example: `alice.near:0:a1b2c3d4...`

### Frontend: Payment Key Mode

```typescript
// Payment Key configuration
let paymentKeyConfig: {
  enabled: boolean;
  key: string | null;
  owner: string | null;
} = { enabled: false, key: null, owner: null };

// Parse payment key format: owner:nonce:secret
function parsePaymentKey(key: string): { owner: string; nonce: string; secret: string } | null {
  const parts = key.split(':');
  if (parts.length < 3) return null;
  return {
    owner: parts[0],
    nonce: parts[1],
    secret: parts.slice(2).join(':')
  };
}

// Set payment key (call when user enters key)
export function setPaymentKey(key: string | null): boolean {
  if (key === null) {
    paymentKeyConfig = { enabled: false, key: null, owner: null };
    localStorage.removeItem('payment-key');
    return true;
  }

  const parsed = parsePaymentKey(key);
  if (!parsed) return false;

  paymentKeyConfig = { enabled: true, key, owner: parsed.owner };
  localStorage.setItem('payment-key', key);
  return true;
}

// Call OutLayer via HTTPS (Payment Key mode)
async function callOutLayerHttps(action: string, params: Record<string, any>): Promise<any> {
  if (!paymentKeyConfig.key) throw new Error('Payment key not configured');

  const url = `https://api.outlayer.ai/call/your-account.near/your-project`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Payment-Key': paymentKeyConfig.key,  // Auth via header
    },
    body: JSON.stringify({
      input: { action, ...params },
      resource_limits: {
        max_instructions: 2000000000,
        max_memory_mb: 512,
        max_execution_seconds: 120,
      },
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(error);
  }

  const result = await response.json();
  if (result.status === 'failed') {
    throw new Error(result.error || 'Execution failed');
  }

  return JSON.parse(result.output);
}

// Unified call function - routes to HTTPS or blockchain
export async function callOutLayer(action: string, params: Record<string, any>): Promise<any> {
  if (paymentKeyConfig.enabled) {
    return callOutLayerHttps(action, params);
  }
  return callOutLayerTransaction(action, params); // blockchain version
}
```

### UI: Payment Key Toggle

```tsx
function AccountMenu() {
  const [paymentKeyEnabled, setEnabled] = useState(false);
  const [paymentKeyInput, setInput] = useState('');

  function handleSaveKey() {
    if (setPaymentKey(paymentKeyInput)) {
      setEnabled(true);
    }
  }

  return (
    <div>
      <input
        placeholder="alice.near:0:secret..."
        value={paymentKeyInput}
        onChange={e => setInput(e.target.value)}
      />
      <button onClick={handleSaveKey}>Save Key</button>

      <label>
        <input
          type="checkbox"
          checked={paymentKeyEnabled}
          onChange={e => setEnabled(e.target.checked)}
        />
        Use Payment Key (faster, no popups)
      </label>
    </div>
  );
}
```

---

## 4. NEP-413 Sign Message for Authentication

For operations that need cryptographic proof of account ownership (without blockchain transactions), use NEP-413 message signing.

**Use cases:**
- Invite system authentication
- Off-chain access control
- Proving account ownership to external APIs

### Frontend: Sign Message with Caching

```typescript
// Signature data structure
interface SignedData {
  signature: string;   // base64 encoded
  public_key: string;  // ed25519:xxx format
  timestamp_ms: number;
  nonce: string;       // base64 encoded 32-byte nonce
}

// Cache signatures to avoid repeated popups (50 min cache, signatures expire at 60 min)
const signatureCache: Map<string, SignedData> = new Map();
const CACHE_DURATION_MS = 50 * 60 * 1000;

function getCachedSignature(accountId: string): SignedData | null {
  const cached = signatureCache.get(accountId);
  if (!cached) return null;

  const age = Date.now() - cached.timestamp_ms;
  if (age > CACHE_DURATION_MS) {
    signatureCache.delete(accountId);
    return null;
  }
  return cached;
}

// Sign message with NEP-413 (wallet popup)
async function signMessage(accountId: string): Promise<SignedData | null> {
  // Check cache first - avoid popup if we have valid signature
  const cached = getCachedSignature(accountId);
  if (cached) {
    console.log('Using cached signature');
    return cached;
  }

  const timestamp_ms = Date.now();
  // Generic message - one signature works for multiple operations
  const message = `your-app:${accountId}:${timestamp_ms}`;

  if (!selector) return null;

  const wallet = await selector.wallet();
  if (!wallet.signMessage) {
    console.error('Wallet does not support signMessage');
    return null;
  }

  // Generate 32-byte nonce (required by NEP-413)
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = Buffer.from(nonceBytes);

  try {
    const result = await wallet.signMessage({
      message,
      recipient: 'your-app',  // Your app identifier
      nonce,
    });

    if (!result) return null;

    // Handle signature format (can be string, Uint8Array, or array-like)
    let signatureBase64: string;
    const sig = result.signature as unknown;
    if (typeof sig === 'string') {
      signatureBase64 = sig;
    } else if (sig instanceof Uint8Array) {
      signatureBase64 = btoa(String.fromCharCode(...sig));
    } else if (Array.isArray(sig)) {
      signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
    } else {
      return null;
    }

    const nonceBase64 = btoa(String.fromCharCode(...nonceBytes));

    const signedData: SignedData = {
      signature: signatureBase64,
      public_key: result.publicKey,
      timestamp_ms,
      nonce: nonceBase64,
    };

    // Cache the signature for future calls
    signatureCache.set(accountId, signedData);

    return signedData;
  } catch (e) {
    console.error('Signing failed:', e);
    return null;
  }
}

// Example: Authenticated API call
async function authenticatedApiCall(accountId: string, endpoint: string, body: any) {
  const signed = await signMessage(accountId);
  if (!signed) throw new Error('Failed to sign request');

  return fetch(`https://your-api.com/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      account_id: accountId,
      signature: signed.signature,
      public_key: signed.public_key,
      timestamp_ms: signed.timestamp_ms,
      nonce: signed.nonce,
      ...body,
    }),
  });
}
```

### Backend: Verify NEP-413 Signature (Rust)

```rust
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};
use borsh::BorshSerialize;

/// NEP-413 payload structure
#[derive(BorshSerialize)]
struct Nep413Payload {
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

/// NEP-413 tag: 2^31 + 413
const NEP413_TAG: u32 = 2147484061;

/// Signed request from frontend
struct SignedRequest {
    account_id: String,
    signature: String,   // base64
    public_key: String,  // ed25519:base58...
    timestamp_ms: u64,
    nonce: String,       // base64
}

/// Verify NEP-413 signature
/// Returns Ok(()) if valid, Err(reason) otherwise
fn verify_signature(signed: &SignedRequest) -> Result<(), String> {
    // 1. Check timestamp (allow 1 hour window)
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let one_hour_ms = 60 * 60 * 1000;

    if signed.timestamp_ms > now_ms + one_hour_ms {
        return Err("Timestamp is in the future".to_string());
    }
    if now_ms > signed.timestamp_ms + one_hour_ms {
        return Err("Signature expired".to_string());
    }

    // 2. Parse public key (format: "ed25519:base58...")
    let pubkey_parts: Vec<&str> = signed.public_key.split(':').collect();
    if pubkey_parts.len() != 2 || pubkey_parts[0] != "ed25519" {
        return Err("Invalid public key format".to_string());
    }

    let pubkey_bytes = bs58::decode(pubkey_parts[1])
        .into_vec()
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    // 3. Decode signature and nonce (base64)
    let sig_bytes = base64::decode(&signed.signature)
        .map_err(|e| format!("Failed to decode signature: {}", e))?;

    let nonce_bytes = base64::decode(&signed.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

    let nonce_array: [u8; 32] = nonce_bytes.try_into()
        .map_err(|_| "Invalid nonce length")?;

    // 4. Reconstruct the message (must match frontend)
    let message = format!(
        "your-app:{}:{}",
        signed.account_id, signed.timestamp_ms
    );

    // 5. Build NEP-413 payload
    let payload = Nep413Payload {
        message,
        nonce: nonce_array,
        recipient: "your-app".to_string(),
        callback_url: None,
    };

    // 6. Serialize with Borsh
    let payload_bytes = borsh::to_vec(&payload)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    // 7. Build final hash: SHA256(NEP413_TAG || Borsh(payload))
    let mut to_hash = Vec::with_capacity(4 + payload_bytes.len());
    to_hash.extend_from_slice(&NEP413_TAG.to_le_bytes());
    to_hash.extend_from_slice(&payload_bytes);
    let hash = Sha256::digest(&to_hash);

    // 8. Verify signature
    let verifying_key = VerifyingKey::from_bytes(
        &pubkey_bytes.try_into().map_err(|_| "Invalid key length")?
    ).map_err(|e| format!("Invalid public key: {}", e))?;

    let signature = Signature::from_bytes(
        &sig_bytes.try_into().map_err(|_| "Invalid signature length")?
    );

    verifying_key
        .verify(&hash, &signature)
        .map_err(|_| "Signature verification failed")?;

    Ok(())
}
```

### Backend: Verify Public Key Ownership

After verifying the signature, verify the public key belongs to the claimed account:

```rust
/// Verify public key belongs to account via FastNEAR API
async fn verify_key_ownership(
    public_key: &str,  // ed25519:base58...
    account_id: &str,
) -> Result<(), String> {
    // FastNEAR API expects key without prefix
    let key = public_key.strip_prefix("ed25519:").unwrap_or(public_key);

    // Mainnet: https://api.fastnear.com
    // Testnet: https://test.api.fastnear.com
    let fastnear_url = if account_id.ends_with(".testnet") {
        "https://test.api.fastnear.com"
    } else {
        "https://api.fastnear.com"
    };

    let url = format!("{}/v1/public_key/{}", fastnear_url, key);

    let response = reqwest::get(&url).await
        .map_err(|e| format!("FastNEAR request failed: {}", e))?;

    if response.status() == 404 {
        return Err("Public key not found on chain".to_string());
    }

    #[derive(Deserialize)]
    struct Response { account_ids: Vec<String> }

    let data: Response = response.json().await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if data.account_ids.contains(&account_id.to_string()) {
        Ok(())
    } else {
        Err(format!("Key does not belong to {}", account_id))
    }
}

/// Full verification: signature + ownership
async fn verify_request(signed: &SignedRequest) -> Result<(), String> {
    verify_signature(signed)?;
    verify_key_ownership(&signed.public_key, &signed.account_id).await?;
    Ok(())
}
```

### Dependencies (Cargo.toml for backend)

```toml
[dependencies]
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
bs58 = "0.5"
borsh = { version = "1.5", features = ["derive"] }
sha2 = "0.10"
base64 = "0.21"
reqwest = { version = "0.11", features = ["json"] }
chrono = "0.4"
serde = { version = "1.0", features = ["derive"] }
```

### Best Practices for Signature Caching

1. **Cache on frontend** - Avoid repeated wallet popups
2. **Use timestamp in message** - For replay protection
3. **Set reasonable expiry** - 50-60 minutes is good balance
4. **Generic message format** - One signature for multiple operations
5. **Clear cache on logout** - Security hygiene

```typescript
// Clear signature cache when user signs out
export async function signOut(): Promise<void> {
  signatureCache.clear();
  await wallet.signOut();
}
```

---

## Summary

| Pattern | When to Use | User Experience |
|---------|-------------|-----------------|
| Blockchain Transaction | Default, most secure | Popup per action |
| Payment Key (HTTPS) | Frequent operations | No popups, fast |
| NEP-413 Sign Message | Off-chain auth, APIs | One popup, cached |

**Key rules:**
1. One wallet call per user click (avoid popup blocking)
2. Cache signatures when possible
3. Offer Payment Keys for power users
4. Always verify public key ownership on backend

---

*Based on near.email production implementation. Last updated: 2025-01*

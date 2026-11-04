# near-email-connector

Email from a NEAR account's own address, as an OutLayer connector. An account
`alice.near` sends as `alice@near.email` and reads that mailbox; the mailbox is
sealed to a key derived inside the enclave, so the service storing it cannot
read it and neither can we.

This is also the reference example of a **public** connector: the whole source
is here, the manifest is in the artefact, and the author's one credential is a
W5 author secret rather than anything a caller supplies. Read it alongside
[docs/CONNECTORS.md](../../../docs/CONNECTORS.md).

## Operations

| `operation` | class | what it does |
|---|---|---|
| `status` | read | the caller's address, whether it can send, inbox and sent counts, that the service answers |
| `send_pubkey` | read | the key to seal a message to before `send`; constant per account, cacheable |
| `list` | read | inbox + sent, decrypted in the enclave and re-sealed to the caller's `ephemeral_pubkey`; paging via `inbox_offset`/`sent_offset`, budget via `max_output_size` |
| `read_attachment` | read | one attachment by `attachment_id`, sealed the same way |
| `send` | write | `encrypted_data` (preferred) or flat `to`/`subject`/`body`; refuses a message that carries attachments |
| `send_with_attachment` | write | the same, with `attachments` |
| `delete` | write | delete `email_id` from this account's mailbox |

`status` and `send_pubkey` need no input beyond the operation. Every read that
returns mail needs `ephemeral_pubkey`: a 33-byte compressed secp256k1 public
key, hex, whose private half only the caller has. The reply's `encrypted_data`
is ECIES to that key, base64.

## Who the caller is

The acting account comes from the platform (`signer_account_id`), never from
the body, so an agent cannot read or send as somebody else. Only a named
account of the network has an address: an implicit 64-hex account is refused by
`send`, and `status` says `can_send: false` for it.

## Sealing

* **Reading.** The mailbox is encrypted to `user_priv = master_priv +
  SHA256("near-email:v1:" ‖ account)`. The enclave derives it per call,
  decrypts, and re-seals to the caller's ephemeral key. Nothing leaves in the
  clear.
* **Sending.** Seal `{to, subject, body, attachments}` to the key
  `send_pubkey` returns and pass it as `encrypted_data`. The flat fields are
  accepted too, and the answer then carries a `warning`: on the on-chain path
  they are public chain state forever.
* Internal mail (`…@near.email` recipient) never leaves the service: it is
  sealed to the recipient's derived key and stored. External mail goes out
  through the service's relay.

## Pricing and the attachment rule

Reads are free, `send` costs, `send_with_attachment` costs more. The operation
the caller paid for is checked **after** a sealed payload is opened — until
then the attachments are ciphertext, so a cheap `send` cannot smuggle them.
An attachment whose `size` the caller left out is counted from its data here,
because that number decides inline versus separate storage.

The manifest's daily cap is on `send:external` and `send_with_attachment:external`,
a counter the coordinator derives from the recipients in the request body and
not a second operation. It fails closed: a body it cannot read counts as
external, which is what a sealed `send` always is.

Prices live on chain and are set by `./set-prices.sh` in this directory, which
checks itself against this manifest and then refreshes the coordinator. Mainnet
only — an address derives from a `.near` account, so there is nothing to price on
testnet.

## The author secret

`PROTECTED_MASTER_KEY` is the master private key every derivation starts from,
and it is the one the live service already uses: every mailbox in the database is
sealed to a key derived from it. It cannot be read out of the keystore by anyone,
including its owner, which is what the `PROTECTED_` prefix means — so this
connector has to run where that secret already is, and the manifest names that
owner and profile.

No caller sends the key and no operation returns it: key maintenance is
deliberately not for sale here, because a connector operation is callable by
anybody who pays.

`API_SECRET` is optional and is the shared secret the mailbox service checks on
writes.

## Prices

```bash
CONTRACT=outlayer.near OWNER=owner.outlayer.near ./set-prices.sh
```

Sets the on-chain price row, then tells the coordinator to re-read it. The admin
token and the coordinator URL come from the main repo's `scripts/.env`; the
priced operations are checked against this manifest before anything is sent.

## Build

```bash
./build.sh
```

Builds `wasm32-wasip2`, then refuses the artefact unless the `outlayer.manifest`
section is present, the manifest's operations are exactly the ones the code
dispatches on, the limits are well formed and `author_secrets.profile` is set.
Prints the SHA-256 to publish.

## Layout

| file | what it is |
|---|---|
| `src/main.rs` | the connector: operation dispatch, the author secret, sealing to the caller, the attachment-price rule |
| `src/crypto.rs` | the derivation and the `EC01` envelope — the near.email wire, pinned by tests |
| `src/db.rs` | the mailbox service's HTTP protocol; the host is a constant |
| `src/http_chunked.rs` | chunked writes, because `blocking_write_and_flush` caps at 4 KB |
| `src/mail.rs` | message building, the sent copy with lazy attachments, account validation |
| `src/types.rs` | the wire types |

The crypto and the protocol are the live service's, not ours to redesign; the
tests pin the derivation prefix and the envelope magic so a change to either is
a failing test rather than a mailbox nobody can read.

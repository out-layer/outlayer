# Licensing

This document is the authoritative map of which license applies to which part of
OutLayer. It exists because this repository is a monorepo whose components are not
all released under the same terms — the root `LICENSE` does **not** automatically
govern every subdirectory.

Copyright holder for all first-party code: **OutLayer, Inc.**.

## Rationale

OutLayer sells verifiable compute and custody. The value proposition depends on
third parties being able to read, build, and independently attest the code that runs
inside the TEE. Anything a customer must inspect in order to trust us, or must copy
in order to integrate with us, is released under an OSI-approved permissive license.
The competitive moat is the coordinator, the on-chain registry of approved TEE
measurements, and the operated TDX fleet — not the source of the enclave binary.

Apache-2.0 is the default rather than MIT because it carries an express patent grant
with defensive termination (§3). MIT's silence on patents is an ambiguity that works
against us in both fundraising and acquisition diligence.

## First-party components

| Component | Path / repository | License |
|---|---|---|
| NEAR contract | `contract/` | Apache-2.0 |
| Worker registration contract | `register-contract/` | Apache-2.0 |
| Vault contract | `vault-contract/` | Apache-2.0 |
| Keystore DAO contract | `keystore-dao-contract/` | Apache-2.0 |
| Worker (TEE execution) | `worker/` | Apache-2.0 |
| Keystore worker (TEE custody) | `keystore-worker/` | Apache-2.0 |
| Dashboard | `dashboard/` | Apache-2.0 |
| Monitor | `outlayer-monitor/` | Apache-2.0 |
| Deployment tooling, docs, scripts | `deploy/`, `docs/`, `docker/`, `scripts/`, `tests/` | Apache-2.0 |
| **Rust SDK** | `sdk/outlayer/` | **MIT OR Apache-2.0** |
| **WASI examples** | `wasi-examples/` | **MIT OR Apache-2.0** |
| NEAR Email | `out-layer/near-email` (submodule) | Apache-2.0 |
| TEE auth helpers | `out-layer/shared-tee-helpers` | Apache-2.0 |
| Attestation portal | `out-layer/attestation-portal` | Apache-2.0 |
| Verification tool | `out-layer/outlayer-verify` | Apache-2.0 |
| **CLI** | `out-layer/outlayer-cli` | **MIT OR Apache-2.0** |
| **TypeScript SDK** | `out-layer/sdk-js` | **MIT** |
| **API specification** | `out-layer/api-spec` | **MIT** |
| **Web starter** | `out-layer/outlayer-web-starter` | **MIT** |
| Self-hosted scheduler | `out-layer/self-hosted-scheduler` (submodule) | Apache-2.0 |
| Self-hosted TDX runbooks | `out-layer/self-hosted-tdx` (submodule) | Apache-2.0 |
| **Coordinator** | `out-layer/coordinator` (private) | **Proprietary — all rights reserved** |

The dual-licensed and MIT rows are deliberate: they are the integration surface. Any
license friction there is friction on adoption, and several are already published to
crates.io / npm under those terms, where the declaration cannot be retracted for
already-released versions.

`wasi-examples/` is dual-licensed specifically so customers can copy an example into a
proprietary product without an attribution burden they might overlook. `wasi-examples/near-email`
is the exception: it is a deployed product, not a template, so it follows the platform's
Apache-2.0.

## Submodules

Several paths are git submodules and are **not** covered by this repository's
`LICENSE`. Each is governed by the `LICENSE` in its own repository:

- `self-hosted-scheduler` → `out-layer/self-hosted-scheduler`
- `deploy/self-hosted-tdx` → `out-layer/self-hosted-tdx`
- `wasi-examples/{ai,botfather,captcha,echo,env-test,eth-proof,intents,oracle,private-dao,random,test-secrets,vrf,weather}-example`
- `wasi-examples/near-email` — Apache-2.0, not dual: it is a finished product rather than a
  template to copy from, and its cryptography makes the express patent grant worth keeping

## Third-party dependencies

See `THIRD_PARTY_LICENSES.md` for the full inventory, the license elected for each
dual-licensed dependency, and the GPL components present in published container
images.

No dependency in any first-party component is licensed under GPL-only, AGPL, or SSPL
terms. Nothing in the dependency tree obliges OutLayer to release proprietary code.

## Contributions

All contributions require a signed Contributor License Agreement — see
`CONTRIBUTING.md` and `CLA.md`. The CLA grants OutLayer, Inc. the right to
relicense contributed material, which is what preserves the ability to change any of
the above terms in the future.

## Trademarks

Neither the Apache-2.0 nor the MIT license grants any right to use the "OutLayer"
name or logo (Apache-2.0 §6 is explicit on this). Trademark, not copyright, is the
control that prevents a fork from presenting itself as OutLayer.

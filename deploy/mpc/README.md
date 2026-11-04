# NEAR MPC node on self-hosted TDX — from-zero deployment

Stand up a NEAR MPC signing node (`v1.signer-prod.testnet`, a.k.a. NEAR Chain Signatures)
on your **own bare-metal Intel TDX server**, with working on-chain TEE attestation, end
to end from an unprovisioned machine to a node that is registered and awaiting the
governance vote.

Validated on **testnet** (node account `fastnearmpc.testnet`) on a servers.com Dell R760
(2× Xeon Gold 6548Y+, Emerald Rapids). The mainnet path is the same with mainnet
accounts/contract (see [Mainnet differences](#mainnet-differences)).

> **Scope — this is node *operation*, not OutLayer custody.** Running an MPC node makes
> you a **participant** in NEAR Chain Signatures: you hold a share of the network's
> threshold key and help produce signatures for everybody's requests. That is a separate
> thing from how OutLayer's keystore obtains its own secrets. The keystore is a **client**
> of the same network — it gets its master through MPC Chain Key Derivation
> (`mpc_contract.request_app_private_key`, see `keystore-worker/src/mpc_ckd.rs` and
> [`../../VAULTS.md`](../../VAULTS.md)), and so does every per-customer vault master. That
> derivation works identically whoever the participants happen to be, so OutLayer custody
> does not depend on us running a node — and running one grants us no extra access to any
> key derived by the network.

> **Authoritative upstream:** NEAR's own guide
> [`running-an-mpc-node-in-tdx-external-guide.md`](https://github.com/near/mpc/blob/main/docs/running-an-mpc-node-in-tdx-external-guide.md)
> in `github.com/near/mpc`. This runbook is *our* concrete, gotcha-annotated walk of that
> guide on Dell/iDRAC hardware. When the two disagree, the upstream guide wins for the
> CVM-deployment specifics; this doc wins for the host/BIOS/PCCS specifics.
>
> The host layer (BIOS, TDX kernel, attestation/PCCS) is **shared** with the OutLayer
> self-hosted worker. The full BIOS table lives in
> [`../self-hosted-tdx/docs/bios.md`](../self-hosted-tdx/docs/bios.md); it is summarized
> here so this page is self-contained.

---

## 0. What you're building & prerequisites

```
 Bare-metal host (Ubuntu 24.04 + canonical/tdx kernel)
 ├─ BIOS: TME-MT + TDX + SGX enabled, 8 DIMMs/socket
 ├─ Attestation collateral:  local PCCS (:8081)  ←  Intel PCS (api.trustedservices.intel.com)
 │                           QGS (qgsd)  ·  gramine local-key-provider (:3443, SGX sealing)
 ├─ dstack-vmm (v0.5.8, :10000)  ── the CVM control plane
 └─ MPC node CVM  (nearone/mpc-node image, launched by NEAR's cvm-deployment)
        ├─ nearcore (tracks only the contract's shard)  ·  P2P 24567
        ├─ MPC peer protocol  ·  P2P :80
        └─ /public_data  ·  :8989   (signer + p2p public keys)
```

**Hardware (mandatory):**
- Intel Xeon **5th/6th gen with TDX** (Emerald/Sapphire/Granite Rapids). Verified: Xeon
  Gold 6548Y+.
- **All 8 DIMM channels populated per socket** (16 identical DIMMs on a dual-socket box).
  This is a TME/TDX memory-interleaving requirement — with fewer, `IntelSgx` stays
  read-only `Off` in the BIOS and attestation can never work. We needed a RAM refit to
  16× 32 GB = 512 GB before SGX would unlock.
- ≥ 1 TB NVMe (the node syncs one testnet shard; budget more for headroom). RAID1 mirror
  is what we ran.
- BMC/iDRAC access for BIOS config (Dell here), or equivalent vendor BIOS access.

**Accounts / keys you must have before step 8:**
- A funded NEAR account for the node (we used `fastnearmpc.testnet`) and its full-access
  key in a keychain you control.
- The MPC contract account: testnet `v1.signer-prod.testnet`.
- A free **Intel PCS API key** — get it at <https://api.portal.trustedservices.intel.com/>
  (subscribe to "Intel SGX Provisioning Certification Service"). Without it, attestation
  collateral never resolves (see step 5 — this is the single biggest gotcha).

NEAR RPC is always `rpc.testnet.fastnear.com` / `rpc.mainnet.fastnear.com` (never
`*.near.org`).

---

## 1. Confirm the silicon actually supports TDX

Before touching BIOS, confirm the CPU is TDX-capable (model name + flags). Over SSH on the
host (or from the live installer):

```bash
lscpu | grep -iE 'model name|tdx|sgx'
# CPU flags of interest: tdx_host_platform / sgx / sgx_lc.  Model must be a Xeon with TDX.
grep -ciE 'tdx|sgx' /proc/cpuinfo     # non-zero
```

If the flags are absent, TDX is either unsupported or disabled in firmware — the BIOS step
below is what enables it. (A brand-new box from the vendor will usually show nothing until
BIOS + microcode are set.)

---

## 2. BIOS: enable TME-MT, TDX, SGX (Dell iDRAC / racadm)

Full table and per-vendor notes: [`../self-hosted-tdx/docs/bios.md`](../self-hosted-tdx/docs/bios.md).
On Dell 16G we drove this over iDRAC racadm (the iDRAC password rotates — read it off the
provider portal each time):

This is a **strict two-pass** sequence — `EnableTdx`, `EnableTdxSeamldr`, `IntelSgx` are
dependent attributes that print `#` (read-only) and reject a `set` until their parent is
applied. `ProcX2Apic` / `NodeInterleave` are usually already correct from the factory (check
and skip). Each pass = set + `jobqueue create BIOS.Setup.1-1` + `serveraction powercycle`
(~5–8 min POST each). Connect with `ssh admin@<idrac-ip>` (run one racadm command per line —
no pipes inside the racadm shell).

**Pass 1 — memory encryption (unlocks TDX/SGX):**
```bash
racadm set BIOS.ProcSettings.CpuPaLimit Disabled
racadm set BIOS.SysSecurity.MemoryEncryption MultipleKeys
racadm set BIOS.SysSecurity.GlbMemIntegrity Disabled
racadm jobqueue create BIOS.Setup.1-1
racadm serveraction powercycle
```

After it applies, `EnableTdx` + `IntelSgx` become writable. **Pass 2 — TDX + SGX; order
matters:** set `EnableTdx` *before* `EnableTdxSeamldr` (Seamldr unlocks in the same session
once Tdx is staged), and `IntelSgx=On` unlocks `SgxAutoRegistrationAgent`:

```bash
racadm set BIOS.SysSecurity.EnableTdx Enabled            # BEFORE Seamldr
racadm set BIOS.SysSecurity.EnableTdxSeamldr Enabled
racadm set BIOS.SysSecurity.IntelSgx On
racadm set BIOS.SysSecurity.SgxAutoRegistrationAgent Enabled
racadm jobqueue create BIOS.Setup.1-1
racadm serveraction powercycle
```

Each `set` returns `RAC1017 ... pending state`; confirm `(Pending Value=...)` with
`racadm get BIOS.SysSecurity` before creating the job. Verify after Pass 2:

```bash
racadm get BIOS.SysSecurity
# want: MemoryEncryption=MultipleKeys, EnableTdx=Enabled, EnableTdxSeamldr=Enabled,
#       IntelSgx=On, KeySplit=1
```

**Also update BIOS + microcode** (Maintenance → System Update) so the platform TCB is
current. The on-chain attestation rejects any platform whose TCB is not `UpToDate` — and on
a self-hosted box, TCB recovery is the operator's job.

> **Do NOT factory-reset SGX again** once registered. `SgxFactoryReset On` (values are
> `On`/`Off`, not `Enabled`) forces a fresh platform registration but **changes the
> QE-ID/PPID and wipes the PCK association** — you'll have to re-do step 5. It auto-reverts
> to Off after one boot; leave it.

If `IntelSgx` won't leave read-only `Off`, the DIMM population is wrong — fix the memory
(8/socket) first.

---

## 3. OS + TDX host kernel + attestation stack

### Storage: RAID1, not RAID0

Provision the two NVMe as **RAID1** (mirror) — **not RAID0**. The node holds a TEE-sealed
**keyshare**, so a disk loss means downtime + nearcore re-sync + keyshare restore
(`backup-cli`); RAID0 doubles the failure probability for capacity you won't use. The node
tracks only the contract's shard with `gc=3`, so its footprint is tens of GB — the ~894 GB
usable from a single mirrored 960 GB pair is plenty. (RAID type does **not** affect TDX
attestation — the CVM disk is SGX-sealed regardless — so RAID0 buys no functional upside,
only a reliability downside.)

### Partition layout (UEFI)

`BootMode=Uefi`, so the boot disk needs an **EFI System Partition (ESP, FAT32)** — not just a
"bootable" flag on an ext4 partition. Layout used on the provider portal (it creates the ESP
implicitly when the volume is marked bootable, even if it only *shows* `/boot`):

| Partition | Size | FS | Mount |
|---|---|---|---|
| EFI System Partition | ~1 GB | FAT32 | `/boot/efi` (often auto/hidden in the portal) |
| `/boot` | 1 GB | ext4 | `/boot` |
| swap | 2 GB | swap | — (token only; 512 GB RAM makes swap moot — fine to omit) |
| `/` | rest (~957 GB) | ext4 | `/` |

If the portal lists `/boot` (ext4) + a bootable flag but no explicit ESP, that is normal for a
UEFI target — confirm the host actually boots after install. `/boot` at 1 GB is slightly tight
over many kernel upgrades but fine for a server; 2 GB is more comfortable if the portal allows.

### Install + host setup

Install Ubuntu 24.04 LTS (root login by SSH key on the **public IP** — that is *not* the iDRAC
OOB IP). **After a provider reinstall, re-verify BIOS via iDRAC first** (`racadm get
BIOS.SysSecurity` ⇒ MemoryEncryption/EnableTdx/EnableTdxSeamldr/IntelSgx still set) — some
reinstalls run a hardware/factory reset that can flip SGX/TDX or trigger `SgxFactoryReset`.
Then run host setup as root. We use the same script as the OutLayer node — it installs
build deps, docker, **qemu-system-x86 8.2.2+tdx**, Node, the canonical/tdx host kernel, and the
DCAP attestation stack (QGS + local PCCS):

```bash
sudo deploy/self-hosted-tdx/00-host-setup.sh
# under the hood: apt deps + docker + qemu + node, then clones github.com/canonical/tdx,
# sets TDX_SETUP_ATTESTATION=1, and runs ./setup-tdx-host.sh (TDX kernel + QGS + PCCS).
sudo reboot
```

> **QEMU version is part of the measurement** (MRTD/RTMR). NEAR pins qemu 8.2.2; ours is
> 8.2.2+tdx1.1. Because we control our **own** approved-measurements list this is fine — but
> if you ever want to reuse NEAR's *reproducible* measurements bit-for-bit, you must match
> their qemu + dstack exactly.

---

## 4. Verify TDX is live

After reboot:

```bash
sudo dmesg | grep -i tdx
# expect: "virt/tdx: module initialized", a TDX module version (e.g. v1.5), CMRs, a PAMT
#         size, and a KeyID range like [32,64).
cat /sys/module/kvm_intel/parameters/tdx          # Y  -> KVM can launch TD guests
ls -l /dev/kvm                                     # present
ls /dev/sgx_enclave /dev/sgx_provision /dev/sgx_vepc   # SGX up (key-provider sealing)
systemctl is-active qgsd pccs docker               # all active
```

> **`/dev/tdx_guest` is a GUEST-side device** — it appears *inside* a CVM (for quote
> generation), and is correctly **absent on the host**. Host readiness is
> `kvm_intel.tdx=Y` + `/dev/kvm` + the TDX module-initialized dmesg line, not `/dev/tdx_guest`.

The canonical/tdx script prints a generic "enable Intel TDX in the BIOS" tail message even
when BIOS is already correct — ignore it if `dmesg` shows `module initialized`.

---

## 5. Attestation collateral — Intel PCS key + PCK manifest push ⚠️

**This is the step that silently breaks everything if skipped.** A TDX quote is worthless
without *collateral* (PCK certs + TCB info), and the local PCCS can only serve it once it has
your platform's PCK certs cached. On a 2-socket / multi-package box, the certs do **not** get
cached automatically — you must push the platform manifest.

Symptoms when this is wrong: PCCS log `Intel PCS server returns error(401) Access denied due
to invalid subscription key`, or `404 No cache data for this platform`; the gramine
key-provider crash-loops with `AESM service returned error 44`. Note: `mpa_manage` saying
"registration OK" and `PCKIDRetrievalTool` saying "completed" are **both misleading** — the
real gate is a valid Intel PCS key + cached PCK certs.

### Get the Intel PCS API key

It is a **free, account-level** Intel subscription key (one Intel account, reusable across all
your platforms — it just authorizes fetching public PCK certs / TCB info). Three ways, easiest
first:

1. **Reuse an existing node's** (what we did) — read it off a box that already has it:
   ```bash
   ssh root@<existing-node> 'jq -r .ApiKey /opt/intel/sgx-dcap-pccs/config/default.json'
   ```
2. **From your own saved secret store.**
3. **Fresh from Intel** — <https://api.portal.trustedservices.intel.com/> → subscribe to
   "Intel SGX Provisioning Certification Service" → copy the primary key.

> It's a credential: move it host→host over **stdin**, not on a command line/args:
> ```bash
> printf '%s' "$KEY" | ssh root@<new-node> "umask 077; cat > /root/.intel-apikey"
> ```
> Don't commit it; delete the transfer file once it's in the PCCS config.

### Provision the PCCS (exactly what we ran on this node)

```bash
CFG=/opt/intel/sgx-dcap-pccs/config/default.json
APIKEY=$(cat /root/.intel-apikey)            # the key from above

# Mint a FRESH PCCS user-token — a LOCAL secret you define; PCKIDRetrievalTool must present
# the same plaintext, and the PCCS stores only its sha512. (No need to recover any old token.)
TOKEN=$(openssl rand -hex 32)
HASH=$(printf '%s' "$TOKEN" | sha512sum | awk '{print $1}')
umask 077; printf '%s' "$TOKEN" > /root/pccs-user-token   # keep — needed for future re-pushes

# Set ApiKey + UserTokenHash atomically. (A sed on the JSON is fragile — use python.)
python3 - "$CFG" "$APIKEY" "$HASH" <<'PY'
import json,sys
p,api,h = sys.argv[1:4]
d = json.load(open(p)); d["ApiKey"] = api; d["UserTokenHash"] = h
json.dump(d, open(p,'w'), indent=4)
PY
sudo systemctl restart pccs                   # fresh node only; never restart pccs under running CVMs

# Push the platform manifest to the LOCAL PCCS:
cd /tmp
PCKIDRetrievalTool -url https://localhost:8081 -user_token "$TOKEN" -use_secure_cert false
#   ⚠️ -url is the BASE ONLY — do NOT append /sgx/certification/v4/ (doubles the path → 404).
#   Success prints: "the data has been sent to cache server successfully!".
#   A warning "platform manifest is not available or current platform is not multi-package
#   platform" is HARMLESS — the PPID-based cache still fills (verify next).
```

Verify the PCK certs are cached and **record the FMSPC**:

```bash
DB=/opt/intel/sgx-dcap-pccs/pckcache.db
sqlite3 "$DB" 'select count(*) from pck_cert;'          # > 0   (we got 8)
sqlite3 "$DB" 'select distinct fmspc from fmspc_tcbs;'  # our platform -> B0C06F000000
sqlite3 "$DB" 'select count(*) from platforms;'         # 1
```

The **FMSPC** is needed for the on-chain collateral and TCB refresh. Ours is `B0C06F000000`
(it is per CPU-model — every Xeon Gold 6548Y+ box in our fleet shares it). Once `pck_cert > 0`,
restart the gramine key-provider (§6) and it comes up healthy on :3443.

Why it matters here: the gramine **local-key-provider** seals the CVM's disk key to SGX, and
SGX needs this PCCS-served collateral to attest. Once PCCS serves 200, restart the
key-provider and it comes up `Up, listening :3443` ("PRODUCTION mode, full security
enabled").

---

## 6. dstack v0.5.8 + the gramine key-provider

NEAR pins **dstack v0.5.8** for the MPC node (its measurements are what NEAR's reproducible
build expects). Build the dstack host components and download the v0.5.8 guest image. You can
reuse our build script — it defaults to 0.5.8.

**Build prerequisites NOT covered by `00-host-setup.sh`** (it installs Node but not Rust nor
these `-dev` libs — install them first or the cargo build fails midway):

```bash
sudo apt-get install -y pkg-config libssl-dev protobuf-compiler clang cmake
# Rust (as the build user, e.g. mpc):
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
```

```bash
# as an unprivileged user in the kvm+docker groups (we used `mpc`):
./10-build-dstack.sh 0.5.8
# clones meta-dstack v0.5.8 (recursive) into ~/dstack-node, build.sh hostcfg, downloads the
# v0.5.8 guest image, build.sh host -> binaries in
# ~/dstack-node/meta-dstack/build/rust-target/release/ (dstack-vmm, dstack-kms, ...),
# guest image in ~/dstack-node/meta-dstack/build/images/dstack-0.5.8/. (~15-40 min cargo build.)
```

**Prereq — the build/run user.** Create the unprivileged `mpc` user (in `kvm`+`docker` so it
can drive qemu and docker) before building dstack:

```bash
sudo useradd -m -s /bin/bash mpc && sudo usermod -aG kvm,docker,sudo mpc
```

**Run dstack-vmm as a systemd service on `127.0.0.1:10000`** with an MPC-specific `vmm.toml`
— distinct port/CID from any OutLayer vmm (which uses :11000 / cid 40000) — written into the
build dir (the vmm runs there, so `./images` + `./run` resolve):

```toml
# ~/dstack-node/meta-dstack/build/vmm.toml
address = "tcp:127.0.0.1:10000"   # the `tcp:` prefix is REQUIRED — without it, parsed as a unix path
reuse = true
image_path = "./images"
run_path = "./run/vm"

[cvm]
kms_urls = []        # MPC CVM seals via the gramine key-provider, not a dstack KMS
gateway_urls = []    # MPC node needs no dstack gateway
cid_start = 30000
cid_pool_size = 1000
max_disk_size = 1000

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [ { protocol = "tcp", from = 1, to = 20000 }, { protocol = "udp", from = 1, to = 20000 } ]

[host_api]
address = "vsock:2"
port = 10000
```

systemd unit (runs as `mpc`). **The `enable-linger` line is mandatory:** a system service with
`User=` has no login session, so `/run/user/<uid>` — which dstack-vmm needs for its
instance-discovery dir — won't exist and the vmm dies on start with
`failed to create directory /run/user/<uid>/dstack-vmm: Permission denied`.

```bash
BUILD=/home/mpc/dstack-node/meta-dstack/build
sudo cp "$BUILD"/rust-target/release/{dstack-vmm,supervisor} "$BUILD"/   # binaries beside vmm.toml
sudo loginctl enable-linger mpc                                          # MANDATORY (see above)
sudo tee /etc/systemd/system/mpc-dstack-vmm.service >/dev/null <<UNIT
[Unit]
Description=NEAR MPC dstack-vmm (self-hosted TDX node)
After=network-online.target docker.service
[Service]
Type=simple
WorkingDirectory=$BUILD
ExecStart=$BUILD/dstack-vmm -c vmm.toml
Restart=on-failure
RestartSec=5
User=mpc
Group=mpc
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl enable --now mpc-dstack-vmm

systemctl is-active mpc-dstack-vmm                              # active
ss -ltn | grep 127.0.0.1:10000                                 # LISTEN
python3 ~/dstack-node/meta-dstack/dstack/vmm/src/vmm-cli.py --url http://127.0.0.1:10000 lsvm
#   -> "No VMs found" until you deploy the CVM (step 9)
```

### Gramine local-key-provider (`127.0.0.1:3443`)

The MPC CVM seals its encrypted disk to SGX via the **gramine-sealing-key-provider** (two
docker containers: `gramine-sealing-key-provider` + `aesmd`). It is built from **dstack
v0.5.11** (the `APT_SNAPSHOT` build-arg that fixes the measurement lives in
`key-provider-build/` only as of v0.5.11) while the vmm + OS image stay on v0.5.8 — so add a
v0.5.11 worktree just for this build:

```bash
cd ~/dstack-node/meta-dstack/dstack            # the dstack repo (submodule under meta-dstack)
git fetch --tags
git worktree add ~/dstack-v0.5.11 v0.5.11
cd ~/dstack-v0.5.11/key-provider-build

# Point its QCNL at the LOCAL PCCS (the shipped default is a remote public PCCS) BEFORE building:
cat > sgx_default_qcnl.conf <<'JSON'
{ "pccs_url": "https://localhost:8081/sgx/certification/v4/", "use_secure_cert": false,
  "retry_times": 6, "retry_delay": 10, "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168, "local_cache_only": false }
JSON

# Build + start. The snapshot date is REQUIRED for the reproducible mr_enclave — do NOT change it.
APT_SNAPSHOT=20260423T000000Z ./run.sh         # = docker compose up --build -d
```

Verify the enclave measurement equals NEAR's canonical reproducible value (this is what the
contract attests — a mismatch means a non-reproducible build):

```bash
docker logs gramine-sealing-key-provider 2>&1 | grep mr_enclave | head -1
#  must equal: 6b5ed02e549a1c30aaa8e3171a045f1f449b0017353ef595e78e39c348c98d01
docker ps --filter name=aesmd --filter name=gramine-sealing-key-provider \
  --format 'table {{.Names}}\t{{.Status}}'     # both Up; key-provider listens 127.0.0.1:3443
```

> **Ordering:** the key-provider's `aesmd` needs the local PCCS to serve this platform's PCK
> cert, so do **§5 (Intel PCS key + manifest push) FIRST** — otherwise the containers
> crash-loop with `AESM service returned error 44`. The `mr_enclave` is logged at enclave load
> regardless, so you can build + verify the measurement before §5; it just won't run healthy
> until §5 is done. After §5, `docker compose restart` (or it self-heals via `restart:`).

> A **local PCCS (:8081)** plus QGS plus this key-provider is all the attestation infra the
> MPC node needs. The *same* PCCS (with your PCK certs cached) will also serve any future
> OutLayer worker CVM on this box — one attestation stack, many CVMs.

---

## 7. Host networking for nearcore (MPC-specific tuning)

These are needed by the **NEAR node** and are NOT part of the generic TDX/OutLayer host
setup:

```bash
# NEAR-recommended socket buffers — persist them:
sudo tee /etc/sysctl.d/99-nearcore.conf >/dev/null <<'EOF'
net.core.rmem_max=8388608
net.core.wmem_max=8388608
net.ipv4.tcp_rmem=4096 87380 8388608
net.ipv4.tcp_wmem=4096 16384 8388608
net.ipv4.tcp_slow_start_after_idle=0
EOF
sudo sysctl --system

# Let the non-root vmm's qemu bind low port 80 (the MPC peer protocol listens there):
sudo setcap 'cap_net_bind_service=+ep' "$(which qemu-system-x86_64)"
```

Ports the running node uses: **24567** (nearcore P2P), **80** (MPC peer protocol — needs the
setcap above), **8989** (`/public_data`), plus dstack agent ports. Keep the control-plane ports
(vmm :10000, key-provider :3443, PCCS :8081) on loopback.

**Firewall.** We apply the shared `45-firewall.sh` (ufw: default-deny incoming, allow
outgoing, SSH-first so it can't lock you out; keeps all NEAR ports — 22, 24567 tcp/udp, 80,
8079, 8989). On this node the WAN iface is `agge` (the script's `WAN_IF` is cosmetic; the rules
are interface-agnostic):

```bash
sudo apt-get install -y ufw
sudo deploy/self-hosted-tdx/45-firewall.sh          # dry-run: prints the plan
sudo deploy/self-hosted-tdx/45-firewall.sh --apply  # enable; then verify with a FRESH ssh
```

(It also opens the OutLayer gateway ports 443/9202 — unused on an MPC-only node, harmless
since nothing listens there; `ufw delete allow 443/tcp` etc. to trim.)

---

## 8. Prepare the NEAR node account

The node needs a NEAR account and, after first boot, a **function-call access key** granting
the node's signer key call rights on the MPC contract.

- Fund the node account (e.g. `fastnearmpc.testnet`) and keep its full-access key in your
  keychain.
- You do **NOT** need a staking pool. MPC participation is gated by TEE attestation +
  a governance vote, not by stake — there is no stake field anywhere in the contract's
  participant set.

The signer key to grant is **generated inside the CVM on first boot** (step 9), so you add
the access key *after* the node prints its keys. (Command in step 11.)

---

## 9. Deploy the MPC node CVM

Clone NEAR's `mpc` repo and use its CVM deployment tooling. First install the `vmm-cli.py`
python deps (the deploy driver needs them):

```bash
pip install --break-system-packages eth_keys eth_utils cryptography pyyaml requests
```

The launcher is `mpc/deployment/cvm-deployment/deploy-launcher.sh`. It takes an env file and
a `user-config.toml`:

```bash
cd <path>/mpc/deployment/cvm-deployment
AUTO_YES=1 ./deploy-launcher.sh \
  --env-file configs/<your>-testnet.env \
  --base-path <dstack-root>/dstack \
  --python-exec python3
```

**`configs/<your>-testnet.env`** (base `default.env` plus your overrides). What we set:

| Key | Value (testnet) | Notes |
|---|---|---|
| `OS_IMAGE` | `dstack-0.5.8` | must match the guest image from step 6 |
| `LAUNCHER_MANIFEST_DIGEST` | `sha256:a4c01dd9…` | from NEAR's release / guide |
| `MPC_MANIFEST_DIGEST` | `sha256:0f3e5721…` | the `nearone/mpc-node` image manifest |
| `APP_NAME` | `mpc-node-testnet` | CVM name |
| `SEALING_KEY_TYPE` | `SGX` | → selects `--local-key-provider` (our gramine provider) |
| `VMM_RPC` | `http://127.0.0.1:10000` | the dstack-vmm from step 6 |

> Pin the manifest digests to the versions in NEAR's current guide/release; the two above are
> the ones we deployed and **will go stale** as NEAR ships new node images.

**`user-config.toml`** — the node identity & nearcore init. Key sections:

```toml
[mpc_node_config]
account_id = "fastnearmpc.testnet"
# the node's advertised P2P address (public IP : nearcore P2P port):
#   e.g. <public-ip>:24567
# secret_store_key / backup keys are generated here (NOT deterministic — see below)

[mpc_node_config.near_init]
download_config = "rpc"
# optional custom nearcore config (step 10):
# download_config_url = "http://10.0.2.2:8899/config.json"
# boot_nodes = "<from the testnet template>"
```

Run it; the launcher builds the app-compose, deploys the CVM to the vmm, and the launcher
container pulls the `nearone/mpc-node` image, verifies its hash, extends RTMR3, and boots it.

Confirm it's running and read the node's freshly-generated keys:

```bash
V=<dstack-root>/dstack/vmm/src/vmm-cli.py; U=http://127.0.0.1:10000
python3 $V --url $U lsvm                       # MPC CVM present, status running
curl -s http://127.0.0.1:8989/public_data      # near_signer_public_key + near_p2p_public_key
```

> **Node keys change on every fresh-disk (re)deploy** — they are sealed-disk material, not
> deterministic. If you wipe `/data` and redeploy, you get new signer + p2p keys and must
> re-add the access key (step 11).

---

## 10. (Optional) Optimized nearcore config — smaller disk

nearcore's `config.json` lives **inside the encrypted CVM** and is frozen at first init from
`download_config`; there is no operator shell on the production image. To shrink the disk
footprint (`gc_num_epochs_to_keep=3`, `store.state_snapshot_enabled=false`), serve a patched
config from the host and point the CVM at it:

```bash
mkdir -p /opt/mpc/config-host && cd /opt/mpc/config-host
# base = canonical testnet validator config, then patch gc + snapshot:
curl -sO https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore-deploy/testnet/validator/config.json
#   edit: gc_num_epochs_to_keep=3, store.state_snapshot_enabled=false,
#         state_snapshot_compaction_enabled=false
python3 -m http.server 8899        # CVM reaches the host at http://10.0.2.2:8899/config.json
```

Set `download_config_url = "http://10.0.2.2:8899/config.json"` in `user-config.toml`
(`[mpc_node_config.near_init]`; keep `download_config = "rpc"` — the URL is only used when
`download_config` is set) **before** the deploy in step 9. Verify the CVM fetched it (the
`http.server` log shows `GET /config.json`). The server is only needed at (re)deploy time —
once `/data` is initialized the config is cached in the CVM; stop the server afterward.

Editing only gc/snapshot did **not** change the measured surface (launcher compose hash stayed
identical) — so attestation/verify are unaffected by this tuning.

---

## 11. Verify attestation, then register on-chain

**Verify the quote locally** with NEAR's `attestation-cli` (build it from the `mpc` repo):

```bash
attestation-cli <args per NEAR guide>
# Want: "Verdict: PASS" (Dstack TDX; the MPC image hash matches; a launcher compose hash;
#        an expiry ~ +7d). This is end-to-end TDX attestation on your own hardware.
```

**Add the node's signer key** to the node account, granting function-call access to the MPC
contract (run by the account owner — locally or on the box, with your keychain):

```bash
near account add-key fastnearmpc.testnet \
  grant-function-call-access \
  --allowance unlimited \
  --contract-account-id v1.signer-prod.testnet \
  --function-names '' \
  use-manually-provided-public-key <near_signer_public_key from /public_data> \
  network-config testnet sign-with-keychain send
# (if "unlimited" is rejected, drop --allowance, or grant a NEAR amount.)
# NOTE: the flag is --function-names '' (an empty list = all methods). It is NOT
# --method-names — that name is rejected by current near-cli.
```

**Then the node does the rest automatically:** once it has synced to head it submits
`submit_participant_info` (its TDX quote + TLS key) — one transaction from the node account —
and then appears in `get_tee_accounts`.

```bash
# Watch for the node to appear with its keys:
near contract call-function as-read-only v1.signer-prod.testnet \
  get_tee_accounts json-args '{}' network-config testnet now
```

A successful `submit_participant_info` looks like our testnet tx
[`2sZuU39n5xmraCK8UAXEZBLR1KM8T7aPHhFzUvwy85ve`](https://testnet.near.rocks/tx/2sZuU39n5xmraCK8UAXEZBLR1KM8T7aPHhFzUvwy85ve)
(method `submit_participant_info`, status `SuccessValue`), after which the node is listed in
`get_tee_accounts`.

**Last step — not self-serviceable:** existing `v1.signer-prod.testnet` participants must
cast a **governance vote** to admit the node into the signing cluster
(`vote_new_parameters` with the node in the participant list). This needs NEAR / other-
participant coordination. Until that vote lands, the node is registered and attested but not
yet signing.

---

## 12. Day-2 ops

Handy aliases (we put these in `/root/.bashrc` + the node user's `.bashrc`):

| Alias | What |
|---|---|
| `near_log [N]` | live MPC node logs (dstack agent, container `mpc-node`) |
| `near_log_signer [N]` | logs filtered to signing (sign/presignature/triple/ckd/participant) |
| `near_log_launcher [N]` | launcher container logs |
| `near_restart` | vmm-cli stop+start the CVM (this is the node-upgrade path — see below) |
| `near_stop` / `near_start` | vmm-cli stop or start the CVM separately (disk/state persists; for a fresh-`/data` recovery start the host http.server :8899 first — see the recovery subsection) |
| `near_config` | `cd` to the `cvm-deployment` dir |

Status checks:

```bash
curl -s http://127.0.0.1:8989/public_data                  # signer/p2p keys, node liveness
near contract call-function as-read-only v1.signer-prod.testnet \
  get_tee_accounts json-args '{}' network-config testnet now
```

Routine watcher noise you'll see and can ignore: `allowed_image_hashes_watcher: Writing
approved MPC image hashes to disk … len=N` is the node caching the on-chain
`allowed_docker_image_hashes` (N approved images) for the upgrade flow — it is not part of
registration.

**Node-upgrade flow (new nearcore/mpc release):** nearcore is bundled in the
`nearone/mpc-node` image — there is no separate nearcore update. Governance votes the new
image hash into `allowed_docker_image_hashes` (`vote_code_hash`); the node polls it; on
`near_restart` the launcher pulls the approved image, verifies the hash, extends RTMR3, and
starts it. **`/data` (synced state) persists**, nearcore migrates its DB in place, and
re-attestation is automatic. You only re-sync from zero if `/data` is wiped. Moving to a
**new host** is a separate keyshare backup/restore flow (`backup-cli`, NEAR's
`node-migration-guide.md`), not a version upgrade.

**Testnet sharding note:** testnet has 9 shards; the node tracks only the one shard holding
`v1.signer-prod.testnet` (`tracked_shards_config={Accounts:[contract]}`, set by the node at
init) — that is what bounds its disk footprint.

### Recovering from a corrupted nearcore DB (interrupted migration)

**Symptom:** mpc-node crash-loops; `near_log` shows
`Detected an existing database migration snapshot at '/data/data/migration-snapshot' …
database is corrupted`. **Cause:** an image upgrade pulled a newer nearcore that started a
DB migration, and the CVM was **stopped/started mid-migration** — leaving the snapshot, which
neard then refuses to start over.

> **There is no surgical fix** — you cannot just delete `/data/data/migration-snapshot` (which
> would otherwise be the clean fix, since the keyshare/keys live in `/data`, **not** in
> `/data/data`). The production CVM has **no shell**: no sshd in the guest image (the `…-:22`
> forward just resets), no serial getty, the guest-agent exposes only `/logs`+`/metrics`, and
> `vmm-cli` has no `exec`/`console`. The data disk is LUKS, sealed by the gramine key-provider,
> and the disk key is derived from the TDX measurements `mr_td‖rtmr0..3` — **RTMR3 includes the
> app-compose hash**, so you can't inject a recovery `pre_launch_script`/`init_script` without
> changing the key and making the existing `/data` undecryptable. It also can't be mounted from
> the host. (This same binding is *why* an mpc-node image upgrade keeps `/data`: the launcher
> swaps the image at runtime, the app-compose is unchanged.)

So the only recovery is a **full data-disk wipe + re-register**. It regenerates the node's
signer/p2p keys (sealed-disk material → they change) but **preserves app_id / RTMR3 / port
mapping / on-chain measurement-approval** (the app-compose is untouched, so re-attestation is
not needed — only the signer access key + governance vote).

```bash
VMID=<vmid from lsvm>                                   # e.g. 6d1f2bd9-…
VMM="python3 <dstack-root>/dstack/vmm/src/vmm-cli.py --url http://127.0.0.1:10000"
DISK=<vmm-data>/run/vm/$VMID/hda.img                   # the hd1/vdb DATA disk
#                                                        (rootfs is a separate read-only verity image)

# 1. Stop the CVM; confirm qemu is gone and the disk file is released.
$VMM stop $VMID
pgrep -af "qemu.*$VMID"                                 # must be empty before touching the disk

# 2. Recreate the data disk EMPTY at the SAME byte size (also reclaims space — dstack-prepare
#    sees an empty /dev/vdb and reformats it fresh with the derived key on next boot).
SIZE=$(stat -c %s "$DISK")
truncate -s 0 "$DISK" && truncate -s "$SIZE" "$DISK"
chown mpc:mpc "$DISK"; chmod 644 "$DISK"

# 3. A fresh /data re-fetches nearcore config from the host
#    (user-config.toml: download_config_url=http://10.0.2.2:8899/config.json).
#    Start that server BEFORE booting or init stalls. Stop it once /data has cached the config.
cd /opt/mpc/config-host && nohup python3 -m http.server 8899 --bind 0.0.0.0 >>httpd.log 2>&1 &

# 4. Start the CVM.
$VMM start $VMID
```

Watch the boot: the serial log shows `Empty disk detected at /dev/vdb → creating dstack-data
partition → Formatting encrypted disk`; the launcher pulls the mpc-node image; neard downloads
genesis; `runtime: flushing changes … changes=100000` (via `near_log`) means it is syncing.
There must be **no** migration-snapshot panic.

> **Gotcha:** do **not** `pkill -f "http.server 8899"` over SSH — the pattern matches your own
> ssh command line and kills the session. Stop it by PID, or `pkill -f "[h]ttp.server"`.

After it syncs:
1. `curl -s http://127.0.0.1:8989/public_data` → the **new** signer/p2p keys.
2. Re-add the signer access key (step 11) for the new `near_signer_public_key`.
3. The node auto-submits `submit_participant_info`; **re-request the governance vote** (keys changed).

> Because the interrupted migration was triggered by a governance-approved newer image, the
> launcher may re-pull that image on a later restart and re-run the migration. On a small/fresh
> DB it is fast — just **never stop/start the CVM while a migration is in progress**, or you
> recreate this snapshot crash.

---

## 13. New-node verification checklist

Run top-to-bottom on a fresh box; each line is a gate for the next.

- [ ] **1** — `lscpu`/`/proc/cpuinfo` show a TDX-capable Xeon.
- [ ] **2** — `racadm get BIOS.SysSecurity` ⇒ MultipleKeys / EnableTdx / EnableTdxSeamldr /
  IntelSgx=On / KeySplit=1; BIOS + microcode updated. (8 DIMMs/socket or `IntelSgx` stays Off.)
- [ ] **3–4** — after `00-host-setup.sh` + reboot: `dmesg | grep -i tdx` ⇒
  `virt/tdx: module initialized`; **`cat /sys/module/kvm_intel/parameters/tdx` ⇒ `Y`**;
  `/dev/kvm` + `/dev/sgx_enclave|provision|vepc` present; `qgsd pccs docker` active.
  (`/dev/tdx_guest` is guest-side — correctly **absent** on the host.)
- [ ] **5** — `sqlite3 /opt/intel/sgx-dcap-pccs/pckcache.db 'select count(*) from pck_cert;'`
  **> 0** (we got 8); **FMSPC recorded** (`select distinct fmspc from fmspc_tcbs;` ⇒
  `B0C06F000000`); valid Intel PCS key in the PCCS config.
- [ ] **6** — `mpc` user (kvm+docker) exists; `mpc-dstack-vmm` active on :10000 (`lsvm` ⇒
  "No VMs found"); **key-provider both containers Up**, listening :3443, `mr_enclave =
  6b5ed02e…` (matches NEAR canonical).
- [ ] **7** — `sysctl` buffers applied; qemu has `cap_net_bind_service`; **ufw active**
  (SSH + 24567/80 open; verified via a fresh SSH so you're not locked out).
- [ ] **8** — node NEAR account funded; full-access key in keychain. (No staking pool.)
- [ ] **9** — `lsvm` shows the MPC CVM running; `/public_data` returns signer + p2p keys.
- [ ] **10** — (if used) `http.server` log shows the CVM fetched the custom `config.json`.
- [ ] **11** — `attestation-cli` ⇒ **Verdict: PASS**; signer key added to the node account;
  node auto-submits `submit_participant_info`; node appears in `get_tee_accounts`.
- [ ] **12** — request the governance vote from existing participants (the only non-self-
  serviceable step).

---

## Mainnet differences

Same procedure with mainnet values: MPC contract `v1.signer` (the account the mainnet keystore
DAO and `outlayer-monitor` use), mainnet node account, mainnet RPC
`rpc.mainnet.fastnear.com`, the mainnet manifest digests from NEAR's release, and mainnet
boot nodes. Mainnet TCB/collateral hygiene matters more — keep the Intel PCS collateral for
your FMSPC refreshed (Intel updates TCB roughly monthly), or attestation expires.

## Source material

- NEAR upstream guide: `github.com/near/mpc` → `docs/running-an-mpc-node-in-tdx-external-guide.md`
- Host/BIOS detail: [`../self-hosted-tdx/docs/bios.md`](../self-hosted-tdx/docs/bios.md),
  [`../self-hosted-tdx/00-host-setup.sh`](../self-hosted-tdx/00-host-setup.sh),
  [`../self-hosted-tdx/10-build-dstack.sh`](../self-hosted-tdx/10-build-dstack.sh)
- dstack: <https://github.com/Dstack-TEE/dstack/blob/master/docs/deployment.md>
- Intel PCS API key: <https://api.portal.trustedservices.intel.com/>

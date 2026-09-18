#!/usr/bin/env python3
"""
Single-file runner for all bash e2e tests under tests/.

Why a pty wrapper: most tests delegate `outlayer`/`near` CLI calls through
`script -q /dev/null bash …` (inside a `near_tty` helper) to obtain a tty
for keychain prompts. Without a real tty (e.g. running from a background
task or piped shell) that `script` invocation dies with
`tcgetattr/ioctl: Operation not supported on socket`. `pty.spawn` here
allocates a tty for the whole test subprocess so the inner `script` works.

Reads env vars from tests/.env.tests (gitignored). Required:
    API_AUTH_TOKEN  MPC_PUBLIC_KEY  PARENT  APPROVER  NETWORK

Usage:
    ./tests/run_tests.py                          # default battery
    ./tests/run_tests.py --list                   # show groups
    ./tests/run_tests.py --group vault-e2e        # run a named group
    ./tests/run_tests.py approval_flow_e2e.sh …   # run specific tests
    ./tests/run_tests.py --all                    # every *.sh test in tests/
"""
import argparse
import os
import pty
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ENV_FILE = TESTS_DIR / ".env.tests"

REQUIRED_ENV = ["API_AUTH_TOKEN", "MPC_PUBLIC_KEY", "PARENT", "APPROVER", "NETWORK"]

# Tests that MUST pass before any PR touching the wallet-id derivation
# layer (coordinator/auth.rs, customer-recovery, keystore-worker mpc_ckd).
# A formula drift between these components silently breaks customer
# recovery — see `bearer_near_recovery_e2e` which caught the v2 fix.
#
# Use `./run_tests.py --required` (or `--group required`) to run.
REQUIRED: list[str] = [
    "api_key_signed_derive_e2e.sh",          # v2 wallet_id derivation, distinct scopes
    "bearer_vault_endpoint_parity_e2e.sh",   # cross-endpoint consistency
    "v2_policy_invariants_e2e.sh",           # validate_seed + trial policy + reverse-lookup
    "bearer_near_recovery_e2e.sh",           # offline recovery matches on-chain (caught v2 gap)
]

GROUPS: dict[str, list[str]] = {
    "required": REQUIRED,
    "vault-e2e": [
        "wallet_sign_message_roundtrip.sh",
        "api_key_signed_derive_e2e.sh",
        "bearer_vault_endpoint_parity_e2e.sh",
        "v2_policy_invariants_e2e.sh",
        "internal_policy_sync_e2e.sh",
        "approval_flow_wk_e2e.sh",
        "approval_flow_e2e.sh",
        "bearer_near_recovery_e2e.sh",
        "sovereignty_e2e.sh",
    ],
    "vault-extra": [
        "vault_e2e.sh",
        "vault_detach_test.sh",
        "vault_recovery_e2e.sh",
        "vault_backward_compat.sh",
        "vault_multi_customer_isolation.sh",
        "multi_wallet_vault_e2e.sh",
    ],
    "https-api": [
        "gasless_e2e.sh",
        "payment_checks_e2e.sh",
        "wallet_intents_e2e.sh",
    ],
    "local-infra": [
        "unit.sh",
        "integration.sh",
        "compilation.sh",
        "compilation_timeout.sh",
        "transactions.sh",
        "job_workflow.sh",
        "parallel_execution.sh",
        "parallel_ai_execution.sh",
        "verify_jobs.sh",
        "wallet_mode1_agent.sh",
        "wallet_mode2_policy.sh",
    ],
}

DEFAULT_GROUP = "vault-e2e"


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        sys.stderr.write(
            f"✗ {path} not found. Create it with required vars:\n"
            f"    {' '.join(REQUIRED_ENV)}\n"
        )
        sys.exit(2)
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        sys.stderr.write(f"✗ missing env vars in {path}: {', '.join(missing)}\n")
        sys.exit(2)
    os.environ.setdefault("APPLY", "true")


def run_one(test: str) -> tuple[int, int]:
    script = TESTS_DIR / test
    if not script.is_file():
        sys.stdout.write(f"\033[31m✗ {test} not found at {script}\033[0m\n")
        return (127, 0)
    sys.stdout.write(f"\n\033[1;35m=== {test} ===\033[0m\n")
    sys.stdout.flush()
    t0 = time.time()
    rc_raw = pty.spawn(["/bin/bash", str(script), "--apply"])
    rc = os.WEXITSTATUS(rc_raw) if os.WIFEXITED(rc_raw) else 1
    dt = int(time.time() - t0)
    mark = "\033[32m✓\033[0m" if rc == 0 else "\033[31m✗\033[0m"
    sys.stdout.write(f"\n\033[1;35m=== {test}: {mark} rc={rc} ({dt}s) ===\033[0m\n")
    sys.stdout.flush()
    return (rc, dt)


def print_summary(results: list[tuple[str, int, int]]) -> int:
    sys.stdout.write("\n\033[1;35m===== SUMMARY =====\033[0m\n")
    passed = 0
    for name, rc, dt in results:
        mark = "\033[32m✓\033[0m" if rc == 0 else "\033[31m✗\033[0m"
        sys.stdout.write(f"  {mark} {name} (rc={rc}, {dt}s)\n")
        if rc == 0:
            passed += 1
    sys.stdout.write(f"\n{passed}/{len(results)} passed\n")
    return 0 if passed == len(results) else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run bash e2e tests under pty.")
    parser.add_argument("--group", help=f"named group (default: {DEFAULT_GROUP})")
    parser.add_argument("--required", action="store_true",
                        help="shortcut for --group required (must pass before merging wallet-id changes)")
    parser.add_argument("--all", action="store_true", help="run every *.sh test in tests/")
    parser.add_argument("--list", action="store_true", help="list groups and exit")
    parser.add_argument("tests", nargs="*", help="explicit test basenames")
    args = parser.parse_args(argv[1:])

    if args.list:
        for g, items in GROUPS.items():
            print(f"\n[{g}]")
            for t in items:
                print(f"  {t}")
        return 0

    load_dotenv(ENV_FILE)

    if args.tests:
        tests = args.tests
    elif args.required:
        tests = GROUPS["required"]
    elif args.all:
        tests = sorted(p.name for p in TESTS_DIR.glob("*.sh"))
    elif args.group:
        if args.group not in GROUPS:
            sys.stderr.write(f"✗ unknown group: {args.group}. Use --list.\n")
            return 2
        tests = GROUPS[args.group]
    else:
        tests = GROUPS[DEFAULT_GROUP]

    results = [(t, *run_one(t)) for t in tests]
    return print_summary(results)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

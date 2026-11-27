"""Draws docs/images/on-chain-custody.svg, the two sides of Agent On-chain custody in
docs/ON_CHAIN_CUSTODY_DESIGN.md.

Run: python3 docs/images/on-chain-custody.py docs/images/on-chain-custody.svg
"""
import html, sys

FONT = "font-family='Helvetica, Arial, sans-serif'"
COL = {
    "door": ("#dbeafe", "#2563eb"),
    "owner": ("#ede9fe", "#7c3aed"),
    "plain": ("#f3f4f6", "#6b7280"),
    "enclave": ("#dcfce7", "#16a34a"),
    "chain": ("#fef3c7", "#d97706"),
}
W, H = 1200, 660
out = []


def text(x, y, t, size=14, anchor="middle", weight="normal", color="#111"):
    out.append(f"<text x='{x}' y='{y}' text-anchor='{anchor}' {FONT} font-size='{size}' "
               f"font-weight='{weight}' fill='{color}'>{html.escape(t)}</text>")


def zone(x, y, w, h, fill, stroke, title, side="middle"):
    out.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' fill='{fill}' stroke='{stroke}' stroke-width='2'/>")
    at = {"start": x + 18, "middle": x + w / 2, "end": x + w - 18}[side]
    text(at, y + 25, title, 15, anchor=side, weight="bold")


def box(x, y, w, h, kind, lines):
    fill, stroke = COL[kind]
    out.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.5'/>")
    step = 20
    top = y + h / 2 - (len(lines) - 1) * step / 2 + 5
    for i, line in enumerate(lines):
        text(x + w / 2, top + i * step, line, 15 if i == 0 else 14, weight="bold" if i == 0 else "normal")


def arrow(d, color="#374151", both=False, width=1.8):
    end = {"#374151": "ae", "#7c3aed": "ao", "#2563eb": "ad", "#16a34a": "ag"}[color]
    start = " marker-start='url(#as)'" if both else ""
    out.append(f"<path d='{d}' fill='none' stroke='{color}' stroke-width='{width}' marker-end='url(#{end})'{start}/>")


def label(x, y, lines, stroke="#e5e7eb", size=12):
    w = max(len(line) for line in lines) * size * 0.56 + 14
    h = len(lines) * (size + 4) + 6
    out.append(f"<rect x='{x - w / 2}' y='{y - h / 2}' width='{w}' height='{h}' rx='3' fill='#ffffff' stroke='{stroke}'/>")
    for i, line in enumerate(lines):
        text(x, y - h / 2 + (size + 4) * (i + 1) - 1, line, size, color="#374151")


def marker(name, color, start=False):
    path = "M10,0 L0,5 L10,10 z" if start else "M0,0 L10,5 L0,10 z"
    ref = 1 if start else 9
    return (f"<marker id='{name}' viewBox='0 0 10 10' refX='{ref}' refY='5' markerWidth='8' markerHeight='8' "
            f"orient='auto'><path d='{path}' fill='{color}'/></marker>")


# ── the owner, above both sides ─────────────────────────────────────────────
box(390, 20, 420, 70, "owner", ["Owner: a NEAR account", "sets the policy, approves, can leave with both keys"])

# ── two sides of equal weight ───────────────────────────────────────────────
zone(40, 125, 520, 350, "#eff6ff", "#2563eb", "Agent On-chain custody, on NEAR", "start")
zone(640, 125, 520, 350, "#f0fdf4", "#16a34a", "OutLayer: an Intel TDX enclave", "end")

box(90, 165, 420, 110, "door", ["Agent signer: key A", "made from one signature of the owner", "checks the request and signs last"])
box(90, 355, 420, 100, "chain", ["Wallet contract on NEAR", "the NEAR Intents wallet contract, holds the funds",
                                  "a keyless 0s… account (NEP-616) by default",
                                  "key = A ‖ E: executes only with both signatures"])

box(690, 165, 420, 74, "enclave", ["The owner's policy", "limits, allowlists, approvals by M of N,", "freeze, lock"])
box(690, 250, 420, 70, "enclave", ["TEE signer: key E", "signs only an operation the policy allows"])
box(690, 355, 205, 100, "enclave", ["Working account", "TEE custody:", "other chains, venues,", "relays, pays gas"])
box(905, 355, 205, 100, "enclave", ["Connectors, secrets", "web2: banks, mail,", "exchanges; their keys", "stay in the enclave"])

# ── the owner's two acts ────────────────────────────────────────────────────
arrow("M 450,90 L 450,165", "#7c3aed")
label(450, 108, ["one signature"], "#7c3aed")
arrow("M 750,90 L 750,165", "#7c3aed")
label(750, 108, ["policy, approvals, freeze"], "#7c3aed")

# ── the two signatures meet at the wallet contract ──────────────────────────
arrow("M 510,195 L 690,195")
label(600, 180, ["operation"])
arrow("M 690,265 L 510,265")
label(600, 250, ["request to check"])

arrow("M 220,275 L 220,355", "#2563eb", width=2.6)
label(220, 316, ["signature of A"], "#2563eb", 13)
arrow("M 800,320 L 800,338 L 380,338 L 380,355", "#16a34a", width=2.6)
label(600, 338, ["signature of E"], "#16a34a", 13)

arrow("M 690,420 L 510,420")
label(600, 420, ["w_execute_signed"])

# ── NEAR, under both ────────────────────────────────────────────────────────
zone(40, 510, 1120, 130, "#fffbeb", "#fcd34d", "NEAR")
box(90, 548, 420, 74, "chain", ["intents.near and the 1Click API", "the balance, swaps, withdrawals to other chains"])
box(690, 548, 200, 74, "chain", ["NEAR MPC", "reaches key E", "and never key A"])
box(910, 548, 200, 74, "chain", ["OutLayer DAO", "approves builds by hash,", "holds the exit's escrow"])
arrow("M 790,548 L 790,475")
label(925, 497, ["master secret, through the DAO", "or the owner's own vault"])
arrow("M 300,455 L 300,548")
label(300, 492, ["one promise"])
arrow("M 810,40 L 1185,40 L 1185,585 L 1110,585", "#7c3aed")
label(1010, 40, ["owner exit: both keys, no OutLayer service"], "#7c3aed")

svg = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>",
       "<defs>" + marker("ae", "#374151") + marker("as", "#374151", True) + marker("ao", "#7c3aed")
       + marker("ad", "#2563eb") + marker("ag", "#16a34a") + "</defs>",
       f"<rect x='0' y='0' width='{W}' height='{H}' fill='#ffffff'/>"] + out + ["</svg>"]
open(sys.argv[1], "w").write("\n".join(svg) + "\n")

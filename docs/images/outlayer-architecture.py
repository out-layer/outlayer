"""Draws docs/images/outlayer-architecture.svg, the architecture diagram in README.md.

Run: python3 docs/images/outlayer-architecture.py docs/images/outlayer-architecture.svg
"""
import html, sys

W, H = 1500, 690
out = []
FONT = "font-family='Helvetica, Arial, sans-serif'"

COL = {
    "door": ("#dbeafe", "#2563eb"),
    "owner": ("#ede9fe", "#7c3aed"),
    "plain": ("#f3f4f6", "#6b7280"),
    "enclave": ("#dcfce7", "#16a34a"),
    "chain": ("#fef3c7", "#d97706"),
}


def box(x, y, w, h, lines, kind, bold_first=True, size=14):
    fill, stroke = COL[kind]
    out.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.5'/>")
    lh = size + 5
    y0 = y + h / 2 - (len(lines) - 1) * lh / 2 + size * 0.35
    for i, t in enumerate(lines):
        wgt = " font-weight='bold'" if (i == 0 and bold_first) else ""
        out.append(f"<text x='{x + w / 2}' y='{y0 + i * lh:.1f}' text-anchor='middle' {FONT} font-size='{size}' fill='#111'{wgt}>{html.escape(t)}</text>")


def stack(x, y, w, h, kind, n=2, d=7):
    fill, stroke = COL[kind]
    for i in range(n, 0, -1):
        out.append(f"<rect x='{x + i * d}' y='{y + i * d}' width='{w}' height='{h}' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.2'/>")


def group(x, y, w, h, title, fill, stroke, sw=2):
    out.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='8' fill='{fill}' stroke='{stroke}' stroke-width='{sw}'/>")
    out.append(f"<text x='{x + w / 2}' y='{y + 20}' text-anchor='middle' {FONT} font-size='13' fill='#111' font-weight='bold'>{html.escape(title)}</text>")


def arrow(pts, both=False, dash=False, color="#374151", end="ae"):
    d = "M " + " L ".join(f"{x},{y}" for x, y in pts)
    extra = " marker-start='url(#as)'" if both else ""
    da = " stroke-dasharray='5,4'" if dash else ""
    out.append(f"<path d='{d}' fill='none' stroke='{color}' stroke-width='1.5' marker-end='url(#{end})'{extra}{da}/>")


def label(x, y, lines, size=12, border="#e5e7eb"):
    lh = size + 4
    w = max(len(t) for t in lines) * size * 0.56 + 10
    h = len(lines) * lh + 4
    out.append(f"<rect x='{x - w / 2:.1f}' y='{y - h / 2:.1f}' width='{w:.1f}' height='{h}' rx='3' fill='#ffffff' stroke='{border}'/>")
    y0 = y - (len(lines) - 1) * lh / 2 + size * 0.35
    for i, t in enumerate(lines):
        out.append(f"<text x='{x}' y='{y0 + i * lh:.1f}' text-anchor='middle' {FONT} font-size='{size}' fill='#374151'>{html.escape(t)}</text>")



out.append(f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>")
out.append("<defs>"
           "<marker id='ae' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='8' markerHeight='8' orient='auto'><path d='M0,0 L10,5 L0,10 z' fill='#374151'/></marker>"
           "<marker id='as' viewBox='0 0 10 10' refX='1' refY='5' markerWidth='8' markerHeight='8' orient='auto'><path d='M10,0 L0,5 L10,10 z' fill='#374151'/></marker>"
           "<marker id='ao' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='8' markerHeight='8' orient='auto'><path d='M0,0 L10,5 L0,10 z' fill='#7c3aed'/></marker>"
           "<marker id='ad' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='8' markerHeight='8' orient='auto'><path d='M0,0 L10,5 L0,10 z' fill='#2563eb'/></marker>"
           "</defs>")
out.append(f"<rect x='0' y='0' width='{W}' height='{H}' fill='#ffffff'/>")

# ---------- groups
group(500, 30, 600, 378, "Intel TDX enclaves: every build attested on chain and approved by the DAO", "#f0fdf4", "#16a34a")
group(60, 505, 1040, 160, "NEAR: the state", "#fffbeb", "#fcd34d", 1.5)

# ---------- entries, one under another
box(60, 30, 215, 76, ["Owner: a NEAR account", "sets the rules, lends secrets,", "approves, can leave"], "owner", size=13)
box(60, 126, 215, 60, ["Agent or backend", "HTTPS: API key, payment key"], "door", size=13)
box(60, 206, 215, 60, ["NEAR contract", "calls OutLayer, yield / resume"], "door", size=13)

# ---------- coordinator
box(60, 330, 370, 100, ["Coordinator", "API, auth, queue, metering", "holds no wallet keys"], "plain")

# ---------- enclaves
stack(535, 70, 530, 100, "enclave")
box(535, 70, 530, 100, ["Workers: a fleet of enclaves", "run WASI programs, each run isolated",
                        "permissionless: anyone publishes a program, anyone calls it",
                        "yours, a partner's, connectors"], "enclave")
stack(620, 300, 360, 80, "enclave")
box(620, 300, 360, 80, ["Keystores: several instances, the same keys", "derive keys, check the policy,", "sign, decrypt secrets"], "enclave")

# ---------- right column
box(1180, 85, 290, 70, ["The internet: any HTTPS API", "NEAR AI, banks, exchanges, mail"], "plain", size=13)
box(1180, 270, 290, 58, ["NEAR, EVM, Solana", "signed directly"], "plain", size=13)
box(1180, 345, 290, 74, ["NEAR Intents (intents.near)", "swaps, Bitcoin, TON", "and every other chain"], "plain", size=13)
box(1180, 530, 290, 110, ["NEAR MPC network", "CKD: confidential key derivation.",
                          "Derives the master secret, returns it", "encrypted to the enclave that asked"], "chain", size=13)

# ---------- chain state
box(90, 548, 290, 95, ["outlayer.near", "encrypted policies and secrets,", "projects, payment keys, prices"], "chain", size=13)
box(410, 548, 300, 95, ["your vault contract", "optional: gates a master secret", "of your own"], "chain", size=13)
box(740, 548, 330, 95, ["dao.outlayer.near: the keystore DAO", "approves enclave builds and contract",
                         "upgrades, gates the default master secret"], "chain", size=13)

# ---------- entries -> coordinator
arrow([(275, 68), (415, 68), (415, 330)], both=True)
label(345, 68, ["approvals, tasks"], size=11)
arrow([(275, 156), (400, 156), (400, 330)])
label(337, 156, ["wallet call or run"], size=11)

# ---------- coordinator <-> enclaves
arrow([(430, 345), (450, 345), (450, 100), (535, 100)])
label(450, 200, ["job"])
arrow([(535, 150), (485, 150), (485, 370), (430, 370)])
label(527, 262, ["on-chain requests", "to queue, results,", "attestations,", "wallet host calls"], size=11)
arrow([(430, 416), (560, 416), (560, 350), (620, 350)])
label(497, 432, ["wallet operation"])

# ---------- worker -> keystore, internet
arrow([(770, 170), (770, 300)])
label(672, 235, ["host functions ask:", "secrets, keys, VRF"], size=11)
arrow([(840, 300), (840, 185)])
label(945, 235, ["decrypted secrets, program keys,", "VRF output; wallet keys never"], size=11)
arrow([(1065, 120), (1180, 120)])
label(1325, 52, ["HTTPS calls, authorised with", "the secrets it was given"])

# ---------- keystore -> chains
arrow([(980, 325), (1140, 325), (1140, 299), (1180, 299)])
label(1055, 312, ["signatures"])
arrow([(980, 360), (1140, 360), (1140, 382), (1180, 382)])
label(1055, 374, ["signed intents"])

# ---------- enclaves -> chain state
arrow([(606, 170), (606, 458), (240, 458), (240, 548)], both=True)
label(405, 458, ["reads request events, writes the result back"], size=11)
arrow([(650, 380), (650, 484), (330, 484), (330, 548)])
label(490, 484, ["reads the policy before every signature, and the secrets"], size=11)
arrow([(700, 380), (700, 548)])
label(735, 440, ["asks for a vault's", "own master"], size=11)
arrow([(900, 380), (900, 548)])
label(945, 440, ["asks for the master secret:", "attested, approved builds only"], size=11)

# ---------- chain -> MPC
arrow([(1070, 585), (1180, 585)])
label(1125, 571, ["CKD"], size=11)
arrow([(560, 643), (560, 655), (1150, 655), (1150, 615), (1180, 615)])
label(850, 655, ["CKD request"], size=11)

# ---------- owner -> chain
arrow([(60, 68), (22, 68), (22, 615), (60, 615)], color="#7c3aed", end="ao")
label(140, 470, ["on chain: policy, freeze,", "secrets and who may use", "them, exit with the keys"], size=11, border="#7c3aed")

# ---------- calling contract -> outlayer.near
arrow([(60, 236), (42, 236), (42, 580), (90, 580)], color="#2563eb", end="ad")
label(112, 298, ["request_execution"], size=11, border="#2563eb")

out.append("</svg>")
open(sys.argv[1], "w").write("\n".join(o for o in out if o))

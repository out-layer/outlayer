"""Draws docs/images/on-chain-custody-operation.svg, one operation of Agent On-chain custody in
docs/ON_CHAIN_CUSTODY_DESIGN.md.

Run: python3 docs/images/on-chain-custody-operation.py docs/images/on-chain-custody-operation.svg
"""
import html, sys

FONT = "font-family='Helvetica, Arial, sans-serif'"
COL = {
    "door": ("#dbeafe", "#2563eb"),
    "plain": ("#f3f4f6", "#6b7280"),
    "enclave": ("#dcfce7", "#16a34a"),
    "chain": ("#fef3c7", "#d97706"),
}
# lifelines: name, x, kind
P = [
    ("Agent, key A", 130, "door"),
    ("OutLayer API", 400, "plain"),
    ("Enclave: policy, key E", 700, "enclave"),
    ("Wallet contract", 1010, "chain"),
    ("intents.near", 1270, "chain"),
]
A, C, E, W_, I = (x for _, x, _ in P)
W = 1400
ROW = 46
out = []


def text(x, y, t, size=14, anchor="middle", weight="normal", color="#111"):
    out.append(f"<text x='{x}' y='{y}' text-anchor='{anchor}' {FONT} font-size='{size}' "
               f"font-weight='{weight}' fill='{color}'>{html.escape(t)}</text>")


def head(y):
    for name, x, kind in P:
        fill, stroke = COL[kind]
        w = max(150, len(name) * 9 + 30)
        out.append(f"<rect x='{x - w / 2}' y='{y}' width='{w}' height='44' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.5'/>")
        text(x, y + 27, name, 15, weight="bold")


def msg(y, x1, x2, label, reply=False, color="#374151", width=1.5):
    dash = " stroke-dasharray='6,4'" if reply else ""
    end = {"#374151": "ae", "#2563eb": "ad", "#16a34a": "ag"}[color]
    out.append(f"<line x1='{x1}' y1='{y}' x2='{x2}' y2='{y}' stroke='{color}' stroke-width='{width}' marker-end='url(#{end})'{dash}/>")
    text((x1 + x2) / 2, y - 8, label, 13, color="#1f2937")


def self_msg(y, x, label):
    out.append(f"<path d='M {x},{y - 6} h 40 v 18 h -36' fill='none' stroke='#374151' stroke-width='1.5' marker-end='url(#ae)'/>")
    text(x + 50, y + 7, label, 13, anchor="start", color="#1f2937")


def marker(name, color):
    return (f"<marker id='{name}' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='8' markerHeight='8' orient='auto'>"
            f"<path d='M0,0 L10,5 L0,10 z' fill='{color}'/></marker>")


steps = [
    lambda y: msg(y, A, C, "an operation, signed by A"),
    lambda y: msg(y, C, E, "prepare"),
    lambda y: msg(y, E, W_, "read: an approved build, the pair, no extension"),
    lambda y: self_msg(y, E, "the owner's policy: limits, allowlists, approvals"),
    lambda y: self_msg(y, E, "build the request, sign it with E"),
    lambda y: msg(y, E, C, "the request and the signature of E", reply=True, color="#16a34a", width=2.2),
    lambda y: msg(y, C, A, "the request and the signature of E", reply=True),
    lambda y: self_msg(y, A, "is it the operation asked for? then sign, last"),
    lambda y: msg(y, A, C, "the signature of A", color="#2563eb", width=2.2),
    lambda y: msg(y, C, W_, "w_execute_signed(request, both signatures), sent by the working account"),
    lambda y: self_msg(y, W_, "both signatures, the nonce"),
    lambda y: msg(y, W_, I, "one promise"),
]
TOP = 126
BOTTOM = TOP + ROW * len(steps) + 4
H = BOTTOM + 44 + 30

svg = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>",
       "<defs>" + marker("ae", "#374151") + marker("ad", "#2563eb") + marker("ag", "#16a34a") + "</defs>",
       f"<rect x='0' y='0' width='{W}' height='{H}' fill='#ffffff'/>"]
text(W / 2, 34, "One operation: the enclave signs what the policy allows, the agent signs last", 18, weight="bold")
for _, x, _ in P:
    out.append(f"<line x1='{x}' y1='92' x2='{x}' y2='{BOTTOM}' stroke='#cbd5e1' stroke-width='1.5'/>")
head(48)
head(BOTTOM)
for i, step in enumerate(steps):
    step(TOP + ROW * i)
out.append("</svg>")
open(sys.argv[1], "w").write("\n".join(svg + out) + "\n")

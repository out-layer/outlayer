"""Draws docs/images/agent-pays.svg, the "what happens when an agent pays" sequence in README.md.

Run: python3 docs/images/agent-pays.py docs/images/agent-pays.svg
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

# lifelines: name, x, kind
P = [
    ("Agent", 130, "door"),
    ("Coordinator", 430, "plain"),
    ("Keystore (Intel TDX)", 760, "enclave"),
    ("outlayer.near", 1060, "chain"),
    ("Owner", 1290, "owner"),
]
X = {n.split(" ")[0]: x for n, x, _ in P}
A, C, K, N, O = X["Agent"], X["Coordinator"], X["Keystore"], X["outlayer.near"], X["Owner"]

W = 1420
ROW = 46
TOP = 110          # first message row
out = []


def text(x, y, t, size=14, anchor="middle", weight="normal", color="#111", italic=False):
    st = " font-style='italic'" if italic else ""
    out.append(f"<text x='{x}' y='{y}' text-anchor='{anchor}' {FONT} font-size='{size}' "
               f"font-weight='{weight}' fill='{color}'{st}>{html.escape(t)}</text>")


def head(y):
    for name, x, kind in P:
        fill, stroke = COL[kind]
        w = max(150, len(name) * 9 + 30)
        out.append(f"<rect x='{x - w / 2}' y='{y}' width='{w}' height='44' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.5'/>")
        text(x, y + 27, name, 15, weight="bold")


def msg(y, x1, x2, label, reply=False):
    dash = " stroke-dasharray='6,4'" if reply else ""
    out.append(f"<line x1='{x1}' y1='{y}' x2='{x2}' y2='{y}' stroke='#374151' stroke-width='1.5' marker-end='url(#ae)'{dash}/>")
    text((x1 + x2) / 2, y - 8, label, 13, color="#1f2937")


def self_msg(y, x, label):
    out.append(f"<path d='M {x},{y - 6} h 40 v 18 h -36' fill='none' stroke='#374151' stroke-width='1.5' marker-end='url(#ae)'/>")
    text(x + 50, y + 7, label, 13, anchor="start", color="#1f2937")


def frame(y1, y2, title):
    out.append(f"<rect x='40' y='{y1}' width='{W - 80}' height='{y2 - y1}' fill='none' stroke='#9ca3af' stroke-width='1.2' stroke-dasharray='4,3' rx='4'/>")
    out.append(f"<rect x='40' y='{y1}' width='44' height='22' fill='#f3f4f6' stroke='#9ca3af' stroke-width='1.2'/>")
    text(62, y1 + 16, "alt", 12, weight="bold", color="#374151")
    text(100, y1 + 16, title, 13, anchor="start", weight="bold", color="#374151")


def divider(y, title):
    out.append(f"<line x1='40' y1='{y}' x2='{W - 40}' y2='{y}' stroke='#9ca3af' stroke-width='1.2' stroke-dasharray='4,3'/>")
    text(100, y + 17, title, 13, anchor="start", weight="bold", color="#374151")


rows = []
y = TOP
def nxt(step=ROW):
    global y
    y += step
    return y - step

r1 = nxt(); r2 = nxt(); r3 = nxt(); r4 = nxt(ROW + 6)
f1 = nxt(30)                      # frame top, section 1 title
s1a = nxt(); s1b = nxt(ROW - 6)
d2 = nxt(30)                      # section 2 title
s2a = nxt(); s2b = nxt(); s2c = nxt(); s2d = nxt(); s2e = nxt(ROW + 6)
d3 = nxt(30)                      # section 3 title
s3a = nxt(); s3b = nxt(ROW - 10)
f_end = y
BOTTOM = f_end + 20
H = BOTTOM + 44 + 30

out.append(f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>")
out.append("<defs><marker id='ae' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='8' markerHeight='8' orient='auto'>"
           "<path d='M0,0 L10,5 L0,10 z' fill='#374151'/></marker></defs>")
out.append(f"<rect x='0' y='0' width='{W}' height='{H}' fill='#ffffff'/>")
text(W / 2, 34, "What happens when an agent pays", 18, weight="bold")

for _, x, _ in P:
    out.append(f"<line x1='{x}' y1='92' x2='{x}' y2='{BOTTOM}' stroke='#cbd5e1' stroke-width='1.5'/>")
head(48)
head(BOTTOM)

frame(f1 - 8, f_end, "[inside the policy]")
divider(d2 - 8, "[needs approval]")
divider(d3 - 8, "[outside the policy]")

msg(r1 + 20, A, C, "transfer 50 USDC to bob.near")
msg(r2 + 20, C, K, "operation + wallet id")
msg(r3 + 20, K, N, "read the encrypted policy (a free view call)")
self_msg(r4 + 18, K, "decrypt, evaluate: type, token, limits, whitelist, freeze")

msg(s1a + 20, K, C, "derive the key, sign", reply=True)
msg(s1b + 20, C, A, "tx hash", reply=True)

msg(s2a + 20, K, C, "pending approval", reply=True)
msg(s2b + 20, C, A, "pending_approval", reply=True)
msg(s2c + 20, O, C, "NEP-413 signature over this exact operation")
msg(s2d + 20, C, K, "operation + approvals")
self_msg(s2e + 18, K, "verify the approvers' signatures, then sign")

msg(s3a + 20, K, C, "refused, nothing is signed", reply=True)
msg(s3b + 20, C, A, "policy_denied", reply=True)

out.append("</svg>")
open(sys.argv[1], "w").write("\n".join(out))

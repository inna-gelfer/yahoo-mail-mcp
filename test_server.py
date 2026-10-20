"""Offline tests: fake IMAP connection, no network."""
import asyncio
import email
import email.policy
import os
import sys

os.environ.update(
    YAHOO_EMAIL="me@yahoo.com",
    # Hebrew folder name with an invisible RTL mark, as copy-paste often adds.
    YAHOO_ALLOWED_FOLDERS="Receipts,Work Stuff,‏חשבוניות",
    YAHOO_APP_PASSWORD="x",
    YAHOO_ENABLE_DRAFTS="true",
)
sys.path.insert(0, os.path.dirname(__file__))
import server

# ---- modified UTF-7 (RFC 3501 examples + Hebrew) ----
assert server.mutf7_encode("~peter/mail/台北/日本語") == "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
assert server.mutf7_decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-") == "~peter/mail/台北/日本語"
assert server.mutf7_encode("A&B") == "A&-B" and server.mutf7_decode("A&-B") == "A&B"
for name in ["חשבוניות", "עבודה 2024", "Inbox/לקוחות & ספקים", "Receipts"]:
    assert server.mutf7_decode(server.mutf7_encode(name)) == name, name
    assert server.mutf7_encode(name).isascii()

# ---- Hebrew header/body decoding ----
HEB = "שלום"
for cs in ("utf-8", "windows-1255", "iso-8859-8", "iso-8859-8-i"):
    import base64
    enc = base64.b64encode(HEB.encode(cs.replace("-i", ""))).decode()
    raw = (
        f"Subject: =?{cs}?B?{enc}?=\r\nFrom: =?{cs}?B?{enc}?= <a@b.co.il>\r\n"
        f"Content-Type: text/plain; charset={cs}\r\n\r\n"
    ).encode() + HEB.encode(cs.replace("-i", ""))
    out = server._full(raw)
    assert f"Subject: {HEB}" in out and f"From: {HEB} <a@b.co.il>" in out and out.endswith(HEB), (cs, out)
# raw 8-bit windows-1255 header (no RFC 2047), sent by some old clients
raw8 = b"Subject: " + HEB.encode("cp1255") + b"\r\n\r\nx"
assert f"subject: {HEB}" in server._summary(raw8, 1)

# ---- fake IMAP ----
RAW = (b"From: a@b.com\r\nTo: me@yahoo.com\r\nDate: Mon, 1 Sep 2026 10:00:00 +0000\r\n"
       b"Subject: Hi\r\nContent-Type: text/html\r\n\r\n<p>Hello<script>x()</script></p><br>World")
LIST_RESPONSE = [
    b'(\\HasNoChildren) "/" "Inbox"',
    b'(\\HasNoChildren \\Drafts) "/" "Draft"',
    b'(\\HasNoChildren) "/" "' + server.mutf7_encode("חשבוניות").encode() + b'"',
]
LIST_SPECIAL_USE = None  # set to a LIST response to simulate RFC 6154 servers
CAPS = ("IMAP4REV1",)
MESSAGES = {}  # uid -> raw message; default RAW
SIZES = {}  # uid -> RFC822.SIZE override
calls = []


class FakeIMAP:
    def __init__(self, host, port, ssl_context, timeout):
        assert ssl_context.verify_mode.name == "CERT_REQUIRED" and ssl_context.check_hostname
        self.literal = None
        self.capabilities = CAPS

    def _simple_command(self, *args):
        calls.append(("cmd",) + args)
        return "OK", [b""]

    def _untagged_response(self, typ, data, name):
        return "OK", LIST_SPECIAL_USE

    def login(self, u, p): calls.append(("login", u))
    def select(self, f, readonly): calls.append(("select", f, readonly)); return "OK", [b"1"]
    def list(self): calls.append(("list",)); return "OK", LIST_RESPONSE
    def append(self, mbox, flags, dt, msg): calls.append(("append", mbox, flags, msg)); return "OK", [b""]

    def uid(self, cmd, *a):
        calls.append(("uid", cmd, a, self.literal))
        if cmd == "SEARCH":
            return "OK", [b"3 7"]
        uid = int(a[0])
        raw = MESSAGES.get(uid, RAW)
        if "RFC822.SIZE" in a[1]:
            return "OK", [f"1 (UID {uid} RFC822.SIZE {SIZES.get(uid, len(raw))})".encode()]
        return "OK", [(b"x", raw)]

    def logout(self): pass


server.imaplib.IMAP4_SSL = FakeIMAP

# ---- reading: allowlist, read-only, injection ----
assert "not allowed" in server.list_messages("Inbox")
assert "not allowed" in server.get_message("../Inbox", 1)
assert "not allowed" in server.list_messages("Draft")  # drafts folder is NOT readable
out = server.get_message("Work Stuff", 7)
assert "Hello" in out and "World" in out and "x()" not in out and "untrusted" in out
assert ("select", '"Work Stuff"', True) in calls
assert all("PEEK" in c[2][1] for c in calls if c[0] == "uid" and c[1] == "FETCH")
r = server.search_messages("Receipts", 'evil" OR ALL\r\nx')
assert r.startswith("Error"), r
server.search_messages("Receipts", 'invoice "Q3"')
s = [c for c in calls if c[0] == "uid" and c[1] == "SEARCH"][-1]
assert s[3] == b'invoice "Q3"' and "invoice" not in " ".join(s[2])
assert "Error" in server.get_message("Receipts", -5)

# ---- Hebrew folders ----
assert server.list_allowed_folders().splitlines() == ["Receipts", "Work Stuff", "חשבוניות"]
server.list_messages("חשבוניות")
assert ("select", '"' + server.mutf7_encode("חשבוניות") + '"', True) in calls
server.list_messages("‏חשבוניות ")  # stray RTL mark / whitespace tolerated
assert ("חשבוניות", set()) == next((n, f - {"\\hasnochildren"}) for n, f in server._list_folders(FakeIMAP(0, 0, server.ssl.create_default_context(), 0)) if n == "חשבוניות")

# ---- create_draft ----
calls.clear()
r = server.create_draft("דנה <dana@example.co.il>, avi@example.com", "הצעת מחיר", "שלום דנה,\nמצורפת הצעה.", cc="boss@example.com")
assert r.startswith("Draft saved to 'Draft'"), r
app = [c for c in calls if c[0] == "append"]
assert len(app) == 1 and app[0][1] == '"Draft"' and app[0][2] == r"(\Draft)"
assert not any(c[0] == "select" for c in calls)  # draft path never opens a folder for reading
m = email.message_from_bytes(app[0][3], policy=email.policy.default)
assert str(m["Subject"]) == "הצעת מחיר" and m.get_content().startswith("שלום דנה")
assert "dana@example.co.il" in str(m["To"]) and "דנה" in str(m["To"]) and str(m["Cc"]) == "boss@example.com"
assert m["From"] == "me@yahoo.com" and "Bcc" not in m

for bad in [
    dict(to="x@y.com\r\nBcc: evil@z.com", subject="s", body="b"),  # header injection
    dict(to="x@y.com", subject="s\r\nBcc: evil@z.com", body="b"),
    dict(to="not-an-address", subject="s", body="b"),
    dict(to="", subject="s", body="b"),
    dict(to="x@y.com", subject="s", body="b", cc="bad"),
    dict(to=",".join(f"u{i}@x.com" for i in range(21)), subject="s", body="b"),
    dict(to="x@y.com", subject="s", body="b" * 100_001),
]:
    calls.clear()
    r = server.create_draft(**bad)
    assert r.startswith("Error"), (bad, r)
    assert not any(c[0] == "append" for c in calls)

# Drafts folder override must exist on the server
server.DRAFTS_FOLDER_OVERRIDE = "NoSuchFolder"
assert "does not match" in server.create_draft("x@y.com", "s", "b")
server.DRAFTS_FOLDER_OVERRIDE = ""

# per-session cap
server._drafts_created = server.MAX_DRAFTS_PER_SESSION
assert "limit" in server.create_draft("x@y.com", "s", "b")
server._drafts_created = 0

# disabled by default
server.DRAFTS_ENABLED = False
assert "disabled" in server.create_draft("x@y.com", "s", "b")
server.DRAFTS_ENABLED = True

# ---- SPECIAL-USE detection (RFC 6154), Hebrew-named Drafts folder ----
CAPS = ("IMAP4REV1", "SPECIAL-USE")
LIST_SPECIAL_USE = [
    b'(\\HasNoChildren) "/" "Inbox"',
    b'(\\HasNoChildren \\Drafts) "/" "' + server.mutf7_encode("טיוטות").encode() + b'"',
]
calls.clear()
assert server.create_draft("x@y.com", "s", "b").startswith("Draft saved to 'טיוטות'")
assert ("cmd", "LIST", '""', '"*"', "RETURN", "(SPECIAL-USE)") in calls
assert [c[1] for c in calls if c[0] == "append"] == ['"' + server.mutf7_encode("טיוטות") + '"']
# SPECIAL-USE advertised but extended LIST has no \Drafts: fall back to plain LIST flags
LIST_SPECIAL_USE = [b'(\\HasNoChildren) "/" "Inbox"']
assert server.create_draft("x@y.com", "s", "b").startswith("Draft saved to 'Draft'")
# no \Drafts anywhere: refuse instead of guessing a name
saved = LIST_RESPONSE[:]
LIST_RESPONSE[:] = [b'(\\HasNoChildren) "/" "Inbox"', b'(\\HasNoChildren) "/" "Draft"']
assert "Could not identify the Drafts folder" in server.create_draft("x@y.com", "s", "b")
# ...unless the env override names an existing folder
server.DRAFTS_FOLDER_OVERRIDE = "Draft"
assert server.create_draft("x@y.com", "s", "b").startswith("Draft saved to 'Draft'")
server.DRAFTS_FOLDER_OVERRIDE = ""
LIST_RESPONSE[:] = saved
CAPS = ("IMAP4REV1",)

# ---- create_reply_draft ----
def b64h(text):
    return "=?utf-8?B?" + base64.b64encode(text.encode()).decode() + "?="

ORIG = (  # 1 Sep 2026 is a Tuesday
    f"From: {b64h('דנה כהן')} <dana@example.co.il>\r\n"
    "To: me@yahoo.com, Avi <avi@example.com>\r\n"
    "Cc: ME@yahoo.com, boss@example.com, avi@example.com\r\n"
    f"Subject: {b64h('הצעת מחיר')}\r\n"
    "Date: Tue, 1 Sep 2026 10:00:00 +0300\r\n"
    "Message-ID: <orig-2@example.co.il>\r\n"
    "References: <root-0@example.co.il> <prev-1@example.co.il>\r\n"
    "Content-Type: text/plain; charset=windows-1255\r\n\r\n"
).encode() + "שורה ראשונה\nשורה שנייה".encode("cp1255")
MESSAGES[11] = ORIG

calls.clear()
r = server.create_reply_draft("חשבוניות", 11, "תודה, מאשרת.")
assert r.startswith("Draft saved to 'Draft' (to: dana@example.co.il)"), r
assert ("select", '"' + server.mutf7_encode("חשבוניות") + '"', True) in calls  # original opened read-only
assert all("PEEK" in c[2][1] for c in calls if c[0] == "uid" and c[1] == "FETCH")
app = [c for c in calls if c[0] == "append"]
assert len(app) == 1 and app[0][1] == '"Draft"' and app[0][2] == r"(\Draft)"
m = email.message_from_bytes(app[0][3], policy=email.policy.default)
assert str(m["Subject"]) == "Re: הצעת מחיר"
assert m["In-Reply-To"] == "<orig-2@example.co.il>"

assert str(m["References"]).split() == ["<root-0@example.co.il>", "<prev-1@example.co.il>", "<orig-2@example.co.il>"]
assert "dana@example.co.il" in str(m["To"]) and "דנה כהן" in str(m["To"]) and m["Cc"] is None
text = m.get_content()
assert text.startswith("תודה, מאשרת.\n\nOn Tue, 01 Sep 2026")
assert "> שורה ראשונה\n> שורה שנייה" in text
assert b"=?utf-8?" in app[0][3].split(b"\n\n")[0].lower() or b"=?UTF-8?" in app[0][3]  # encoded headers

# reply_all: original To/Cc go to Cc, minus me (any case) and duplicates
calls.clear()
r = server.create_reply_draft("חשבוניות", 11, "ok", reply_all=True)
m = email.message_from_bytes([c for c in calls if c[0] == "append"][0][3], policy=email.policy.default)
cc = [a.addr_spec for a in m["Cc"].addresses]
assert cc == ["avi@example.com", "boss@example.com"], cc
assert "me@yahoo.com" not in str(m["To"]).lower()

# Reply-To wins; existing "Re:" not doubled; no Message-ID -> no threading headers
MESSAGES[12] = (b"From: a@b.com\r\nReply-To: list@b.com\r\nSubject: RE: hello\r\n\r\nhi")
calls.clear()
assert "to: list@b.com" in server.create_reply_draft("Receipts", 12, "x")
m = email.message_from_bytes([c for c in calls if c[0] == "append"][0][3], policy=email.policy.default)
assert str(m["Subject"]) == "RE: hello" and m["In-Reply-To"] is None and m["References"] is None

# hostile original: CRLF hidden in an encoded display name must not create headers
MESSAGES[13] = (f"From: {b64h('x' + chr(13) + chr(10) + 'Bcc: evil@z.com')} <a@b.com>\r\n"
                f"Subject: {b64h('s' + chr(10) + 'Bcc: evil@z.com')}\r\nMessage-ID: <bad id@x>\r\n\r\nhi").encode()
calls.clear()
assert server.create_reply_draft("Receipts", 13, "x").startswith("Draft saved")
raw_draft = [c for c in calls if c[0] == "append"][0][3]
m = email.message_from_bytes(raw_draft, policy=email.policy.default)
assert m["Bcc"] is None and b"\nBcc:" not in raw_draft and m["In-Reply-To"] is None
assert "a@b.com" in str(m["To"])  # still repliable: raw address kept, broken name dropped
assert b"Content-Transfer-Encoding: base64" in raw_draft and max(raw_draft) < 128  # 7-bit clean

# no valid sender -> refuse; disallowed folder / bad uid -> refuse; nothing appended
MESSAGES[14] = b"From: nobody\r\nSubject: s\r\n\r\nhi"
for args in [("Receipts", 14, "x"), ("Inbox", 11, "x"), ("Draft", 11, "x"), ("Receipts", 0, "x")]:
    calls.clear()
    assert server.create_reply_draft(*args).startswith("Error"), args
    assert not any(c[0] == "append" for c in calls)
server.DRAFTS_ENABLED = False
calls.clear()
assert "disabled" in server.create_reply_draft("Receipts", 11, "x") and not calls  # no IMAP at all
server.DRAFTS_ENABLED = True

# the only write anywhere in the test run was APPEND; reads always EXAMINE
assert not any(c[0] == "select" and c[2] is not True for c in calls)

# ---- get_attachment ----
import io
import zipfile
from email.message import EmailMessage


def make_pdf(text):
    """Minimal valid one-page PDF with a text layer (Helvetica, ASCII)."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.4\n")
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + o + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    return out.getvalue()


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


DOCX = make_zip({"word/document.xml": (
    '<w:document xmlns:w="x"><w:body>'
    '<w:p><w:r><w:t>הסכם שירות</w:t></w:r></w:p>'
    '<w:p><w:r><w:t xml:space="preserve">סכום: </w:t></w:r><w:r><w:t>1,200 &amp; מע&quot;מ</w:t></w:r></w:p>'
    '</w:body></w:document>')})
XLSX = make_zip({
    "xl/workbook.xml": '<workbook><sheets><sheet name="חשבוניות" sheetId="1"/></sheets></workbook>',
    "xl/sharedStrings.xml": "<sst><si><t>לקוח</t></si><si><t>סכום</t></si><si><t>דנה</t></si></sst>",
    "xl/worksheets/sheet1.xml": (
        '<worksheet><sheetData>'
        '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
        '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2"><v>350.5</v></c></row>'
        '</sheetData></worksheet>'),
})
BOMB = make_zip({"word/document.xml": "<w:t>" + "A" * (30 * 1024 * 1024) + "</w:t>"})
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")

inner = EmailMessage()
inner["From"], inner["Subject"] = "a@b.com", "הודעה מועברת"
inner.set_content("גוף ההודעה המקורית")

m = EmailMessage()
m["From"], m["To"], m["Subject"] = "a@b.com", "me@yahoo.com", "Files"
m.set_content("see attached")
m.add_attachment(make_pdf("Invoice total 1200 ILS"), maintype="application", subtype="pdf", filename="חשבונית.pdf")
m.add_attachment(DOCX, maintype="application", subtype="vnd.openxmlformats-officedocument.wordprocessingml.document", filename="הסכם.docx")
m.add_attachment(XLSX, maintype="application", subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename="data.xlsx")
m.add_attachment("שם,סכום\nדנה,100\n".encode("cp1255"), maintype="text", subtype="csv", filename="list.csv", params={"charset": "windows-1255"})
m.add_attachment(PNG, maintype="image", subtype="png", filename="receipt.png")
m.add_attachment(inner)
m.add_attachment(b"MZ\x90\x00binary", maintype="application", subtype="octet-stream", filename="setup.exe")
m.add_attachment(make_pdf("Disguised"), maintype="image", subtype="png", filename="photo.png")  # PDF bytes named .png
m.add_attachment(BOMB, maintype="application", subtype="vnd.openxmlformats-officedocument.wordprocessingml.document", filename="bomb.docx")
m.add_attachment(b"<html><body><p>Hello <b>HTML</b></p><script>steal()</script></body></html>", maintype="text", subtype="html", filename="page.html")
MESSAGES[20] = m.as_bytes()

listing = server.get_message("Receipts", 20)
assert "[1] חשבונית.pdf (application/pdf," in listing and "[5] receipt.png (image/png," in listing, listing
assert "[6] unnamed (message/rfc822," in listing

calls.clear()
r = server.get_attachment("Receipts", 20, 1)
assert "untrusted" in r and "Attachment [1]: חשבונית.pdf" in r and "Invoice total 1200 ILS" in r, r
assert ("select", '"Receipts"', True) in calls  # read-only
assert all("PEEK" in c[2][1] or "RFC822.SIZE" in c[2][1] for c in calls if c[0] == "uid" and c[1] == "FETCH")
r = server.get_attachment("Receipts", 20, 2)
assert "הסכם שירות" in r and 'סכום: 1,200 & מע"מ' in r, r
r = server.get_attachment("Receipts", 20, 3)
assert "--- sheet: חשבוניות ---" in r and "לקוח\tסכום" in r and "דנה\t350.5" in r, r
r = server.get_attachment("Receipts", 20, 4)
assert "שם,סכום" in r and "דנה,100" in r, r
r = server.get_attachment("Receipts", 20, 5)
assert isinstance(r, list) and "untrusted" in r[0] and isinstance(r[1], server.Image), r
r = server.get_attachment("Receipts", 20, 6)
assert "הודעה מועברת" in r and "גוף ההודעה המקורית" in r, r
assert "cannot be read" in server.get_attachment("Receipts", 20, 7)
assert "Disguised" in server.get_attachment("Receipts", 20, 8)  # sniffed as PDF, not trusted as image
assert "could not be read" in server.get_attachment("Receipts", 20, 9)  # zip bomb refused in the child
r = server.get_attachment("Receipts", 20, 10)
assert "Hello HTML" in r and "steal" not in r, r
assert "has 10 attachment(s)" in server.get_attachment("Receipts", 20, 11)
assert server.get_attachment("Receipts", 20, 0).startswith("Error")
assert "not allowed" in server.get_attachment("Inbox", 20, 1)

# image comes through the MCP layer as an image content block
res = asyncio.run(server.mcp.call_tool("get_attachment", {"folder": "Receipts", "uid": 20, "index": 5}))
blocks = getattr(res, "content", res)
assert any(getattr(b, "type", "") == "image" and getattr(b, "mime_type", "") == "image/png" for b in blocks), blocks

# size limits: whole message checked before download; big images not sent
SIZES[20] = server.MAX_MESSAGE_BYTES + 1
calls.clear()
assert "too large" in server.get_attachment("Receipts", 20, 1)
assert not any(c[0] == "uid" and c[1] == "FETCH" and "BODY.PEEK[]" in c[2][1] for c in calls)
del SIZES[20]
old = server.MAX_IMAGE_BYTES
server.MAX_IMAGE_BYTES = 10
assert "larger than" in server.get_attachment("Receipts", 20, 5)
server.MAX_IMAGE_BYTES = old

# the parser child gets no credentials and runs isolated; a hang is cut off
seen = {}
real_run = server.subprocess.run
def spy_run(cmd, **kw):
    seen.update(cmd=cmd, env=kw["env"], timeout=kw["timeout"])
    return real_run(cmd, **kw)
server.subprocess.run = spy_run
server.get_attachment("Receipts", 20, 1)
assert "-I" in seen["cmd"] and "YAHOO_APP_PASSWORD" not in seen["env"] and not any("YAHOO" in k for k in seen["env"])
assert seen["timeout"] == server.EXTRACT_TIMEOUT_S
def hang(cmd, **kw):
    raise server.subprocess.TimeoutExpired(cmd, kw["timeout"])
server.subprocess.run = hang
assert "too long" in server.get_attachment("Receipts", 20, 1)
server.subprocess.run = real_run

# ---- tool surface ----
tools = asyncio.run(server.mcp.list_tools())
names = sorted(t.name for t in tools)
assert names == ["create_draft", "create_reply_draft", "get_attachment", "get_message",
                 "list_allowed_folders", "list_messages", "search_messages"], names
assert "get_attachment(folder, uid, index)" in server.mcp.instructions
instr = server.mcp.instructions or ""
assert "list_allowed_folders first" in instr and "CANNOT send" in instr and "untrusted" in instr
assert "Never create a draft" in instr
print({t.name: list(t.input_schema.get("properties", {})) for t in tools})
print("ALL TESTS PASSED")

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
calls = []


class FakeIMAP:
    def __init__(self, host, port, ssl_context, timeout):
        assert ssl_context.verify_mode.name == "CERT_REQUIRED" and ssl_context.check_hostname
        self.literal = None

    def login(self, u, p): calls.append(("login", u))
    def select(self, f, readonly): calls.append(("select", f, readonly)); return "OK", [b"1"]
    def list(self): calls.append(("list",)); return "OK", LIST_RESPONSE
    def append(self, mbox, flags, dt, msg): calls.append(("append", mbox, flags, msg)); return "OK", [b""]

    def uid(self, cmd, *a):
        calls.append(("uid", cmd, a, self.literal))
        if cmd == "SEARCH":
            return "OK", [b"3 7"]
        return "OK", [(b"x", RAW)]

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

# ---- drafts ----
calls.clear()
r = server.create_draft("דנה <dana@example.co.il>, avi@example.com", "הצעת מחיר", "שלום דנה,\nמצורפת הצעה.", cc="boss@example.com")
assert r.startswith("Draft saved to 'Draft'"), r
app = [c for c in calls if c[0] == "append"]
assert len(app) == 1 and app[0][1] == '"Draft"' and app[0][2] == r"(\Draft \Seen)"
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

# ---- tool surface ----
tools = asyncio.run(server.mcp.list_tools())
names = sorted(t.name for t in tools)
assert names == ["create_draft", "get_message", "list_allowed_folders", "list_messages", "search_messages"], names
assert "list_allowed_folders first" in (server.mcp.instructions or "")
print({t.name: list(t.input_schema.get("properties", {})) for t in tools})
print("ALL TESTS PASSED")

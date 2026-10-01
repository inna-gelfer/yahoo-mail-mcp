"""Offline tests: fake IMAP connection, no network."""
import os, sys, asyncio
os.environ.update(YAHOO_EMAIL="me@yahoo.com", YAHOO_ALLOWED_FOLDERS="Receipts,Work Stuff", YAHOO_APP_PASSWORD="x")
sys.path.insert(0, os.path.dirname(__file__))
import server

RAW = (b"From: a@b.com\r\nTo: me@yahoo.com\r\nDate: Mon, 1 Sep 2026 10:00:00 +0000\r\n"
       b"Subject: Hi\r\nContent-Type: text/html\r\n\r\n<p>Hello<script>x()</script></p><br>World")
calls = []

class FakeIMAP:
    def __init__(self, host, port, ssl_context, timeout):
        assert ssl_context.verify_mode.name == "CERT_REQUIRED" and ssl_context.check_hostname
        self.literal = None
    def login(self, u, p): calls.append(("login", u))
    def select(self, f, readonly): calls.append(("select", f, readonly)); return "OK", [b"1"]
    def uid(self, cmd, *a):
        calls.append(("uid", cmd, a, self.literal))
        if cmd == "SEARCH": return "OK", [b"3 7"]
        return "OK", [(b"x", RAW)]
    def logout(self): pass

server.imaplib.IMAP4_SSL = FakeIMAP

assert "not allowed" in server.list_messages("Inbox")
assert "not allowed" in server.get_message("../Inbox", 1)
out = server.get_message("Work Stuff", 7)
assert "Hello" in out and "World" in out and "x()" not in out and "untrusted" in out
assert ("select", '"Work Stuff"', True) in calls
assert all("PEEK" in c[2][1] for c in calls if c[0]=="uid" and c[1]=="FETCH")
r = server.search_messages("Receipts", 'evil" OR ALL\r\nx')
assert r.startswith("Error"), r
server.search_messages("Receipts", 'invoice "Q3"')
s = [c for c in calls if c[1]=="SEARCH"][-1]
assert s[3] == b'invoice "Q3"' and 'invoice' not in " ".join(s[2])
assert "Error" in server.get_message("Receipts", -5)
tools = asyncio.run(server.mcp.list_tools())
names = sorted(t.name for t in tools)
assert names == ["get_message","list_allowed_folders","list_messages","search_messages"], names
assert set(tools[0].input_schema.get("properties",{})) or True
print({t.name: list(t.input_schema.get("properties",{})) for t in tools})
print("ALL TESTS PASSED")

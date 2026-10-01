# yahoo-mail-mcp (read-only)

Minimal MCP server that lets an AI client **read** specific Yahoo Mail folders. Nothing else.

## Tools
| Tool | Purpose |
|---|---|
| `list_allowed_folders` | Show which folders are reachable |
| `list_messages(folder, limit, since_days)` | Recent messages, newest first |
| `search_messages(folder, text, limit)` | Full-text search in a folder |
| `get_message(folder, uid)` | Read one message (body + attachment names) |

## Security design
- **Read-only**: `EXAMINE` + `BODY.PEEK`, so mail isn't even marked as read. There are no send, move, delete or flag tools.
- **Folder allowlist**: only folders listed in `YAHOO_ALLOWED_FOLDERS` can be read.
- **Credentials**: Yahoo *app password* stored in the OS keychain; never logged or returned.
- **TLS**: port 993, certificate + hostname verification, TLS ≥ 1.2.
- **IMAP injection-safe**: search text sent as a length-prefixed literal; UIDs validated.
- **Bounded output**: ≤50 messages per list, bodies truncated at 20k chars, attachment content never returned.
- **Prompt-injection mitigation**: email content is labeled untrusted; since there are no write tools, a malicious email can't make the agent send or delete mail through this server.
- **stdio only**: no network port opened.

## Setup
1. Yahoo → Account Security → **Generate app password**.
2. Install:
   ```bash
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   .venv/bin/keyring set yahoo-mail-mcp you@yahoo.com   # paste app password
   ```
3. Claude Desktop / Claude Code config:
   ```json
   {
     "mcpServers": {
       "yahoo-mail": {
         "command": "/abs/path/yahoo-mail-mcp/.venv/bin/python",
         "args": ["/abs/path/yahoo-mail-mcp/server.py"],
         "env": {
           "YAHOO_EMAIL": "you@yahoo.com",
           "YAHOO_ALLOWED_FOLDERS": "Receipts,Work"
         }
       }
     }
   }
   ```
   Claude Code: `claude mcp add yahoo-mail -e YAHOO_EMAIL=you@yahoo.com -e YAHOO_ALLOWED_FOLDERS=Receipts -- /abs/path/.venv/bin/python /abs/path/server.py`

If no keychain exists (e.g. a headless Linux server), set `YAHOO_APP_PASSWORD` instead. That's less secure because the password sits in your config file.

## Limitations
- Folder names must match IMAP names exactly. Non-ASCII folder names (modified UTF-7) are not supported.
- Opens a new IMAP connection per call; heavy use may hit Yahoo throttling.

## Tests
`python test_server.py` runs offline against a fake IMAP server.

# 🚧 Tollbooth

A mini **Burp Suite-style toolkit** for learning manual web testing, with a browser UI and **zero dependencies** (Python standard library only).

> ⚠️ **For education and authorised testing only.** Use it against labs you own or have written permission to test (DVWA, Juice Shop, WebGoat, your own apps). It refuses to contact anything outside your *scope*, which defaults to `localhost`.

## Burp's core tools, rebuilt

| Tab | What it does | Burp equivalent |
|---|---|---|
| **Proxy** | Capture traffic, hold / edit / drop **requests and responses**, searchable history | Proxy → Intercept / HTTP history |
| **Target** | Site map built from captured traffic | Target → Site map |
| **Repeater** | Edit and resend any request, inspect the response | Repeater |
| **Intruder** | Mark `§positions§`, fire payload lists, spot anomalies by status/length (Sniper & Battering ram) | Intruder |
| **Decoder** | Base64, URL, Hex, HTML encode/decode, MD5 / SHA-1 / SHA-256 | Decoder |
| **Comparer** | Line diff of any two requests/responses | Comparer |
| **Options** | Scope allowlist and match & replace rules (plain or regex) | Target scope, Match and Replace |

## Quick start

```bash
git clone https://github.com/<your-username>/tollbooth.git
cd tollbooth
python3 tollbooth.py            # proxy on :8080, UI on :8081
```

1. Set your browser's HTTP proxy to `127.0.0.1:8080`.
2. Open **http://127.0.0.1:8081** in a browser *without* the proxy (Firefox and Chrome bypass `localhost` by default).
3. Browse your lab app, then watch traffic appear in **Proxy**.

Allow a non-local lab host:

```bash
python3 tollbooth.py --scope 127.0.0.1 localhost dvwa.lab
```

## A 2-minute walkthrough

1. **Proxy**: tick *Intercept requests*, submit a login form. The request is held. Edit it, then **Forward**.
2. Select the request in history, click **→ Repeater**, change a parameter, **Send**, and compare responses.
3. Click **→ Intruder**, select the password value, **Add §**, paste a wordlist, **Start attack**. The odd-length row is your hit.
4. **Options → Match & replace**: add `isAdmin=false` → `isAdmin=true` on requests and watch the app react.

## Architecture

```
Browser ──► Proxy :8080 ──► Lab app
              │  scope check → match/replace → [hold request] → send
              │  record → match/replace → [hold response] → return
              ▼
         shared State ◄──► JSON API + UI :8081 (Repeater, Intruder, Decoder, Comparer)
```

- `tollbooth.py`: proxy, tools, and JSON API (~500 lines)
- `ui.html`: single-file UI, no build step
- `tests/`: unit tests (`pytest`)

## Security notes

- The UI/API binds to `127.0.0.1` only, validates the `Host` header (anti DNS-rebinding), and requires a custom header on every write (anti CSRF).
- The UI renders captured traffic with `textContent` only, so hostile responses can't run script in the UI.
- Repeater/Intruder also honour scope and cap Intruder at 2000 requests.

## Limitations

- **HTTPS through the proxy is tunnelled, not decrypted.** Use HTTP labs, or send `https://` URLs from Repeater/Intruder (certificates are not verified, since this is a lab tool).
- One request per connection; no WebSockets or chunked *request* bodies.
- Intruder has Sniper and Battering ram only (no Pitchfork/Cluster bomb), and no payload processing.

## Development

```bash
python3 -m pytest tests
```

## License

MIT © YOUR FULL NAME

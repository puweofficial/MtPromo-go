# mtproto-go

A pure-Go MTProto library for Telegram — **no third-party Telegram libraries**, no HTTP Bot API.  
Connects directly to Telegram's data centres using the MTProto binary protocol, exactly like Pyrogram does in Python.

## Features

- MTProto v2 (AES-IGE, SHA-256 msg_key derivation)
- Authorization key generation (DH key exchange with Telegram DCs)
- Persistent session (saves auth key to disk)
- User authentication (phone + SMS code)
- Bot authentication (`auth.importBotAuthorization`)
- **File upload** with multi-part chunking (512 KB per part)
- **SendFile** — documents, photos, audio
- Plain-text message sending
- Username resolver
- Keepalive ping loop
- Pure stdlib + `golang.org/x/crypto` only

## Project structure

```
mtproto-go/
├── auth/          — DH key exchange (GenerateAuthKey)
├── client/        — Client session, RPC, API methods
│   ├── client.go  — connection, encryption, Call()
│   ├── api.go     — SendMessage, UploadFile, SendFile, GetMe, …
│   └── bot.go     — BotSignIn, GetUpdates
├── crypto/        — AES-IGE, SHA1/256, key derivation
├── transport/     — TCP abridged framing
├── types/         — TL serialization helpers
└── examples/
    ├── send_file/ — User account: sign in + send a file
    └── bot/       — Bot: poll updates, echo, send file
```

## Quick start

### 1. Get App credentials

Go to <https://my.telegram.org> → API Development Tools → create an app.  
Copy your **App ID** and **App Hash**.

### 2. Install (Go 1.21+)

```bash
go get github.com/yourusername/mtproto-go
```

### 3. Send a file (user account)

```bash
go run ./examples/send_file \
  -app-id=123456 \
  -app-hash=abcdef1234567890 \
  -phone=+380501234567 \
  -to=@someuser \
  -file=/path/to/document.pdf \
  -caption="Here is your file" \
  -type=document
```

On first run you will be prompted for the SMS code. The session is saved to
`session.json` — keep it secret!

### 4. Run a bot (no Bot API)

```bash
go run ./examples/bot \
  -app-id=123456 \
  -app-hash=abcdef1234567890 \
  -token=1234567890:AAAA... \
  -session=bot_session.json
```

### 5. Use as a library

```go
package main

import (
    "log"
    "github.com/yourusername/mtproto-go/client"
)

func main() {
    c, err := client.New(client.Config{
        AppID:       123456,
        AppHash:     "your_app_hash",
        Phone:       "+380501234567",
        SessionFile: "session.json",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close()

    // Interactive auth on first run
    if _, err := c.GetMe(); err != nil {
        c.PhoneAuthFlow()
    }

    go c.Keepalive()

    // Send a message
    c.SendMessage("@username", "Hello from mtproto-go!")

    // Send a file
    c.SendFile("@username", "/tmp/report.pdf", "Monthly report", "document")
}
```

## How it compares to Pyrogram

| Feature | Pyrogram (Python) | mtproto-go (this) |
|---|---|---|
| Protocol | MTProto v2 | MTProto v2 |
| Language | Python | Go |
| Auth key | ✅ | ✅ |
| User auth | ✅ | ✅ |
| Bot auth | ✅ | ✅ |
| File upload | ✅ multi-part | ✅ 512 KB parts |
| Send document/photo | ✅ | ✅ |
| Extra libraries | MTProto built-in | stdlib + x/crypto only |

---

## How to publish to GitHub

### First time

```bash
# 1. Create a repo on github.com (no README, no .gitignore — we have those)
# 2. Initialise locally
cd mtproto-go
git init
git add .
git commit -m "feat: initial MTProto library"

# 3. Push
git remote add origin https://github.com/yourusername/mtproto-go.git
git branch -M main
git push -u origin main
```

### Update the module path

Edit `go.mod` and replace `github.com/yourusername/mtproto-go` with your actual GitHub path:

```
module github.com/YOUR_GITHUB_USERNAME/mtproto-go
```

Then run `go mod tidy`.

### Tag a release (so others can `go get` it)

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## How others install it

```bash
go get github.com/yourusername/mtproto-go@latest
```

Or a specific version:

```bash
go get github.com/yourusername/mtproto-go@v0.1.0
```

Then in their `go.mod`:
```
require github.com/yourusername/mtproto-go v0.1.0
```

And import in code:

```go
import "github.com/yourusername/mtproto-go/client"
```

---

## Security notes

- **Never commit `session.json`** — it contains your auth key (equivalent to a password).
- The `.gitignore` already excludes `*.json` for this reason.
- The RSA public key embedded in `auth/auth.go` must match the fingerprint returned by Telegram's servers. Verify it against the [official key list](https://core.telegram.org/api/obtaining_api_id).

## License

MIT

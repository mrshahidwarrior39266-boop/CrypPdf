# CrypPDF local gateway

Requires Node 18+. No `npm install` needed (zero dependencies).

## Run
```
cd cryppdf-local
DEV_LOGIN=1 node server.js          # local testing, no Google keys needed
```
Windows PowerShell: `$env:DEV_LOGIN="1"; node server.js`
Then open **http://127.0.0.1:3000** (use this address, not a file path: browser encryption needs it).

## Google OAuth (at deployment)
```
GOOGLE_CLIENT_ID=<your web client id> node server.js
```
No key is stored in code. The frontend loads Google Identity Services only when the server reports a client ID, and the server verifies each ID token (audience, expiry, verified email) before creating a session. Add your origin to the client's authorised JavaScript origins in Google Cloud.

## Settings (environment variables)
PORT (3000), HOST (127.0.0.1), MAX_MB (25), DEV_LOGIN (1 = local test login, loopback only), GOOGLE_CLIENT_ID.

## How the gateway protects PDFs
- The browser encrypts the PDF (AES-256-GCM) before upload. The key sits in the share link after `#`, which browsers never send to servers.
- The server holds only ciphertext, in RAM, for 15 to 60 minutes. It is zero-filled on expiry, deletion, "burn after download", Delete my data, or shutdown.
- The server never writes to disk (its only file access is reading `public/index.html` at startup).
- Each owner approval allows one download.

## Limits to know
- The server can see the file name, size, requester names and timing. It cannot read the PDF.
- Anyone with the full link (including the key) who gets approved can decrypt. Send links over a channel you trust.
- RAM can be swapped to disk by your OS. For stricter setups, use encrypted swap and `ulimit -c 0` (no core dumps).
- The server listens on 127.0.0.1, so receivers must reach your PC (same network with HOST=0.0.0.0 plus https, or a tunnel). Browser encryption requires https or 127.0.0.1.

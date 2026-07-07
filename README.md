# Omerta 🔇

> *"What happens in the vault, stays in the vault."*

A self-hosted, **zero-knowledge** password & secret manager. The server is cryptographically blind to all vault contents — it stores only ciphertext it cannot read.

Built by **Le Viet Cuong** | HUST SoICT

---

## Security Model

- **AES-256-GCM** — all vault items encrypted client-side before reaching the server
- **PBKDF2** (310,000 iterations) — derives Auth Key + Encryption Key from master password
- **Merkle Blind Index** — server stores only SHA-256 leaf hashes of item names, never the names
- **RSA-OAEP** — shared vault key exchange between members
- **Recovery Code** — zero-knowledge account recovery without exposing encryption keys
- **Password History** — git-style versioning, last 10 versions per item

---

## Quick Start

### 1. Start the database
```bash
docker-compose up -d
```

### 2. Start the backend
```bash
cd backend
npm install
npm run dev
```

### 3. Start the frontend
```bash
cd frontend
npm install
npm run dev
```

- Backend: http://localhost:3000
- Frontend: http://localhost:5173
- MongoDB: localhost:27017

---

## Architecture

```
frontend/src/crypto/     ← All encryption happens here (browser only)
backend/src/services/    ← Business logic (never sees plaintext)
backend/src/entities/    ← Mongoose models (stores only ciphertext)
```

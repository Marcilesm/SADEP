# 🔐 SADEP – Secure Agent Data Exchange Protocol

**SADEP** is a secure, cryptographically-verifiable protocol that enables AI agents to safely transmit sensitive data to services over HTTP — with mutual trust, encryption, replay protection, and audit logging.

This is a prototype reference implementation written in Python, using Flask and modern cryptographic primitives.

---

## Features

End-to-end encrypted payloads (AES-256 + RSA-4096)  
Agent-signed requests (Ed25519)  
Service-signed confirmations (RSA-PSS)  
Timestamp + nonce-based replay protection  
Real HTTP transport using Flask  
Transaction-level logging for full auditability  

---

## Project Structure

```
sadep/
├── agent.py                # Agent logic (sign + encrypt)
├── service.py              # Service logic (verify + decrypt + sign)
├── generate_keys.py        # One-time RSA keypair generation
├── sadep_client.py         # Agent HTTP client
├── sadep_server.py         # Flask server (service)
├── requirements.txt
├── logs/
│   └── sadep_transaction_log.txt
└── README.md
```

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/Marcilesm/sadep.git
cd sadep
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate service RSA keypair

```bash
python generate_keys.py
```

---

## Usage

### Start the Service (Flask server)

```bash
python sadep_server.py
```

Runs on `http://localhost:5000`

---

### Run the Agent

```bash
python sadep_client.py
```

- Encrypts + signs sensitive data
- Sends to service via HTTP
- Verifies service response signature
- Prints confirmation

---

## Audit Logs

All verified transactions are logged to:

```
logs/sadep_transaction_log.txt
```

Each entry includes:
- Timestamp
- Agent fingerprint
- Message nonce
- SHA-256 hash of payload
- Verification status

---

## Cryptography Details

| Component         | Algorithm           |
|------------------|---------------------|
| Payload Encryption | AES-256-CBC         |
| Key Wrapping       | RSA-4096 + OAEP     |
| Request Signature  | Ed25519             |
| Response Signature | RSA-PSS + SHA-256   |

---

## License

Apache 2.0

---

## Status: Prototype v0.1

This is a working prototype. Not production-ready (yet) — but a strong foundation for secure agent-to-service communication.

---

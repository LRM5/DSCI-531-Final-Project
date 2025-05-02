# DSCI-531-Final-Project
Secure Decentralized Audit System

# Secure Electronic Audit System

This project implements a simplified yet secure electronic audit system for tracking access to sensitive electronic health records (EHRs). The system supports privacy, integrity, and non-repudiation using authenticated encryption, digital signatures, hash chaining, and tamper detection.

## 📦 Features

- 🔐 **Privacy**: Audit records are encrypted using AES-GCM and digitally signed using ECDSA.
- 🔍 **Query Support**: Patients can query access logs tied to their own ID.
- 🧱 **Immutability**: Entries are linked in a tamper-evident hash chain.
- 🕵️‍♂️ **Tamper Detection**: Altered metadata or hash inconsistencies are automatically detected.
- 💻 **Client/Server Architecture**: Simulated via file-based message passing—no sockets or web servers required.

---

## 📁 Project Structure

```bash
├── audit_generator.py        # Builds, encrypts, and signs audit entries
├── client_server.py          # Server/client stub for processing and verifying logs
├── encryption_utils.py       # Core crypto logic (encryption, signing, hash chaining)
├── messages/                 # Folder containing encrypted log messages
├── ledger.json               # Decrypted audit log, with tamper-evident hashes
├── keys/                     # AES and ECDSA keys for encryption and signing
├── README.md                 # You're here!

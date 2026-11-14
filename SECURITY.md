# Security Policy

At **Nullvouts**, security, privacy, and data sovereignty are our absolute highest priorities. Because this application is designed for local, offline credential management, our threat model places you—the user—as the sole custodian of your cryptographic keys and data.

---

## 🔒 Core Security Principles

* **100% Offline (Air-Gapped):** Nullvouts contains zero networking code, telemetry, analytics, or external API calls. Your data never leaves your local file system.
* **Zero-Knowledge Architecture:** There is no cloud backend, account server, or central database. We have zero access to your master key, keyfiles, or stored credentials.
* **Self-Custody Responsibility:** Because there are no servers, there is no "Password Reset" mechanism. If you lose your master key or keyfile and lack a backup, **your data cannot be recovered**.

---

## 🛠️ Cryptographic & Protection Stack

Nullvouts implements industry-standard cryptographic primitives and platform-level security measures:

* **Encryption:** Data is secured using **AES-256-GCM** (Galois/Counter Mode), providing both confidentiality and cryptographic integrity.
* **Key Derivation:** Master passwords are processed through **Scrypt** (`N_LOG2 = 19`), making brute-force and hardware acceleration attacks computationally expensive.
* **Anti-Screenshot Protection:** Integrates platform-level API protection (`WDA_EXCLUDEFROMCAPTURE`) to prevent malicious screen-scraping tools or background malware from capturing sensitive window contents.
* **Memory & Clipboard Hygiene:** Sensitive credentials stored in the clipboard are automatically cleared after a set period of inactivity to minimize memory exposure windows.

---

## 📂 Backup & User Custody Warning

Because Nullvouts operates entirely offline without cloud synchronization:
1. **You are responsible for your own backups.** We strongly recommend periodically copying your encrypted vault file to secure external media (such as an encrypted USB flash drive).
2. **Corrupted or lost files** resulting from hardware failure cannot be restored by us. Always keep offline redundancies of your critical vault files.

---

## 🛡️ Reporting a Vulnerability

If you discover a security vulnerability or cryptographic flaw within Nullvouts, we take it extremely seriously. 

* **Please do not open public GitHub issues** for security vulnerabilities.
* Instead, please report vulnerabilities directly through private communication channels (or by reaching out to the project maintainer privately). 
* Include a detailed description of the issue, steps to reproduce, and potential impact. We will review and address valid security reports promptly.

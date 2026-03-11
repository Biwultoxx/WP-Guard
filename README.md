# WP Guard

**WP Guard** is a VPS-level database integrity protection engine designed to prevent unauthorized modification of critical WordPress user data.

Unlike traditional security solutions that operate at the application or plugin level, WP Guard enforces **immutable database state at the infrastructure layer**, ensuring that even if database credentials are compromised, attacker-initiated changes can be automatically detected and reverted.

---

## 🚀 Overview

WP Guard continuously monitors WordPress user tables and automatically restores them to a trusted snapshot if unauthorized changes are detected.

This provides protection against:

- Unauthorized admin account creation
- Admin password tampering
- Privilege escalation via direct SQL access
- Database compromise via leaked `wp-config.php`
- Persistence mechanisms using user table manipulation
- Direct database access from panel tools (phpMyAdmin, DBeaver, etc.)

WP Guard operates independently from WordPress runtime and does **not rely on plugins or MySQL triggers**.

---

## 🔐 Key Features

- Immutable protection for WordPress admin accounts
- Real-time integrity monitoring (hash-based)
- Automatic rollback engine
- Snapshot-driven restore mechanism
- Systemd-isolated worker processes
- Multi-database support
- Automatic WordPress table prefix detection
- VPS-level security enforcement
- No dependency on WordPress or PHP runtime environment
- Compatible with MariaDB & MySQL

---

## 🧠 Architecture Concept

WP Guard works using the following mechanism:

1. Create a trusted snapshot of WordPress user tables
2. Generate integrity hash from snapshot
3. Run isolated monitoring worker on VPS
4. Continuously compare live database state with trusted hash
5. Automatically restore snapshot if tampering detected

This creates an **immutable enforcement layer** for critical authentication data.

---

## 📦 Requirements

- Linux VPS (Ubuntu/Debian recommended)
- systemd available
- MySQL or MariaDB
- PHP CLI installed
- mysqldump available
- Root or sudo access

---

## ⚙️ Installation (Conceptual)

1. Deploy WP Guard dashboard on DB VPS
2. Configure database provisioner credentials
3. Enable guard per WordPress database
4. Snapshot will be generated automatically
5. Background worker will start via systemd

---

## 🛡 Security Model

WP Guard assumes:

- Attackers may obtain database credentials
- Attackers may access database directly
- Attackers may modify WordPress core
- Attackers may bypass application-level protections

WP Guard protects against:

✔ Direct SQL modification of user accounts  
✔ Privilege escalation persistence  
✔ Unauthorized admin creation  
✔ Silent password reset attacks  
✔ Database tampering via leaked configs  

WP Guard does NOT protect against:

✖ Full root compromise of VPS  
✖ Kernel-level attacks  
✖ Disk-level manipulation  
✖ Snapshot tampering if attacker gains filesystem access  

---

## ⚠️ Important Notice

WP Guard enforces **data immutability**.  
Improper configuration may cause:

- User changes being automatically reverted
- WordPress admin operations being blocked
- Authentication anomalies

Use with full understanding of its enforcement model.

---

## 🎯 Intended Use Cases

- Hardened WordPress hosting environments
- High-risk public WordPress deployments
- Security research labs
- Incident response mitigation
- Malware persistence prevention
- Red-team defensive simulation

---

## 🧩 Future Roadmap

- Admin-only immutable mode
- Snapshot integrity signing
- Kernel-level guard extension
- Multi-node replication protection
- Behavioral anomaly detection
- Immutable options table protection
- Stealth guard mode

---

## 📜 License

TBD

---

## 👤 Author

Security infrastructure project for advanced WordPress hardening.

---

## ⭐ Disclaimer

This project is provided for security research and infrastructure hardening purposes.  
Improper usage may disrupt normal WordPress functionality.

Use at your own risk.

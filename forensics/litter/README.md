# Litter

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Medium
**Status:** Retired

## Overview

This Sherlock investigates a Windows 10 workstation compromised via DNS tunneling using dnscat2. The attacker established a covert command channel through DNS queries to a rogue DNS server on the same subnet, used it to execute commands, enumerate the file system, attempt to exfiltrate data via cloud storage, and ultimately stole a CSV file containing 721 PII records from the victim's Documents folder.

## Attack Chain

```
DNS tunnel established via dnscat2 (victim → 192.168.157.145:53)
  → whoami (identify user: desktop-umncbe7\test)
    → cmd.exe session opened
      → dir C:\Users\test\Downloads (enumerate files, discover dnscat2 binary)
        → ren dnscat2-v0.07-client-win32.exe win_installer.exe (cover tracks)
          → cd OneDrive → dir (enumerate cloud storage — 0 files)
            → cd Documents → dir (find client data optimisation folder)
              → type "user details.csv" (exfiltrate 721 PII records via DNS tunnel)
```

## Evidence Files

| File | Description |
|------|-------------|
| `suspicious_traffic.pcap` | Network traffic capture from the compromised Windows 10 workstation |

## Tools Used

| Tool | Purpose |
|------|---------|
| Zui (formerly Brim) | Pcap indexing, protocol summary, connection analysis |
| Wireshark | Packet inspection, display filters |
| tshark | CLI extraction of DNS query names and hex-encoded tunnel data |
| xxd | Decoding hex-encoded data from DNS tunnel payloads |

## Methodology

### Step 1: Initial Traffic Overview with Zui

Loading the pcap into Zui and running `count() by _path | sort -r count` reveals the traffic breakdown:

| Protocol | Count | Notes |
|----------|-------|-------|
| dns | 6,494 | Unusually high — potential DNS tunneling |
| conn | 1,444 | All connections |
| ssl | 304 | Encrypted HTTPS traffic |
| files | 173 | File transfers |
| http | 122 | Unencrypted web traffic |
| ssh | 2 | SSH connections |
| pe | 1 | Windows executable transferred |

The 6,494 DNS queries immediately stand out as suspicious.

### Step 2: Investigate the PE File

Querying `_path=="pe"` shows a 64-bit Windows executable was transferred. However, checking the HTTP logs reveals it was downloaded from `au.download.windowsupdate.com` — a legitimate **Windows Defender update** (`am_delta_patch`), not malware. All HTTP traffic is benign (Windows Update, OCSP checks).

### Step 3: Identify the DNS Tunnel

Querying `_path=="conn" | sort -r orig_bytes | head 10` reveals the largest data flow:

```
192.168.157.144:64377 → 192.168.157.145:53 (UDP/DNS)
orig_bytes: 809,199 | resp_bytes: 1,029,842 | duration: 25 minutes
4,978 packets each direction
```

This is the DNS tunnel — **192.168.157.145** is the attacker's rogue DNS server on the same subnet, exchanging ~1.8MB of data over 25 minutes through DNS queries. The tunneling domain is `microsofto365.com` (note the typo — "microsofto" not "microsoft").

### Step 4: Decode the DNS Tunnel

Using tshark to extract DNS queries to the suspect host:

```bash
tshark -r suspicious_traffic.pcap -Y 'ip.dst == 192.168.157.145 && dns' \
  -T fields -e dns.qry.name | head -5
```

The first query contains hex-encoded data in the subdomain:

```
2cea00661b600a0021636f6d6d616e6420284445534b544f502d554d4e43.4245372900.microsofto365.com
```

Decoding with `xxd -r -p` reveals: `!command (DESKTOP-UMNCBE7)` — this is **dnscat2's** initial beacon, identifying the tool and victim hostname.

### Step 5: Extract Commands and Data

Filtering for data-carrying queries (longer DNS names) and decoding the hex payloads reveals the full attack sequence:

1. **`whoami`** → `desktop-umncbe7\test`
2. **`dir`** in Downloads → reveals `dnscat2-v0.07-client-win32.exe` among other files
3. **`ren dnscat2-v0.07-client-win32.exe win_installer.exe`** → rename to hide the tool
4. **`cd OneDrive`** → `dir` shows **0 files** in cloud storage
5. **`cd ..`** → navigate to user profile, then Documents
6. **`cd "client data optimisation"`** → find sensitive data folder containing 3 files:
   - `Info on the ingest process.txt` (0 bytes)
   - `README.rtf` (7 bytes)
   - `user details.csv` (239,714 bytes)
7. **`type "user details.csv"`** → exfiltrate the entire CSV through the DNS tunnel

### Step 6: Analyze Stolen PII

The CSV data tunneled through DNS contains employee PII with columns: job, company, SSN, residence, current_location, blood_group, website, username, name, sex, address, mail, birthdate.

Records are numbered starting from 0, with the last record being **720** — totaling **721 PII records** stolen.

### Step 7: Additional Observations

**SSH/WinSCP connections** to internal host `192.168.0.26:22`:
- First attempt at 10:29:44 — `auth_success: false`
- Second attempt at 10:29:55 — `auth_success: true`
- Client: WinSCP 5.17.8, suggesting file transfer activity

**Suspicious domain `nedukeration.info`**: 5 TLS connections over CloudFront CDN — purpose unclear but potentially related to the compromise.

## Key Takeaways

**Zui (Brim) cuts through noise fast** — With 6,494 DNS queries, 1,444 connections, and thousands of ARP/broadcast packets, Zui's `count() by _path` query immediately identified where to focus. It indexes the pcap and lets you query it like a database, far faster than scrolling through Wireshark.

**DNS tunneling hides in plain sight** — DNS is allowed through almost every firewall. The attacker used dnscat2 to tunnel a full cmd.exe session through DNS queries to a rogue server on the same subnet. The data was hex-encoded in DNS subdomains under `microsofto365.com` — a typosquat designed to look legitimate at a glance.

**xxd is essential for DNS tunnel analysis** — The `xxd -r -p` command converts hex back to readable text. Without it, the DNS query names look like random hex strings. With it, you can reconstruct the attacker's entire session — every command typed and every byte of output returned.

**tshark enables scripted analysis** — Key flags: `-r` (read pcap), `-Y` (display filter), `-T fields` (field output mode), `-e` (extract specific fields like `dns.qry.name`). Piping tshark output through `sed` and `xxd` lets you decode tunnel data at scale.

**Volume of DNS queries is a detection signal** — 6,494 DNS queries in a short capture window is abnormal. Monitoring for excessive DNS traffic to a single destination, unusually long DNS query names, or queries to newly registered/suspicious domains can detect DNS tunneling.

**Anti-forensics attempts leave traces** — The attacker tried to rename `dnscat2-v0.07-client-win32.exe` to `win_installer.exe` to hide the tool. The first rename attempt failed (incorrect syntax), and the second succeeded — but both attempts were captured in the DNS tunnel traffic.

## Personal Lessons Learned

**Zui/Brim setup on Kali** — Zui was renamed from Brim. Install via `.deb` from GitHub. It requires a `zed` backend service. If `localhost` doesn't resolve (missing from `/etc/hosts`), Zui can't connect to its backend — fix with `echo "127.0.0.1 localhost" | sudo tee -a /etc/hosts`. The Zui `zed` binary is at `/opt/Zui/resources/app.asar.unpacked/zdeps/zed` — don't confuse it with the ZFS `zed` daemon.

**Zui query language basics** — `count() by _path | sort -r count` for traffic overview, `_path=="dns"` to filter by protocol, `_path=="conn" | sort -r orig_bytes` to find largest data flows. Click protocol tags to drill down.

**DNS tunnel decoding workflow** — Extract queries with tshark (`-e dns.qry.name`), strip the tunnel domain with `sed`, decode hex with `xxd -r -p`. Filter for longer queries (`dns.qry.name.len > 60`) to find data-carrying packets vs heartbeats.

**The `&` operator** — Appending `&` to a command runs it in the background so you get your terminal prompt back. Useful when starting services like `zed serve`.

**Wireshark noise filtering** — Use `!arp && !dns` to filter out background noise. Save frequently-used filters as bookmarks with the + button on the filter bar.

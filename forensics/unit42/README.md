# Unit42

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Very Easy
**Status:** Retired

## Overview

This Sherlock introduces Sysmon log analysis on a Windows system. Inspired by Palo Alto Unit42's research on a campaign using a backdoored version of UltraVNC, the lab walks through the initial access stage: a malicious executable delivered via Dropbox that performs file drops, timestomping, network connectivity checks, and ultimately deploys a backdoored UltraVNC variant for persistent access.

## Attack Chain

```
Malicious file downloaded from Dropbox via Firefox
  → Preventivo24.02.14.exe.exe executes (double extension masquerading)
    → Drops files to disk with timestomping (T1070.006)
      → Writes once.cmd and UltraVNC components
        → DNS query to www.example.com (connectivity check)
          → Outbound connection to 93.184.216.34
            → Process self-terminates after deploying backdoor
```

## Evidence Files

| File | Description |
|------|-------------|
| `Microsoft-Windows-Sysmon-Operational.evtx` | Sysmon event log from compromised Windows host (DESKTOP-887GK2L) |

## Tools Used

| Tool | Purpose |
|------|---------|
| `libevtx-utils` (`evtxexport`) | Convert .evtx to parseable text format on Linux |
| `grep` | Filter and count events by Event ID and indicators |

## Methodology

### Step 1: Export and Parse the Sysmon Log

The `.evtx` format is a Windows binary log format. On Linux, use `evtxexport` from `libevtx-utils` to convert it to a text format suitable for grep:

```bash
sudo apt install libevtx-utils
evtxexport Microsoft-Windows-Sysmon-Operational.evtx > sysmon.xml
```

The output uses the field `Event identifier` with hex and decimal values, e.g., `0x0000000b (11)`.

### Step 2: Count File Creation Events (Event ID 11)

Event ID 11 records file creation events. Count them:

```bash
grep -c '(11)' sysmon.xml
```

Result: **56** file creation events.

### Step 3: Identify the Malicious Process (Event ID 1)

Event ID 1 logs process creation with details like command line, hashes, and parent process. Searching for process creation events reveals the suspicious executable:

```bash
grep -A 20 '(1)$' sysmon.xml
```

The malicious process is `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` — the double `.exe` extension is a classic social engineering technique to disguise an executable as a document.

### Step 4: Identify the Delivery Mechanism

The earliest events (Event ID 22 — DNS queries) show Firefox resolving Dropbox domains, and file creation events show the download originating from `dropboxusercontent.com`:

```bash
grep -i 'dropbox' sysmon.xml
```

The `ZoneTransfer` data confirms the file was downloaded from **Dropbox** with a referrer URL of `https://www.dropbox.com/`.

### Step 5: Detect Timestomping (Event ID 2)

Event ID 2 records file creation time changes. Sysmon tags this with MITRE ATT&CK technique `T1070.006` (Timestomp):

```bash
grep -B 5 -A 20 '\.pdf' sysmon.xml
```

The dropped PDF file (`~.pdf`) had its creation timestamp changed to **2024-01-14 08:10:06** to blend in with legitimate files — a month earlier than the actual execution date.

### Step 6: Locate Dropped Files

Searching for specific filenames reveals where the malware staged its payloads:

```bash
grep 'once.cmd' sysmon.xml
```

`once.cmd` was created at `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`.

### Step 7: Identify Network Activity (Event IDs 22 and 3)

The malware made a DNS query to check internet connectivity before reaching out to its target:

```bash
grep -A 20 '(22)' sysmon.xml
```

It resolved **www.example.com** — a commonly used dummy domain for connectivity checks.

Event ID 3 (network connection) shows the outbound TCP connection:

```bash
grep -A 20 '(3)' sysmon.xml
```

Destination IP: **93.184.216.34** on port 80, tagged with MITRE technique `T1036` (Masquerading).

### Step 8: Process Termination (Event ID 5)

After deploying the backdoored UltraVNC components, the malicious process terminated itself:

```bash
grep -A 20 '(5)' sysmon.xml
```

Process `Preventivo24.02.14.exe.exe` (PID 10672) terminated at **2024-02-14 03:41:58**.

## Key Takeaways

**Know your Sysmon Event IDs** — Sysmon provides granular visibility into system activity. The most critical IDs for threat hunting are 1 (process creation), 3 (network connection), 11 (file creation), and 22 (DNS query). Memorizing these accelerates analysis significantly.

**Double extensions are a red flag** — Files like `Preventivo24.02.14.exe.exe` exploit Windows' default behavior of hiding known extensions, making the file appear as a legitimate document to end users.

**Timestomping is a common evasion technique** — Attackers modify file creation timestamps (T1070.006) to make dropped files blend in with legitimate ones. Sysmon Event ID 2 specifically catches this, making it invaluable for detection.

**Connectivity checks precede C2** — Malware frequently queries benign domains like `www.example.com` to verify internet access before attempting command-and-control communication. These DNS queries can serve as early indicators of compromise.

**Self-terminating droppers clean up after themselves** — The initial malicious process terminated after deploying the UltraVNC backdoor, leaving only the persistent payload running. This is why process creation logs (Event ID 1) are critical — the dropper may be gone by the time an analyst investigates.

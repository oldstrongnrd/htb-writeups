# I Like To

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Easy
**Status:** Retired
**CVE:** CVE-2023-34362

## Overview

This Sherlock investigates the exploitation of CVE-2023-34362, a critical SQL injection vulnerability in MOVEit Transfer that was widely exploited in mid-2023. The lab provides a KAPE triage collection from a compromised Windows server along with a 4GB memory dump (without the .vmss file, limiting Volatility usage to basic `strings` analysis). The attacker enumerated the server with Nmap, exploited the MOVEit vulnerability using a Ruby-based exploit, changed the service account password, accessed the server via RDP, and deployed an ASPX webshell.

## Attack Chain

```
Nmap enumeration of web server
  → Exploit MOVEit CVE-2023-34362 via Ruby exploit (machine2.aspx / guestaccess.aspx / moveitisapi.dll)
    → Change moveitsvc account password via SQL injection
      → RDP into server as moveitsvc
        → Upload moveit.asp to C:\inetpub\wwwroot (failed — ASP not supported)
          → Upload move.aspx to C:\MOVEitTransfer\wwwroot (working ASPX webshell)
            → Execute commands via "awen asp.net webshell"
```

## Evidence Files

| File | Description |
|------|-------------|
| `I-like-to-27a787c5.vmem` | Memory dump from compromised VM (no .vmss — use `strings`) |
| `Triage.zip` | KAPE collection: IIS logs, event logs, MFT, registry hives, user profiles |
| `moveit.sql` | Export of MOVEit Transfer MySQL database |
| `u_ex230712.log` | IIS web log for the day of the attack |
| `$MFT` | NTFS Master File Table for filesystem timeline |
| `Security.evtx` | Windows Security event log |
| `ConsoleHost_history.txt` | PowerShell command history for moveitsvc user |

## Tools Used

| Tool | Purpose |
|------|---------|
| `evtxexport` (libevtx-utils) | Convert .evtx event logs to parseable text on Linux |
| `analyzemft` | Parse NTFS MFT to CSV for file creation timestamps |
| `strings` / `grep` | Extract readable strings from memory dump |
| Zimmerman Tools (MFTECmd, EvtxECmd) | Windows-based MFT and EVTX parsing to CSV (recommended) |
| Timeline Explorer | Windows GUI for analyzing converted CSV output |

## Methodology

### Step 1: Identify Reconnaissance Activity (IIS Logs)

Start with the IIS web log to understand the attack timeline:

```bash
head -5 Triage/uploads/auto/C%3A/inetpub/logs/LogFiles/W3SVC2/u_ex230712.log
```

The `#Fields` header tells you the column layout. The Nmap Scripting Engine user agent appears throughout the early entries, indicating the attacker used **nmap** for initial enumeration from **10.255.254.3**.

### Step 2: Identify the Exploit Chain (IIS Logs)

Filter for the MOVEit exploit indicators — requests to `moveitisapi.dll` and `guestaccess.aspx`:

```bash
grep -E 'moveitisapi|guestaccess' u_ex230712.log | head -10
```

The user agent on these requests is **Ruby**, confirming the use of a Ruby-based MOVEit exploit script. The exploit follows the known CVE-2023-34362 pattern: POST to `machine2.aspx`, then `moveitisapi.dll?action=m2`, followed by SQL injection via `guestaccess.aspx`.

### Step 3: Find the Webshell (PowerShell History + IIS Logs)

Check the PowerShell command history for the compromised account:

```bash
cat Triage/uploads/auto/C%3A/Users/moveitsvc.WIN-LR8T2EF8VHM.002/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
```

This reveals the attacker downloaded two webshells via `wget`:
- `moveit.asp` → placed in `C:\inetpub\wwwroot` (ASP — didn't work on this IIS config)
- `move.aspx` → placed in `C:\MOVEitTransfer\wwwroot` (ASPX — worked)

The IIS log confirms `moveit.asp` returned 404 and `move.aspx` returned 200.

### Step 4: Determine Upload Timestamps (MFT)

IIS logs show when the webshell was *accessed*, not when it was *created on disk*. For file creation timestamps, parse the MFT:

```bash
analyzemft -f Triage/uploads/ntfs/%5C%5C.%5CC%3A/\$MFT -o mft_output.csv
grep -ai 'move.aspx\|moveit.asp' mft_output.csv
```

> Note: Zimmerman's MFTECmd (Windows) provides more complete parsing than `analyzemft` (Linux). For best results, use a Windows analysis VM with Timeline Explorer.

### Step 5: Find the Password Change (Security Event Log)

The attacker changed the `moveitsvc` password. Look for Security Event ID 4724 (password reset):

```bash
evtxexport Security.evtx 2>/dev/null | grep -B 5 -A 15 '(4724)'
```

Multiple 4724 events exist — filter for the one on July 12th during the attack window.

### Step 6: Confirm Remote Access (Terminal Services Event Log)

Check for RDP sessions from the attacker's IP:

```bash
evtxexport Microsoft-Windows-TerminalServices-LocalSessionManager%254Operational.evtx 2>/dev/null | grep -B 5 -A 15 '10.255.254.3'
```

Event ID 21 (session logon) confirms the RDP connection with the `moveitsvc` account.

### Step 7: Find the Inst ID (MOVEit SQL Dump)

The attacker's MOVEit instance ID is in the SQL dump. Look at the `log` table for entries from the attacker's IP:

```bash
grep 'msg_post' moveit.sql
```

The `msg_post` entries from `10.255.254.3` all share instid **1234**.

### Step 8: Extract Webshell Content and Password (Memory Dump)

Without the .vmss file, Volatility won't work — but `strings` still extracts useful data:

```bash
# Find the webshell title
strings I-like-to-27a787c5.vmem | grep -B 5 'form name="cmd"' | grep title

# Find the password change command
strings I-like-to-27a787c5.vmem | grep -i 'net user moveitsvc'
```

## Key Takeaways

**The MFT is essential for file-level forensics** — IIS logs show when files were accessed, but the MFT shows when they were created on disk. Zimmerman's MFTECmd is the gold standard for parsing; Linux alternatives like `analyzemft` work but are less thorough.

**PowerShell history is a goldmine** — The `ConsoleHost_history.txt` file under each user profile records every command typed in PowerShell. It immediately revealed the attacker's webshell download commands and locations.

**MOVEit CVE-2023-34362 has distinct IOCs** — The exploit chain (machine2.aspx → moveitisapi.dll?action=m2 → guestaccess.aspx → API file upload) with a Ruby user agent is a signature pattern. Monitoring these endpoints would have detected the attack.

**Memory dumps are useful even without proper tooling** — Without the .vmss file, Volatility couldn't process the memory dump, but `strings` + `grep` still extracted the webshell HTML, the password change command, and other critical evidence.

**Windows DFIR tooling matters** — Zimmerman tools, Timeline Explorer, and Event Log Viewer provide significantly better analysis workflows than Linux alternatives for Windows artifact analysis. A dedicated Windows analysis VM is recommended for Sherlock-style labs.

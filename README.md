# Day 3: Developer's Toolbox (Linux & Networking for AppSec)

A comprehensive hands-on lab covering process and socket inspection, log forensics (`grep`/`awk`/PowerShell), raw HTTP manipulation via `curl`, cookie and security header analysis, and network routing fundamentals.

> [!NOTE]
> **Environment Execution Note**: All outputs and commands documented in this report were **observed on Windows PowerShell 5.1; Linux commands are reference only, not run here**.

---

## Workspace Structure

```text
day-3/
├── day3-lab/
│   ├── lab_server.py      # Local-only Flask testbench (127.0.0.1:5050, debug=False)
│   └── lab.log            # Local request access log (untracked / gitignored)
├── day3-toolbox.md        # Lab curriculum and mission specifications
├── .gitignore             # Git ignore configuration (*.log, .venv, caches)
└── README.md              # Complete walkthrough, observed outputs, and Day 3 report
```

---

## Lab Architecture & Execution Model

The lab server (`lab_server.py`) is designed with strict local development boundaries:
* **Bind Address**: Hardcoded to `127.0.0.1` (loopback only, preventing remote interface exposure).
* **Port**: Default `5050` (configurable via `LAB_PORT`).
* **Debug Mode**: Disabled (`debug=False`).
* **Access Logging**: Appends request metadata locally to `day3-lab/lab.log` (excluded from version control) in the format:  
  `<UTC time> <client ip> <method> <path> <status> <bytes>B "<user agent>"`

---

## Missions 1–10: Detailed Walkthrough & Observed Outputs

### Mission 1: Find It Blind (Port & Process Identification)
* **Goal**: Identify the process listening on port `5050` without reading the terminal banner, and verify against `/health`.
* **Commands**:
  * *Linux (Reference)*: `lsof -nP -iTCP:5050 -sTCP:LISTEN` or `ss -ltnp`
  * *PowerShell 5.1 (Run)*: `Get-NetTCPConnection -LocalPort 5050 -State Listen`
* **Observed Real Output**:
  ```text
  Listening PID from Get-NetTCPConnection: 20572
  curl.exe -s http://127.0.0.1:5050/health -> {"pid":20572,"status":"ok"}
  ```
* **Takeaway**: Confirmed that the socket listener PID maps directly to the active Python server PID.

---

### Mission 2: Port Collision Handling (EADDRINUSE)
* **Goal**: Attempt to launch a second listener on port `5050` while the first is active, and observe socket collision error handling.
* **Linux Standard (Reference)**: `OSError: [Errno 98] Address already in use`
* **Observed Real Output (Windows PowerShell 5.1)**:
  ```text
  Traceback (most recent call last):
    File "<string>", line 1, in <module>
      import socket; s = socket.socket(); s.bind(('127.0.0.1', 5050))
  OSError: [WinError 10048] Only one usage of each socket address (protocol/network address/port) is normally permitted
  ```
* **Remediation**: Isolate process via port query (`Get-NetTCPConnection`), terminate owner (`Stop-Process -Id <PID>`), or select alternate port (`LAB_PORT=5051`).

---

### Mission 3: Bind Comparison (Loopback vs All Interfaces) — *Day 5 Evidence #1*
* **Goal**: Compare binding on loopback (`127.0.0.1`) vs universal interfaces (`0.0.0.0` / `*`).
* **Test Setup**: Launched temporary test listeners from an isolated sandbox and verified socket bindings.
* **Observed Real Output (Windows PowerShell 5.1)**:
  ```text
  LocalAddress LocalPort OwningProcess
  ------------ --------- -------------
  0.0.0.0           8082         20884   <- Public/All Interfaces: Accessible across local network
  127.0.0.1         8081         18192   <- Loopback only: Host machine isolation
  ```
* **Security Finding (Finding 1 — Refined Threat Analysis)**:
  Binding to `0.0.0.0` exposes application ports to all devices on the local network segment. When combined with Werkzeug's interactive debugger (`debug=True`), the exposure introduces severe risk: unhandled exception tracebacks expose internal file paths, source code lines, and framework versions. While interactive console execution and inspection of environment variables are guarded by a PIN, predictable PIN generation algorithms (or PIN bypass vulnerabilities under specific host/container configurations) can elevate this directly to arbitrary remote code execution.

---

### Mission 4: Traffic Generation & Access Log Analysis
* **Goal**: Send a batch of valid and invalid requests and verify status and path counts against total lines in `lab.log`.
* **Commands**:
  * *Linux (Reference)*:
    * Status: `awk '{print $5}' lab.log | sort | uniq -c | sort -rn`
    * Path: `awk '{print $4}' lab.log | sort | uniq -c | sort -rn`
  * *PowerShell 5.1 (Run)*:
    * Status: `Get-Content lab.log | % { ($_ -split ' ')[4] } | Group-Object | Sort Count -Desc`
    * Path: `Get-Content lab.log | % { ($_ -split ' ')[3] } | Group-Object | Sort Count -Desc`
* **Observed Real Output**:
  ```text
  Total lines in lab.log: 31

  --- Count by Status ---
  Count Name
  ----- ----
     19 200
      9 404
      3 302
  (Sum = 31)

  --- Count by Path ---
     10 /health
      3 /badpath
      3 /hardened
      3 /missing
      3 /nope
      3 /headers
      3 /set-cookie
      3 /redirect
  (Sum = 31)
  ```

---

### Mission 5: Brute-Force Log Forensics
* **Goal**: Send 6 failed login attempts with invalid credentials and extract the brute-force signature from access logs.
* **Commands**:
  * *Linux (Reference)*: `grep -E 'POST /login 401' lab.log`
  * *PowerShell 5.1 (Run)*: `Select-String -Path lab.log -Pattern 'POST /login 401'`
* **Observed Real Output**:
  ```text
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  2026-11-19T09:43:58+00:00 127.0.0.1 POST /login 401 42B "curl/8.13.0"
  ```
* **Detection Rule**:
  Trigger an alert when a threshold of $N$ failed `POST /login` attempts (HTTP 401) occurs within a sliding 60-second window from a single IP or targeting a single username.

---

### Mission 6: Content-Type Header Validation
* **Goal**: Trigger an HTTP 400 on `/echo` by omitting required JSON headers, then test both remediation methods.
* **Observed Real Output (Windows PowerShell 5.1)**:
  * **Test 1 (Omitted Header)**:
    ```http
    HTTP/1.1 400 BAD REQUEST
    {"error":"Send a JSON object with Content-Type: application/json"}
    ```
    *Root Cause*: `curl -d` sends `Content-Type: application/x-www-form-urlencoded` by default.
  * **Test 2 (Explicit Header `-H`)**:
    ```http
    HTTP/1.1 200 OK
    {"content_type":"application/json","you_sent":{"msg":"hi"}}
    ```
  * **Test 3 (Modern `--json` flag)**:
    ```http
    HTTP/1.1 200 OK
    {"content_type":"application/json","you_sent":{"msg":"hi"}}
    ```

---

### Mission 7: Security Header Analysis (`/health` vs `/hardened`)
* **Goal**: Inspect security headers added to `/hardened` that are missing from default `/health`.
* **Observed Header Differences**:
  | Security Header | Value on `/hardened` | Vulnerability Mitigation |
  |---|---|---|
  | `X-Content-Type-Options` | `nosniff` | Prevents browser MIME-type sniffing / confusion attacks. |
  | `X-Frame-Options` | `DENY` | Prevents Clickjacking by disallowing framing in `<iframe>`. |
  | `Referrer-Policy` | `no-referrer` | Stops leaking sensitive paths/tokens in `Referer` headers. |
  | `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Restricts untrusted script execution (XSS) and frame embedding. |
  | `Cache-Control` | `no-store` | Prevents local browser or intermediate proxy caching of sensitive data. |
* **Information Leakage**: `Server: Werkzeug/3.1.9 Python/3.15.2` appears on all responses, exposing exact software versions.

---

### Mission 8: Cookie Security Review — *Day 5 Evidence #8*

#### 1. Lab Server Cookie Configuration (`/set-cookie`)
```http
Set-Cookie: session_demo=abc123; Expires=Thu, 19 Nov 2026 10:44:36 GMT; Max-Age=3600; HttpOnly; Path=/; SameSite=Lax
Set-Cookie: tracker=1; Path=/
```
* **Strong**: `session_demo` enforces `HttpOnly` (mitigating XSS theft) and `SameSite=Lax` (mitigating CSRF).
* **Weak**: `tracker` omits `HttpOnly`, `SameSite`, and `Expires`/`Max-Age`.

#### 2. Live Day 2 App Verification (`day-2/app.py` on `127.0.0.1:3000`)
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.15.2
Set-Cookie: session=<redacted>; HttpOnly; Path=/
```
* **Audit Findings (Finding 8 Evidence)**:
  * `HttpOnly`: **Present** (protects cookie from JavaScript DOM access).
  * `SameSite`: **MISSING** (No `SESSION_COOKIE_SAMESITE` configured; weakens CSRF defence in depth alongside no CSRF tokens, noting that modern browsers default to Lax).
  * `Secure`: **MISSING** (No `SESSION_COOKIE_SECURE` configured; cookie vulnerable to plaintext transmission).

---

### Mission 9: Latency & Handshake Timing Analysis (`curl -w`)
* **Goal**: Measure network connection establishment vs application computation time.
* **Commands**:
  ```powershell
  curl.exe -s -o NUL -w "health -> code=%{http_code} connect=%{time_connect}s total=%{time_total}s`n" http://127.0.0.1:5050/health
  curl.exe -s -o NUL -w "slow?sec=2 -> code=%{http_code} connect=%{time_connect}s total=%{time_total}s`n" "http://127.0.0.1:5050/slow?sec=2"
  ```
* **Observed Real Output**:
  ```text
  health      -> code=200 connect=0.010473s total=0.011958s
  slow?sec=2  -> code=200 connect=0.000994s total=2.003401s
  ```
* **Analysis**:
  * `connect` (`%{time_connect}`): Measures initial TCP handshake duration (~0.001s on loopback).
  * `total` (`%{time_total}`): Measures total round-trip duration including server execution / sleep delays (~2.003s).

---

### Mission 10: Network Configuration & DNS Overrides
* **Host Configuration**:
  * **Default Gateway**: `192.168.18.1`
  * **DNS Server**: `192.168.18.1`
* **Static Host Resolution Override (`--resolve`)**:
  ```powershell
  curl.exe -si --resolve lab.test:5050:127.0.0.1 http://lab.test:5050/health
  ```
* **Observed Real Output**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"pid":20572,"status":"ok"}
  ```
* **Takeaway**: `--resolve` replaces operating system DNS queries and hosts file lookups by statically binding `lab.test:5050` to `127.0.0.1` while preserving `Host: lab.test:5050`.

---

## Linux vs. PowerShell Command Reference

*(Note: Linux commands are provided for reference only; all runs occurred in Windows PowerShell 5.1)*

| Operational Goal | Linux Standard (Reference) | Windows PowerShell 5.1 (Executed) |
|---|---|---|
| Query listening port owner | `lsof -nP -iTCP:5050 -sTCP:LISTEN` | `Get-NetTCPConnection -LocalPort 5050 -State Listen` |
| List all listening sockets | `ss -ltnp` | `netstat -ano \| findstr LISTENING` |
| Process details by PID | `ps -o pid,cmd -p <PID>` | `Get-Process -Id <PID>` |
| Tail access logs | `tail -n 20 lab.log` | `Get-Content lab.log -Tail 20` |
| Filter log patterns | `grep -E ' [45][0-9]{2} ' lab.log` | `Select-String ' [45]\d{2} ' lab.log` |
| Aggregate counts | `awk '{print $5}' lab.log \| sort \| uniq -c` | `Get-Content lab.log \| % { ($_ -split ' ')[4] } \| Group-Object` |
| Network interfaces & IPs | `ip -br addr` | `Get-NetIPConfiguration` or `ipconfig` |
| DNS server discovery | `cat /etc/resolv.conf` | `Get-DnsClientServerAddress -AddressFamily IPv4` |
| Host resolution test | `dig example.com` | `Resolve-DnsName example.com` |
| Raw HTTP client | `curl -i URL` | `curl.exe -i URL` (use `@body.json` for JSON bodies) |

---

## Day 3 Submission Report

### 1. Done
- Extracted `day3-package.zip` into the Day 3 workspace, configured `.gitignore`, and set up the local-only `lab_server.py` testbench on port `5050`.
- Systematically executed all 10 missions defined in `day3-toolbox.md` using Windows PowerShell 5.1 native tools and `curl.exe`.
- Captured real outputs across process binding, log forensics, raw HTTP payload manipulation, latency timing, and DNS overrides.
- Collected concrete audit evidence for Day 5 Findings 1 and 8.

### 2. Learned
- **Interface Exposure & Debugger Risk (Finding 1)**: Binding to `0.0.0.0` exposes services to the entire local network segment. Unhandled exception tracebacks expose internal paths, source lines, and framework versions; while environment variables and arbitrary execution are protected by Werkzeug's PIN-protected console, predictable PIN generation or PIN bypasses can elevate this to remote code execution.
- **Session Cookie Flags (Finding 8)**: Inspecting live cookies from `day-2/app.py` proved that while `HttpOnly` is present by default, `SameSite` and `Secure` are missing. Missing `SameSite` weakens CSRF defence in depth, alongside no CSRF tokens (noting that modern browsers default to Lax), while missing `Secure` leaves cookies vulnerable to cleartext interception over HTTP.
- **Header Hardening**: Verified that baseline production security requires `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, and `Cache-Control: no-store`.
- **Log Forensics**: Structured, space-delimited access logs allow fast detection of brute-force and credential stuffing attacks via status aggregation (`401` bursts).

### 3. Blocked
- **PowerShell JSON Escaping**: Inline JSON strings passed via `curl.exe -d` had double quotes stripped by PowerShell's parser, resulting in 400 Bad Request responses. Fixed by reading JSON payloads from temporary files (`-d @body.json`) or leveraging `--json`.
- **Log Exclusion & Secret Scrubbing**: Removed `lab.log` from git tracking (`git rm --cached`) and updated `.gitignore` to prevent committing ephemeral runtime logs. Sanitized all live session tokens in documentation to `session=<redacted>`.
- **Windows vs Linux Syntax Translation**: Successfully translated Linux-specific toolchains (`ss`, `lsof`, `tail`, `grep`, `awk`) into native PowerShell cmdlets (`Get-NetTCPConnection`, `Get-Content`, `Select-String`, `Group-Object`).

### 4. Next actions
- Transition to **Day 4: Web Mechanics and State** (deeper inspection of HTTP state, session management, CSRF tokens, and authentication boundaries).
- Consolidate evidence from Day 2 and Day 3 (Findings 1, 2, and 8) for the comprehensive Day 5 AppSec Audit Report.

---

## AI Assistance & Tooling Metadata

- **Primary AI Assistant**: Antigravity with Gemini (workspace execution, command automation, and verification).
- **Secondary Tooling**: Claude chat for the Day 3 curriculum guide and concept formulation.

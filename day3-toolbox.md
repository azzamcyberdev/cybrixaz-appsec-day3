# Day 3: Developer's Toolbox (Linux and Networking)

Goal: inspect listening ports and the processes that own them, tail logs, read network config,
and talk to a web server with raw `curl` (JSON bodies, headers, cookies).

**Rules (same as the whole week):** only local targets: the lab server in this folder, your own
`day-2` app on `127.0.0.1`, or intentionally vulnerable labs such as Juice Shop. Never scan or send
payloads at anything else. Don't run anything with `sudo`/admin unless a step says so.

**How this guide was checked:** every command marked **ran** was executed against the lab server in
a Linux sandbox and the output shown is real. Commands marked *not run* (`ss`, `ip`, `dig`,
`journalctl`, and all the Windows equivalents) are standard syntax I could not execute there, so
the sample output for them is illustrative. Your addresses and PIDs will differ.

---

## 0. Where to run this on a Windows laptop

The curriculum is Linux. You have three options; pick one:

| Option | How | Notes |
|---|---|---|
| **WSL2 (Ubuntu)** | `wsl --install -d Ubuntu` in an admin PowerShell, restart, open "Ubuntu" | Easiest. Needs your approval to install (your policy file). |
| **Linux VM** | the VM from your repo's `scripts/provision_lab.sh`, or any Ubuntu VM | Most realistic. |
| **Windows only** | use the PowerShell column in each section | Works, but you won't practise the Linux tools the curriculum names. |

Setup (Linux/WSL): `python3 -m venv .venv && . .venv/bin/activate && pip install flask`
Setup (Windows): reuse your `day-2` venv: `..\day-2\.venv\Scripts\python.exe lab_server.py`

## 1. Start the lab

```bash
cd day3-lab
python lab_server.py        # prints: Lab server on http://127.0.0.1:5050 (PID 145, log: lab.log)
```

Leave it running. Use a **second terminal** for everything below. Routes: `/health`, `/headers`,
`/echo` (POST JSON), `/login` (POST JSON, fake creds `lab-user` / `lab-password`), `/set-cookie`,
`/redirect`, `/slow?sec=2`, `/hardened`. Each request is appended to `lab.log`.

---

## 2. Ports and the processes that own them

| Goal | Linux | Windows PowerShell *(not run)* |
|---|---|---|
| Who is listening on port 5050? | `lsof -nP -iTCP:5050 -sTCP:LISTEN` | `Get-NetTCPConnection -LocalPort 5050 -State Listen` |
| All listening TCP ports + owner | `ss -ltnp` *(not run)* | `netstat -ano \| findstr LISTENING` |
| Details of a PID | `ps -o pid,ppid,etime,cmd -p 145` | `Get-Process -Id 145 \| Format-List *` |
| Find a process by name | `pgrep -af lab_server` | `Get-Process python` |
| Stop it politely, then forcefully | `kill 145`, then only if needed `kill -9 145` | `Stop-Process -Id 145`, then `-Force` |

**ran:**
```
$ lsof -nP -iTCP:5050 -sTCP:LISTEN
COMMAND PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python  145 root    3u  IPv4   1931      0t0  TCP 127.0.0.1:5050 (LISTEN)

$ ps -o pid,ppid,etime,cmd -p 145
  PID  PPID     ELAPSED CMD
  145   141       00:02 .../venv/bin/python lab_server.py

$ pgrep -af lab_server
145 .../venv/bin/python lab_server.py
```
Read it: command `python`, PID `145`, listening on **`127.0.0.1:5050`**. The PID matches what
`curl http://127.0.0.1:5050/health` returns (`{"pid":145,...}`). Parent PID 141 is the shell that started it.

`ss -ltnp` prints the same facts in this shape *(illustrative, not run)*:
```
State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN  0       128     127.0.0.1:5050      0.0.0.0:*          users:(("python",pid=145,fd=3))
```

### The bind address is the security-relevant column (this is your finding 1)

**ran** (two throwaway `http.server`s started from an **empty folder**, then killed):
```
COMMAND  PID  NAME
python3  154  127.0.0.1:8081 (LISTEN)     <- loopback only: only this machine can connect
python3  156  *:8082 (LISTEN)             <- all interfaces: anyone on your network can connect
```
`127.0.0.1` = local only. `*` / `0.0.0.0` = every network interface. Your `app.py` line 332
uses `host="0.0.0.0"` *with the debugger on*, which is why it's the top finding.
Don't run `http.server --bind 0.0.0.0` from a folder with files in it: it lists and serves them.

### Address already in use (ran)
Start a second copy while the first is running:
```
Address already in use
Port 5050 is in use by another program. Either identify and stop that program, or start the server with a different port.
```
Fix: find the owner (`lsof` above), stop it, or choose another port (`LAB_PORT=5051 python lab_server.py`).

### Stop it and prove it's gone (ran)
```
$ kill 145
$ lsof -nP -iTCP:5050 -sTCP:LISTEN || echo "port 5050 is free"
port 5050 is free
```

---

## 3. Logs

`lab.log` format: `<UTC time> <ip> <METHOD> <path> <status> <bytes>B "<user-agent>"`. Fields are
space-separated, so the status code is awk's `$5`, the path is `$4`.

| Goal | Linux | Windows PowerShell *(not run)* |
|---|---|---|
| Last 20 lines | `tail -n 20 lab.log` | `Get-Content lab.log -Tail 20` |
| Follow live | `tail -f lab.log` | `Get-Content lab.log -Wait -Tail 10` |
| Only client/server errors | `grep -E ' [45][0-9][0-9] ' lab.log` | `Select-String ' [45]\d\d ' lab.log` |
| Count by status | `awk '{print $5}' lab.log \| sort \| uniq -c \| sort -rn` | `Get-Content lab.log \| % { ($_ -split ' ')[4] } \| Group-Object \| Sort Count -Desc` |
| Requests per path | `awk '{print $4}' lab.log \| sort \| uniq -c \| sort -rn` | same idea with `[3]` |

**ran** (`tail -f` while sending two requests from another terminal):
```
2026-11-19T06:50:56+00:00 127.0.0.1 GET /health 200 26B "curl/8.5.0"
2026-11-19T06:50:56+00:00 127.0.0.1 GET /nope 404 207B "curl/8.5.0"
```
**ran** (status counts after a session of curl experiments):
```
     16 200
      2 302
      1 404
      1 401
      1 400
```
System logs (Linux with systemd) *(not run)*: `journalctl -n 50 --no-pager`, `journalctl -f`,
`journalctl -u <service> --since "10 min ago"`. WSL2 only has a journal if systemd is enabled.

**What an AppSec person looks for:** many `401`s on `/login` from one IP (brute force), bursts of
`400`/`500` (malformed input, your finding 2), a `404` scan across many paths, a user-agent like `sqlmap`.

---

## 4. Network configuration (all *not run*: syntax and how to read the output)

| Goal | Linux | Windows PowerShell |
|---|---|---|
| My IPs | `ip -br addr` | `Get-NetIPConfiguration` or `ipconfig` |
| Default gateway | `ip route` (the `default via ...` line) | `ipconfig` -> "Default Gateway" |
| Route used for a destination | `ip route get 1.1.1.1` | `Find-NetRoute -RemoteIPAddress 1.1.1.1` |
| DNS servers | `cat /etc/resolv.conf` or `resolvectl status` | `Get-DnsClientServerAddress` |
| Resolve a name | `getent hosts example.com`, `dig example.com` | `Resolve-DnsName example.com` |
| Hosts file | `cat /etc/hosts` | `Get-Content C:\Windows\System32\drivers\etc\hosts` |

Illustrative output (made-up private addresses):
```
$ ip -br addr
lo      UNKNOWN  127.0.0.1/8
eth0    UP       192.168.1.23/24
$ ip route
default via 192.168.1.1 dev eth0         <- 192.168.1.1 is the gateway
192.168.1.0/24 dev eth0 ...
$ cat /etc/resolv.conf
nameserver 192.168.1.1                    <- the DNS server your machine asks
```
**ran:** `getent hosts localhost` -> `127.0.0.1       localhost` (answered from the hosts file, no DNS server involved).

---

## 5. curl: talking HTTP by hand

Windows PowerShell 5.1: always type **`curl.exe`** (plain `curl` is an alias for something else) and
send JSON from a **file** (`-d "@body.json"`), because quoting JSON inline is where PowerShell breaks.

### Status line, headers, body (ran)
```
$ curl -i http://127.0.0.1:5050/health
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.13.18
Date: Thu, 19 Nov 2026 06:50:53 GMT
Content-Type: application/json
Content-Length: 26
Connection: close

{"pid":145,"status":"ok"}
```
Useful flags: `-i` headers+body, `-I` headers only (HEAD), `-v` full request and response,
`-s` quiet, `-o /dev/null` discard body (`-o NUL` on Windows), `-L` follow redirects, `-H` add a header.

### What curl sends (ran, trimmed `curl -v`)
```
> GET /health HTTP/1.1
> Host: 127.0.0.1:5050
> User-Agent: curl/8.5.0
> Accept: */*
< HTTP/1.1 200 OK
< Server: Werkzeug/3.1.9 Python/3.13.18
< Content-Type: application/json
```
Lines starting `>` are what you sent, `<` what came back.

### Timing (ran)
```
$ curl -s -o /dev/null -w 'code=%{http_code} connect=%{time_connect}s total=%{time_total}s\n' http://127.0.0.1:5050/health
code=200 connect=0.000094s total=0.001114s
$ curl -s -o /dev/null -w 'code=%{http_code} total=%{time_total}s\n' "http://127.0.0.1:5050/slow?sec=2"
code=200 total=2.001662s
```

### POST with a JSON body (ran)
```
$ curl -s -X POST -H 'Content-Type: application/json' -d '{"msg":"hi"}' http://127.0.0.1:5050/echo
{"content_type":"application/json","you_sent":{"msg":"hi"}}

$ curl -s -w ' [HTTP %{http_code}]\n' -X POST -d '{"msg":"hi"}' http://127.0.0.1:5050/echo      # forgot the header
{"error":"Send a JSON object with Content-Type: application/json"}
 [HTTP 400]
```
Why the 400: `-d` makes curl send `Content-Type: application/x-www-form-urlencoded`, so the server
doesn't treat the body as JSON. Header and body must agree.

Shortcut (curl 7.82+, sets header and Accept for you), and the file form that works in PowerShell:
```
$ curl -s -w ' [HTTP %{http_code}]\n' --json '{"username":"lab-user","password":"lab-password"}' http://127.0.0.1:5050/login
{"status":"authenticated","token":"demo-token-not-a-real-secret"}
 [HTTP 200]
$ curl -s -w ' [HTTP %{http_code}]\n' --json '{"username":"lab-user","password":"nope"}' http://127.0.0.1:5050/login
{"error":"Invalid username or password."}
 [HTTP 401]
$ curl -s -X POST -H 'Content-Type: application/json' -d @body.json http://127.0.0.1:5050/login     # body.json holds the JSON
```

### Redirects, fake hostnames, and what the server sees (ran)
```
$ curl -sI http://127.0.0.1:5050/redirect | grep -iE '^(HTTP|location)'
HTTP/1.1 302 FOUND
Location: /health
$ curl -sIL http://127.0.0.1:5050/redirect | grep -iE '^HTTP'      # -L follows it
HTTP/1.1 302 FOUND
HTTP/1.1 200 OK
$ curl -si --resolve lab.test:5050:127.0.0.1 http://lab.test:5050/health | head -1     # no DNS needed
HTTP/1.1 200 OK
$ curl -s -H 'X-Demo: 1' http://127.0.0.1:5050/headers
{"Accept":"*/*","Host":"127.0.0.1:5050","User-Agent":"curl/8.5.0","X-Demo":"1"}
```

---

## 6. Header analysis (what AppSec reviewers actually read)

### Cookies (ran)
```
$ curl -si http://127.0.0.1:5050/set-cookie | grep -iE '^(HTTP|set-cookie)'
Set-Cookie: session_demo=abc123; Expires=...; Max-Age=3600; HttpOnly; Path=/; SameSite=Lax
Set-Cookie: tracker=1; Path=/
```
- `HttpOnly`: page JavaScript can't read the cookie (limits what XSS can steal).
- `SameSite=Lax`: the browser doesn't send it on most cross-site requests (limits CSRF).
- `Secure`: only sent over HTTPS. The lab runs plain HTTP so neither cookie has it.
- `Max-Age`/`Expires`: lifetime. `tracker` has none of these protections.

Cookie jar round trip: `curl -c jar.txt URL` saves cookies, `curl -b jar.txt URL` sends them back
(**ran**: the server then saw `Cookie: session_demo=abc123; tracker=1`). A jar line starting
`#HttpOnly_` is curl marking an HttpOnly cookie.

### Security headers: `/health` vs `/hardened` (ran, `diff` of sorted headers)
```
> Cache-Control: no-store
> Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
> Referrer-Policy: no-referrer
> X-Content-Type-Options: nosniff
> X-Frame-Options: DENY
```
Everything with `>` is on `/hardened` but missing from `/health`. Also note
`Server: Werkzeug/3.1.9 Python/3.13.18` on every response: **version disclosure** tells an attacker exactly which
software to look up. It's the lab's server, but your Flask app does the same.

---

## 7. Missions (do these yourself; answers at the bottom)

1. **Find it blind.** Start the lab, then in another terminal find the PID listening on 5050 *without* reading the
   banner. Prove it with `/health`'s `pid`. *Done when the two PIDs match.*
2. **Collision.** Start a second copy on the same port, read the error, find the owner, stop the first, confirm the port is free.
3. **Bind comparison.** Reproduce the 127.0.0.1 vs `*` listing from section 2 (empty folder, kill both after). Write one
   sentence on why `0.0.0.0` + debug mode is dangerous.
4. **Traffic and counts.** Send 20+ requests (a shell `for` loop; include some wrong paths). Count the log by status and by path.
   *Done when your counts add up to `wc -l lab.log`.*
5. **Brute-force trace.** Send 6 wrong logins. Find them in the log with `grep`/`awk`. What pattern would a rate-limit alert watch for?
6. **Content-Type.** Reproduce the 400 on `/echo`, then fix it two ways (`-H`, and `--json`).
7. **Header review.** Diff `/health` against `/hardened`. For each of the 5 missing headers, say what attack or leak it reduces.
8. **Cookie review.** Which cookie from `/set-cookie` is weak and why? Then run your own `day-2` app **safely**
   (`python -m flask --app app run --host 127.0.0.1 --port 3000`), log in with `curl -i` (JSON), and read *its* `Set-Cookie`.
   Is `SameSite` there? `Secure`? Screenshot or paste the header: it's evidence for your Day 5 finding 8.
9. **Timing.** Compare `/health` with `/slow?sec=2` using `-w`. Which number is "connect" and which is "total"?
10. **Network facts.** Find your IP, default gateway and DNS server (section 4). Then call the lab through the fake name
    `lab.test` with `--resolve`. What did `--resolve` replace?

## Answer key (open after you've tried)

- **3.** With `0.0.0.0` anyone on the same network can reach the app, and Werkzeug's debugger can execute code
  from a browser if reached. Loopback keeps the app reachable only from the same machine.
- **5.** Many `POST /login 401` lines from the same IP in a short window. Alert on N failures per IP or per username per minute.
- **6.** `curl -d` defaults to form encoding. Use `-H 'Content-Type: application/json'` or `--json`.
- **7.** `X-Content-Type-Options: nosniff`: stops the browser guessing MIME types. `X-Frame-Options` / CSP `frame-ancestors`: clickjacking.
  `Content-Security-Policy`: limits what injected script can do. `Referrer-Policy`: stops leaking full URLs to other sites.
  `Cache-Control: no-store`: sensitive responses aren't cached.
- **8.** `tracker` is weak (no HttpOnly, SameSite or lifetime). Flask's session cookie should show `HttpOnly` (Flask default) but,
  per your app's config, no `SameSite` and no `Secure`.
- **9.** `connect` is the TCP handshake (about 0.0001 s locally); `total` includes the server's work (about 2.0 s for `/slow?sec=2`).
- **10.** `--resolve` replaces the DNS lookup: curl connected to 127.0.0.1 directly while sending `Host: lab.test:5050`.

## Day 3 report prompts
Done: which missions. Learned: one thing about ports, one about logs, one about headers. Blocked: anything that needed
Linux and you only had Windows. Next: Day 4 (web mechanics and state), plus the Day 5 evidence you collected (missions 3 and 8).

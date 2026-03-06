# AsynScan 🔍
> Fast, lightweight async TCP port scanner built with Python asyncio

```
╔═══════════════════════════════════════╗
║      ASYNSCAN PORT SCANNER v1.0       ║
║      github.com/lokesh32t/AsynScan    ║
╚═══════════════════════════════════════╝
```

---

## Features

- ⚡ **Async scanning** — scans hundreds of ports concurrently using `asyncio`
- 🎯 **Live results** — open ports print instantly as they're discovered, no waiting
- 🔍 **Banner grabbing** — grabs service banners from HTTP, SSH, FTP, SMTP and more
- 🗂️ **Flexible port selection** — single ports, ranges, top 100/1000, or all 65535
- 💾 **JSON export** — save results to a file for later analysis
- 🎨 **Rich output** — colored terminal output via `rich`

---

## Installation

**Clone the repo:**
```bash
git clone https://github.com/lokesh32t/AsynScan.git
cd AsynScan
```

**Install dependencies:**
```bash
pip install rich
```

---

## Usage

```bash
python AsynScan.py <target> [options]
```

### Examples

```bash
# Scan default common ports
python AsynScan.py 192.168.1.1

# Scan specific ports
python AsynScan.py example.com -p 80,443,8080

# Scan a port range
python AsynScan.py 10.0.0.1 -p 1-1024

# Scan top 100 common ports
python AsynScan.py 192.168.1.1 --top100

# Scan top 1000 ports with custom timeout and concurrency
python AsynScan.py 10.0.0.1 --top1000 --timeout 2 -c 200

# Full scan all 65535 ports
python AsynScan.py 192.168.1.1 --full

# Save results to JSON
python AsynScan.py 192.168.1.1 -o results.json

# Verbose mode (show closed/filtered ports too)
python AsynScan.py 192.168.1.1 -v
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Host or IP to scan | required |
| `-p`, `--ports` | Ports to scan e.g. `80,443,1000-2000` | common ports |
| `--top100` | Scan top 100 common ports | — |
| `--top1000` | Scan ports 1–1000 | — |
| `--full` | Scan all 65535 ports | — |
| `-t`, `--timeout` | Timeout per port in seconds | `1.0` |
| `-c`, `--concurrency` | Max concurrent connections | `500` |
| `--no-banner` | Disable banner grabbing | — |
| `-v`, `--verbose` | Show closed and filtered ports too | — |
| `-o`, `--output` | Save results to JSON file | — |

---

## Sample Output

```
  Target  : scanme.nmap.org (45.33.32.156)
  Ports   : 40 ports
  Timeout : 1.0s  |  Concurrency: 500
────────────────────────────────────────────────────────────
  [OPEN]      22/tcp  SSH              (12.4ms) | SSH-2.0-OpenSSH_6.6.1p1
  [OPEN]      80/tcp  HTTP             (8.1ms)
  [OPEN]   31337/tcp  unknown          (9.3ms)
────────────────────────────────────────────────────────────
  Open ports: 3/40
```

---

## Supported Services (Banner Grab)

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 8080 | HTTP-Alt |

---

## Requirements

- Python 3.8+
- `rich` library

---

## Disclaimer

> This tool is intended for **authorized testing and educational purposes only**.
> Do not scan systems you do not have explicit permission to test.
> The author is not responsible for any misuse or damage caused by this tool.

---

## Author

**lokesh32t** — [github.com/lokesh32t](https://github.com/lokesh32t)

---

## License

MIT License — free to use, modify, and distribute.

#!/usr/bin/env python3
"""
Web & Port Scanner - Linux Tool
Scans hosts for open TCP ports and gathers web information.
"""

import socket
import argparse
import sys
import threading
from queue import Queue
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def cyan(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLOR else text


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 27017
]

SERVICE_NAMES = {
    21: "FTP",       22: "SSH",      23: "Telnet",  25: "SMTP",
    53: "DNS",       80: "HTTP",     110: "POP3",   111: "RPCbind",
    135: "MSRPC",   139: "NetBIOS", 143: "IMAP",   443: "HTTPS",
    445: "SMB",     993: "IMAPS",   995: "POP3S",  1723: "PPTP",
    3306: "MySQL",  3389: "RDP",    5900: "VNC",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt", 27017: "MongoDB"
}

open_ports = []
lock = threading.Lock()


def grab_banner(ip, port, timeout):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8888):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="replace").strip()
        s.close()
        return banner[:120] if banner else None
    except Exception:
        return None


def scan_port(ip, port, timeout, grab_banners):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            service = SERVICE_NAMES.get(port, "Unknown")
            banner = None
            if grab_banners:
                banner = grab_banner(ip, port, timeout)
            with lock:
                open_ports.append((port, service, banner))
                banner_str = f" | {yellow(banner)}" if banner else ""
                print(f"  {green('[OPEN]')} Port {cyan(str(port)):<6} {service:<12}{banner_str}")
    except Exception:
        pass


def worker(ip, timeout, grab_banners, queue):
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, timeout, grab_banners)
        queue.task_done()


def run_scan(ip, ports, timeout, num_threads, grab_banners):
    global open_ports
    open_ports = []
    q = Queue()
    for p in ports:
        q.put(p)
    for _ in range(min(num_threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, timeout, grab_banners, q))
        t.daemon = True
        t.start()
    q.join()
    return sorted(open_ports, key=lambda x: x[0])


def get_web_info(host):
    if not HAS_REQUESTS:
        print(red("[!] 'requests' not installed. Run: pip install requests"))
        return
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(url, timeout=5, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"},
                                allow_redirects=True)
            print(f"\n{cyan('-- Web Info')} ({url}) {'--' * 15}")
            print(f"  Status Code : {green(str(resp.status_code))}")
            print(f"  Final URL   : {resp.url}")
            print(f"  Server      : {yellow(resp.headers.get('Server', 'N/A'))}")
            print(f"  X-Powered-By: {yellow(resp.headers.get('X-Powered-By', 'N/A'))}")
            content_type = resp.headers.get("Content-Type", "N/A")
            print(f"  Content-Type: {content_type}")
            if "text/html" in content_type:
                import re
                match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    print(f"  Page Title  : {match.group(1).strip()[:80]}")
            break
        except requests.exceptions.SSLError:
            continue
        except Exception as e:
            print(red(f"  [!] Could not connect via {scheme}: {e}"))


def parse_ports(port_arg):
    if port_arg is None:
        return COMMON_PORTS
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(red(f"[!] Cannot resolve host: {target}"))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Web & Port Scanner - Linux Tool")
    parser.add_argument("-t", "--target", required=True, help="Target host (IP or domain)")
    parser.add_argument("-p", "--ports", default=None,
                        help="Ports: range (1-1024), list (22,80,443), or omit for common ports")
    parser.add_argument("--web", action="store_true", help="Fetch HTTP/HTTPS web info")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--threads", type=int, default=100, help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    target = args.target
    ip = resolve_host(target)
    ports = parse_ports(args.ports)

    print(cyan("=" * 55))
    print(cyan("  Web & Port Scanner"))
    print(cyan("=" * 55))
    print(f"  Target  : {yellow(target)} ({ip})")
    print(f"  Ports   : {len(ports)} port(s) to scan")
    print(f"  Threads : {args.threads}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(cyan("-" * 55))

    results = run_scan(ip, ports, args.timeout, args.threads, args.banner)

    print(cyan("-" * 55))
    print(f"  Scan complete. {green(str(len(results)))} open port(s) found.")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if args.web:
        get_web_info(target)

    print(cyan("=" * 55))


if __name__ == "__main__":
    main()

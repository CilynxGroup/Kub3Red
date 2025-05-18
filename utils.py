import os
import sys
import socket
import subprocess
import tempfile
from pathlib import Path

try:
    from rich.console import Console
    from rich.text import Text
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)
try:
    from termcolor import colored
except ImportError:
    print("[!] pip install termcolor")
    sys.exit(1)

C = Console()

def print_header(msg):
    print("\n" + "=" * 80)
    print(colored(msg, 'cyan', attrs=['bold']))
    print("=" * 80)

def print_good(msg): print(colored(msg, 'green'))
def print_warn(msg): print(colored(msg, 'yellow'))
def print_fail(msg): print(colored(msg, 'red'))

def run(cmd: str, silent=False) -> str:
    proc = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if not silent:
        if proc.stdout:
            C.print(Text(proc.stdout.rstrip(), style="green"), markup=False)
        if proc.stderr:
            C.print(proc.stderr.rstrip(), style="yellow")
    return proc.stdout.rstrip()
def print_logo():
    try:
        import pyfiglet
        logo = pyfiglet.figlet_format("Kub3Red", font="slant")
        print("\033[1;36m" + logo + "\033[0m")  # Cyan text
        print("\033[1;31mProfessional Kubernetes Red Team & Exploitation Toolkit (multi-cloud)\033[0m\n")
    except ImportError:
        print("="*60)
        print("           Kub3Red - Kubernetes Red Team Toolkit")
        print("="*60)

def yaml_apply(yaml: str):
    tf = tempfile.NamedTemporaryFile("w", delete=False)
    tf.write(yaml)
    tf.close()
    run(f"kubectl apply -f {tf.name}", silent=True)
    Path(tf.name).unlink(missing_ok=True)

def yaml_delete(kind: str, name: str, namespace: str = "default"):
    run(f"kubectl delete {kind} {name} -n {namespace} --ignore-not-found=true", silent=True)

def output_csv(rows, csvwriter):
    for row in rows:
        csvwriter.writerow(row)
    csvwriter.writerow([])

def try_grab_banner(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in [80, 8080, 8000, 8443, 443]:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = sock.recv(1024)
                return banner.decode(errors="ignore")[:80]
            elif port == 22:
                banner = sock.recv(1024)
                return banner.decode(errors="ignore")[:80]
            else:
                banner = sock.recv(1024)
                return banner.decode(errors="ignore")[:80]
    except Exception:
        return ""

def scan_ports(ips, ports):
    results = []
    for ip in ips:
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=1.5) as sock:
                    banner = try_grab_banner(ip, port)
                    results.append((ip, port, "open", banner.strip()))
            except Exception:
                results.append((ip, port, "closed", ""))
    return results

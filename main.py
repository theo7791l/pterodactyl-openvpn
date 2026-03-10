#!/usr/bin/env python3
"""
main.py - VPN WireGuard 100% userspace dans /home/container
Zero apt, zero sudo, zero /dev/net/tun requis.
Utilise boringtun (binaire portable statique).
"""

import os
import sys
import time
import signal
import subprocess
import urllib.request
import stat
import socket

from config import (
    VPN_PORT, WORKDIR, WG_CONF,
    SERVER_PRIVKEY_FILE, SERVER_PUBKEY_FILE,
    CLIENT_PRIVKEY_FILE, CLIENT_PUBKEY_FILE,
    BORINGTUN_BIN, KEYS_DIR, CLIENTS_DIR, CONF_DIR
)

# URL du binaire boringtun statique (WireGuard userspace, zero dep)
BORINGTUN_URL = "https://github.com/cloudflare/boringtun/releases/download/boringtun-cli-v0.5.2/boringtun-cli-aarch64-unknown-linux-musl.tar.gz"
BORINGTUN_URL_AMD64 = "https://github.com/cloudflare/boringtun/releases/download/boringtun-cli-v0.5.2/boringtun-cli-x86_64-unknown-linux-musl.tar.gz"

# URL wireguard-go statique
WG_GO_URL = "https://github.com/WireGuard/wireguard-go/releases/download/0.0.20230223/wireguard-go-linux-amd64"
WG_GO_BIN = f"{WORKDIR}/wireguard-go"

vpn_proc = None


def run(cmd, check=True, capture=False, input_data=None, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    r = subprocess.run(
        cmd, shell=isinstance(cmd, str),
        capture_output=capture, text=True,
        input=input_data, env=e
    )
    if check and r.returncode != 0:
        print(f"[!] Erreur ({r.returncode}): {cmd}")
        if capture and r.stderr:
            print(r.stderr.strip())
        sys.exit(r.returncode)
    return r


def detect_arch():
    r = subprocess.run("uname -m", shell=True, capture_output=True, text=True)
    return r.stdout.strip()


def download_wg_go():
    """Telecharge wireguard-go statique dans /home/container."""
    if os.path.isfile(WG_GO_BIN) and os.access(WG_GO_BIN, os.X_OK):
        print("[OK] wireguard-go deja present.")
        return
    print(f"[~] Telechargement de wireguard-go...")
    urllib.request.urlretrieve(WG_GO_URL, WG_GO_BIN)
    os.chmod(WG_GO_BIN, os.stat(WG_GO_BIN).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print("[OK] wireguard-go telecharge.")


def wg_genkey():
    """Genere une cle privee WireGuard via Python pur (cryptography)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes = priv.public_key().public_bytes_raw()
        return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()
    except ImportError:
        print("[!] Le package 'cryptography' est requis. Ajout dans requirements.txt.")
        sys.exit(1)


def generate_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.isfile(SERVER_PRIVKEY_FILE):
        print("[OK] Cles deja generees.")
        return
    print("[~] Generation des cles WireGuard (Python pur)...")
    srv_priv, srv_pub = wg_genkey()
    cli_priv, cli_pub = wg_genkey()
    for path, content in [
        (SERVER_PRIVKEY_FILE, srv_priv),
        (SERVER_PUBKEY_FILE,  srv_pub),
        (CLIENT_PRIVKEY_FILE, cli_priv),
        (CLIENT_PUBKEY_FILE,  cli_pub),
    ]:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o600)
    print("[OK] Cles generees.")


def read(path):
    with open(path) as f:
        return f.read().strip()


def detect_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            ip = r.read().decode().strip()
            print(f"[OK] IP publique : {ip}")
            return ip
    except Exception:
        print("[!] Impossible de detecter l'IP publique.")
        sys.exit(1)


def write_server_conf():
    os.makedirs(CONF_DIR, exist_ok=True)
    if os.path.isfile(WG_CONF):
        print("[OK] Config serveur deja presente.")
        return
    srv_priv = read(SERVER_PRIVKEY_FILE)
    cli_pub  = read(CLIENT_PUBKEY_FILE)
    conf = f"[Interface]\nPrivateKey = {srv_priv}\nListenPort = {VPN_PORT}\n\n[Peer]\nPublicKey = {cli_pub}\nAllowedIPs = 10.8.0.2/32\n"
    with open(WG_CONF, "w") as f:
        f.write(conf)
    os.chmod(WG_CONF, 0o600)
    print(f"[OK] Config serveur ecrite : {WG_CONF}")


def write_client_conf(server_ip):
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    out = f"{CLIENTS_DIR}/client1.conf"
    if os.path.isfile(out):
        print(f"[OK] Config client deja presente : {out}")
        return
    cli_priv = read(CLIENT_PRIVKEY_FILE)
    srv_pub  = read(SERVER_PUBKEY_FILE)
    conf = (
        f"[Interface]\n"
        f"PrivateKey = {cli_priv}\n"
        f"Address = 10.8.0.2/24\n"
        f"DNS = 1.1.1.1, 8.8.8.8\n\n"
        f"[Peer]\n"
        f"PublicKey = {srv_pub}\n"
        f"Endpoint = {server_ip}:{VPN_PORT}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
    )
    with open(out, "w") as f:
        f.write(conf)
    print(f"[OK] Config client generee : {out}")
    print(f"     --> Telecharge clients/client1.conf depuis le panel et importe dans WireGuard.")


def setup():
    print("=== Setup WireGuard userspace (zero apt/sudo) ===")
    download_wg_go()
    generate_keys()
    server_ip = detect_ip()
    write_server_conf()
    write_client_conf(server_ip)
    print("=== Setup termine ! ===")


def start_vpn():
    print(f"[~] Demarrage wireguard-go sur port {VPN_PORT} UDP...")
    env = os.environ.copy()
    env["WG_PROCESS_FOREGROUND"] = "1"
    env["WG_TUN_IMPL"] = "userspace"  # force userspace, pas de TUN kernel
    proc = subprocess.Popen(
        [WG_GO_BIN, f"utun{os.getpid()}"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    time.sleep(2)
    if proc.poll() is not None:
        out, _ = proc.communicate()
        print(f"[!] wireguard-go a plante au demarrage : {out}")
        sys.exit(1)

    # Configure l'interface via le socket UAPI de wireguard-go
    uapi_sock = f"/tmp/wireguard/utun{os.getpid()}.sock"
    time.sleep(1)
    srv_priv = read(SERVER_PRIVKEY_FILE)
    cli_pub  = read(CLIENT_PUBKEY_FILE)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(uapi_sock)
            import base64
            priv_hex = base64.b64decode(srv_priv).hex()
            pub_hex  = base64.b64decode(cli_pub).hex()
            cmd = (
                f"set=1\n"
                f"private_key={priv_hex}\n"
                f"listen_port={VPN_PORT}\n"
                f"replace_peers=true\n"
                f"public_key={pub_hex}\n"
                f"allowed_ip=10.8.0.2/32\n"
                f"\n"
            )
            s.sendall(cmd.encode())
            resp = s.recv(4096).decode()
            if "errno=0" not in resp:
                print(f"[!] Erreur UAPI : {resp}")
                sys.exit(1)
        print(f"[OK] WireGuard configure et actif sur le port {VPN_PORT} UDP.")
    except Exception as e:
        print(f"[!] Erreur configuration UAPI : {e}")
        proc.terminate()
        sys.exit(1)

    return proc


def handle_signal(signum, frame):
    print(f"\n[~] Arret...")
    if vpn_proc and vpn_proc.poll() is None:
        vpn_proc.terminate()
        vpn_proc.wait()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if not os.path.isfile(WG_CONF):
        setup()

    vpn_proc = start_vpn()

    while True:
        ret = vpn_proc.wait()
        print(f"[!] VPN arrete (code {ret}). Redemarrage dans 5s...")
        time.sleep(5)
        vpn_proc = start_vpn()

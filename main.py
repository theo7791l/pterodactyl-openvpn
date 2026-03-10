#!/usr/bin/env python3
"""
main.py - VPN WireGuard 100% userspace dans /home/container
Zero apt, zero sudo, zero /dev/net/tun requis.
"""

import os
import sys
import time
import signal
import subprocess
import urllib.request
import tarfile
import stat
import socket
import base64

from config import (
    VPN_PORT, WORKDIR, WG_CONF,
    SERVER_PRIVKEY_FILE, SERVER_PUBKEY_FILE,
    CLIENT_PRIVKEY_FILE, CLIENT_PUBKEY_FILE,
    KEYS_DIR, CLIENTS_DIR, CONF_DIR
)

# Binaire wireguard-go statique (P3TERX builder)
WG_GO_URL = "https://github.com/P3TERX/wireguard-go-builder/releases/download/0.0.20231212/wireguard-go-linux-amd64.tar.gz"
WG_GO_TGZ = f"{WORKDIR}/wireguard-go.tar.gz"
WG_GO_BIN = f"{WORKDIR}/wireguard-go"

vpn_proc = None


def download_wg_go():
    if os.path.isfile(WG_GO_BIN) and os.access(WG_GO_BIN, os.X_OK):
        print("[OK] wireguard-go deja present.")
        return
    print("[~] Telechargement de wireguard-go...")
    urllib.request.urlretrieve(WG_GO_URL, WG_GO_TGZ)
    with tarfile.open(WG_GO_TGZ, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("wireguard-go") or member.name == "wireguard-go":
                member.name = os.path.basename(member.name)
                tar.extract(member, WORKDIR)
                break
    if os.path.isfile(WG_GO_TGZ):
        os.remove(WG_GO_TGZ)
    os.chmod(WG_GO_BIN, os.stat(WG_GO_BIN).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print("[OK] wireguard-go telecharge et extrait.")


def wg_genkey():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
    pub_b64  = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv_b64, pub_b64


def generate_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.isfile(SERVER_PRIVKEY_FILE):
        print("[OK] Cles deja generees.")
        return
    print("[~] Generation des cles WireGuard...")
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
    conf = (
        f"[Interface]\n"
        f"PrivateKey = {srv_priv}\n"
        f"ListenPort = {VPN_PORT}\n\n"
        f"[Peer]\n"
        f"PublicKey = {cli_pub}\n"
        f"AllowedIPs = 10.8.0.2/32\n"
    )
    with open(WG_CONF, "w") as f:
        f.write(conf)
    os.chmod(WG_CONF, 0o600)
    print(f"[OK] Config serveur : {WG_CONF}")


def write_client_conf(server_ip):
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    out = f"{CLIENTS_DIR}/client1.conf"
    if os.path.isfile(out):
        print(f"[OK] Config client deja presente.")
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
    print(f"[OK] Config client : {out}")
    print(f"     --> Telecharge clients/client1.conf depuis le panel et importe dans WireGuard.")


def setup():
    print("=== Setup WireGuard userspace (zero apt/sudo) ===")
    download_wg_go()
    generate_keys()
    server_ip = detect_ip()
    write_server_conf()
    write_client_conf(server_ip)
    print("=== Setup termine ! ===")


def configure_via_uapi(srv_priv, cli_pub):
    """Configure wireguard-go via le socket UAPI Unix."""
    uapi_sock = f"/tmp/wireguard/utun{os.getpid()}.sock"
    # Attendre que le socket soit disponible
    for _ in range(10):
        if os.path.exists(uapi_sock):
            break
        time.sleep(0.5)
    else:
        raise FileNotFoundError(f"Socket UAPI introuvable : {uapi_sock}")

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
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(uapi_sock)
        s.sendall(cmd.encode())
        resp = s.recv(4096).decode()
    if "errno=0" not in resp:
        raise RuntimeError(f"Erreur UAPI : {resp.strip()}")
    print(f"[OK] WireGuard actif sur le port {VPN_PORT} UDP.")


def start_vpn():
    print(f"[~] Demarrage wireguard-go...")
    env = os.environ.copy()
    env["WG_PROCESS_FOREGROUND"] = "1"
    iface = f"utun{os.getpid()}"
    proc = subprocess.Popen(
        [WG_GO_BIN, "-f", iface],
        env=env,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    time.sleep(2)
    if proc.poll() is not None:
        print("[!] wireguard-go a plante au demarrage.")
        sys.exit(1)

    try:
        configure_via_uapi(read(SERVER_PRIVKEY_FILE), read(CLIENT_PUBKEY_FILE))
    except Exception as e:
        print(f"[!] Erreur UAPI : {e}")
        proc.terminate()
        sys.exit(1)

    return proc


def handle_signal(signum, frame):
    print("\n[~] Arret...")
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

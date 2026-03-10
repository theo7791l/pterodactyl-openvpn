#!/usr/bin/env python3
"""
main.py - VPN WireGuard via boringtun (Cloudflare)
100% userspace, zero /dev/net/tun, zero apt, zero sudo.
boringtun agit comme un RELAIS UDP : il ecoute sur VPN_PORT
et fait le chiffrement/dechiffrement WireGuard en espace utilisateur.
"""

import os
import sys
import time
import signal
import subprocess
import urllib.request
import tarfile
import stat
import base64

from config import (
    VPN_PORT, WORKDIR, WG_CONF,
    SERVER_PRIVKEY_FILE, SERVER_PUBKEY_FILE,
    CLIENT_PRIVKEY_FILE, CLIENT_PUBKEY_FILE,
    KEYS_DIR, CLIENTS_DIR, CONF_DIR
)

# boringtun-cli : binaire statique musl (zero dep, zero TUN kernel)
BORINGTUN_URL = "https://github.com/cloudflare/boringtun/releases/download/boringtun-cli-v0.5.2/boringtun-cli-x86_64-unknown-linux-musl.tar.gz"
BORINGTUN_TGZ = f"{WORKDIR}/boringtun.tar.gz"
BORINGTUN_BIN = f"{WORKDIR}/boringtun-cli"

vpn_proc = None


def download_boringtun():
    if os.path.isfile(BORINGTUN_BIN) and os.access(BORINGTUN_BIN, os.X_OK):
        print("[OK] boringtun-cli deja present.")
        return
    print("[~] Telechargement de boringtun-cli (Cloudflare, musl statique)...")
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    with opener.open(BORINGTUN_URL, timeout=60) as resp, open(BORINGTUN_TGZ, "wb") as f:
        f.write(resp.read())
    print("[OK] Telechargement OK, extraction...")
    with tarfile.open(BORINGTUN_TGZ, "r:gz") as tar:
        extracted = False
        for member in tar.getmembers():
            print(f"    membre : {member.name}")
            if os.path.basename(member.name) in ("boringtun-cli", "boringtun"):
                member.name = os.path.basename(member.name)
                tar.extract(member, WORKDIR)
                extracted = True
                # renommer en boringtun-cli si besoin
                extracted_path = f"{WORKDIR}/{os.path.basename(member.name)}"
                if not os.path.isfile(BORINGTUN_BIN):
                    os.rename(extracted_path, BORINGTUN_BIN)
                break
        if not extracted:
            print("[!] Binaire boringtun introuvable dans l'archive.")
            sys.exit(1)
    if os.path.isfile(BORINGTUN_TGZ):
        os.remove(BORINGTUN_TGZ)
    os.chmod(BORINGTUN_BIN, os.stat(BORINGTUN_BIN).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print("[OK] boringtun-cli pret.")


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
        print("[OK] Config client deja presente.")
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
    print("     --> Telecharge clients/client1.conf depuis le panel et importe dans WireGuard.")


def setup():
    print("=== Setup VPN boringtun (zero apt/sudo/TUN) ===")
    download_boringtun()
    generate_keys()
    server_ip = detect_ip()
    write_server_conf()
    write_client_conf(server_ip)
    print("=== Setup termine ! ===")


def start_vpn():
    """
    Lance boringtun en mode foreground.
    boringtun-cli <iface> --foreground
    Il lit la config depuis les variables d'env WG_* ou via UAPI socket.
    On passe la cle privee via stdin/env et le port via --listen-port.
    """
    print(f"[~] Demarrage boringtun sur port {VPN_PORT} UDP...")
    srv_priv = read(SERVER_PRIVKEY_FILE)
    cli_pub  = read(CLIENT_PUBKEY_FILE)

    env = os.environ.copy()
    env["WG_QUICK_USERSPACE_IMPLEMENTATION"] = BORINGTUN_BIN
    env["LOG_LEVEL"] = "info"

    # boringtun-cli <private_key> <peer_public_key> --foreground --listen-port <port>
    cmd = [
        BORINGTUN_BIN,
        srv_priv,       # cle privee du serveur
        cli_pub,        # cle publique du peer (client)
        "--foreground",
        "--listen-port", str(VPN_PORT),
        "--log",
    ]

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    time.sleep(2)
    if proc.poll() is not None:
        print("[!] boringtun a plante au demarrage.")
        sys.exit(1)
    print(f"[OK] boringtun actif sur le port {VPN_PORT} UDP (PID {proc.pid}).")
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

#!/usr/bin/env python3
"""
main.py – Point d'entrée Pterodactyl
Installe wireguard-go si absent, configure et lance WireGuard en userspace.
"""

import os
import subprocess
import sys
import time
import signal
import urllib.request
import tarfile
import stat

from config import VPN_PORT, VPN_SUBNET_CLIENT, WORKDIR, WG_CONF, SERVER_PRIVKEY_FILE, SERVER_PUBKEY_FILE, CLIENT_PRIVKEY_FILE, CLIENT_PUBKEY_FILE

WG_GO_URL = "https://github.com/WireGuard/wireguard-go/releases/download/0.0.20230223/wireguard-go-linux-amd64"
WG_GO_BIN = f"{WORKDIR}/wireguard-go"
WG_QUICK_WORKAROUND = True  # utilise wg + ip en userspace

wg_proc = None


def run(cmd, check=True, capture=False, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True, env=e)
    if check and r.returncode != 0:
        print(f"[!] Erreur ({r.returncode}): {cmd}")
        if capture:
            print(r.stderr)
        sys.exit(r.returncode)
    return r


def install_deps():
    print("[~] Installation des dépendances (wireguard-tools, iproute2)...")
    run("apt-get update -y -qq")
    run("apt-get install -y -qq wireguard-tools iproute2 iptables")
    print("[✓] Dépendances installées.")


def download_wireguard_go():
    if os.path.isfile(WG_GO_BIN):
        print("[✓] wireguard-go déjà présent.")
        return
    print("[~] Téléchargement de wireguard-go (userspace, pas besoin de TUN kernel)...")
    urllib.request.urlretrieve(WG_GO_URL, WG_GO_BIN)
    os.chmod(WG_GO_BIN, os.stat(WG_GO_BIN).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print("[✓] wireguard-go téléchargé.")


def genkey():
    r = subprocess.run("wg genkey", shell=True, capture_output=True, text=True)
    return r.stdout.strip()


def pubkey(privkey):
    r = subprocess.run("wg pubkey", shell=True, input=privkey, capture_output=True, text=True)
    return r.stdout.strip()


def generate_keys():
    os.makedirs(f"{WORKDIR}/keys", exist_ok=True)
    if os.path.isfile(SERVER_PRIVKEY_FILE):
        print("[✓] Clés déjà générées.")
        return
    print("[~] Génération des clés WireGuard...")
    srv_priv = genkey()
    srv_pub  = pubkey(srv_priv)
    cli_priv = genkey()
    cli_pub  = pubkey(cli_priv)
    for path, content in [
        (SERVER_PRIVKEY_FILE, srv_priv),
        (SERVER_PUBKEY_FILE,  srv_pub),
        (CLIENT_PRIVKEY_FILE, cli_priv),
        (CLIENT_PUBKEY_FILE,  cli_pub),
    ]:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o600)
    print("[✓] Clés générées.")


def read(path):
    with open(path) as f:
        return f.read().strip()


def detect_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        print("[!] Impossible de détecter l'IP publique.")
        sys.exit(1)


def write_server_conf():
    os.makedirs(f"{WORKDIR}/conf", exist_ok=True)
    if os.path.isfile(WG_CONF):
        print("[✓] Config serveur déjà présente.")
        return
    srv_priv = read(SERVER_PRIVKEY_FILE)
    cli_pub  = read(CLIENT_PUBKEY_FILE)
    conf = f"""[Interface]
PrivateKey = {srv_priv}
Address = 10.8.0.1/24
ListenPort = {VPN_PORT}

[Peer]
PublicKey = {cli_pub}
AllowedIPs = 10.8.0.2/32
"""
    with open(WG_CONF, "w") as f:
        f.write(conf)
    os.chmod(WG_CONF, 0o600)
    print(f"[✓] Config serveur écrite dans {WG_CONF}")


def write_client_conf(server_ip):
    os.makedirs(f"{WORKDIR}/clients", exist_ok=True)
    out = f"{WORKDIR}/clients/client1.conf"
    cli_priv = read(CLIENT_PRIVKEY_FILE)
    srv_pub  = read(SERVER_PUBKEY_FILE)
    conf = f"""[Interface]
PrivateKey = {cli_priv}
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {srv_pub}
Endpoint = {server_ip}:{VPN_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    with open(out, "w") as f:
        f.write(conf)
    print(f"[✓] Config client générée : {out}")
    print(f"    Importe ce fichier dans ton client WireGuard (Windows/Android/iOS).")


def setup():
    print("=== Setup WireGuard userspace ===")
    install_deps()
    download_wireguard_go()
    generate_keys()
    server_ip = detect_ip()
    write_server_conf()
    write_client_conf(server_ip)
    print("=== Setup terminé ! ===")


def start_wireguard():
    print("[~] Démarrage de wireguard-go en userspace...")
    env = os.environ.copy()
    env["WG_PROCESS_FOREGROUND"] = "1"
    proc = subprocess.Popen(
        [WG_GO_BIN, "utun"],
        env=env,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    time.sleep(2)
    # Applique la config
    run(f"wg setconf utun {WG_CONF}")
    run(f"ip addr add 10.8.0.1/24 dev utun")
    run(f"ip link set utun up")
    print(f"[✓] WireGuard actif sur le port {VPN_PORT} UDP.")
    return proc


def handle_signal(signum, frame):
    print(f"\n[~] Signal {signum} – arrêt...")
    if wg_proc and wg_proc.poll() is None:
        wg_proc.terminate()
        wg_proc.wait()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if not os.path.isfile(WG_CONF):
        setup()

    wg_proc = start_wireguard()

    while True:
        ret = wg_proc.wait()
        print(f"[!] WireGuard arrêté (code {ret}). Redémarrage dans 5s...")
        time.sleep(5)
        wg_proc = start_wireguard()

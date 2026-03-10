#!/usr/bin/env python3
"""
setup.py – Installation d'OpenVPN + génération PKI via easy-rsa
Lancé automatiquement par main.py si c'est le premier démarrage.
"""

import os
import subprocess
import sys
import urllib.request

from config import (
    VPN_PORT, VPN_PROTO, VPN_SUBNET, VPN_MASK,
    DNS1, DNS2, SERVER_IP, CERTDIR, CLIENTDIR, CONFDIR, SERVER_CONF, WORKDIR
)


def run(cmd, check=True, **kwargs):
    """Lance une commande shell et affiche la sortie en temps réel."""
    print(f"[+] {cmd}")
    result = subprocess.run(cmd, shell=True, **kwargs)
    if check and result.returncode != 0:
        print(f"[!] Erreur (code {result.returncode}) : {cmd}")
        sys.exit(result.returncode)
    return result


def install_openvpn():
    """Installe OpenVPN et easy-rsa si absents."""
    if subprocess.run("which openvpn", shell=True, capture_output=True).returncode == 0:
        print("[✓] OpenVPN déjà installé.")
        return
    print("[~] Installation d'OpenVPN + easy-rsa...")
    run("apt-get update -y")
    run("apt-get install -y openvpn easy-rsa")


def detect_server_ip():
    """Détecte l'IP publique du serveur si non définie dans config.py."""
    if SERVER_IP:
        return SERVER_IP
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            ip = r.read().decode().strip()
            print(f"[✓] IP publique détectée : {ip}")
            return ip
    except Exception:
        print("[!] Impossible de détecter l'IP publique. Renseigne SERVER_IP dans config.py.")
        sys.exit(1)


def generate_pki():
    """Génère la PKI (CA, clé serveur, DH, ta.key) avec easy-rsa."""
    easy_rsa_dir = "/usr/share/easy-rsa"
    if not os.path.isdir(easy_rsa_dir):
        print("[!] easy-rsa introuvable. Vérifiez l'installation.")
        sys.exit(1)

    os.makedirs(CERTDIR, exist_ok=True)

    pki_path = f"{CERTDIR}/pki"
    if os.path.isdir(pki_path):
        print("[✓] PKI déjà générée.")
        return

    env = os.environ.copy()
    env["EASYRSA_PKI"] = pki_path
    env["EASYRSA_BATCH"] = "1"
    env["EASYRSA_REQ_CN"] = "OpenVPN-CA"

    def easyrsa(args):
        run(f"{easy_rsa_dir}/easyrsa {args}", env=env)

    easyrsa("init-pki")
    easyrsa("build-ca nopass")
    easyrsa("gen-req server nopass")
    easyrsa("sign-req server server")
    easyrsa("gen-dh")
    run(f"openvpn --genkey secret {pki_path}/ta.key")
    print("[✓] PKI générée avec succès.")


def write_server_conf(server_ip):
    """Écrit le fichier server.conf OpenVPN."""
    os.makedirs(CONFDIR, exist_ok=True)
    pki_path = f"{CERTDIR}/pki"

    conf = f"""# Généré par setup.py
port {VPN_PORT}
proto {VPN_PROTO}
dev tun

ca   {pki_path}/ca.crt
cert {pki_path}/issued/server.crt
key  {pki_path}/private/server.key
dh   {pki_path}/dh.pem
tls-auth {pki_path}/ta.key 0

server {VPN_SUBNET} {VPN_MASK}
ifconfig-pool-persist {CONFDIR}/ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS {DNS1}"
push "dhcp-option DNS {DNS2}"

keepalive 10 120
cipher AES-256-GCM
auth SHA256
comp-lzo
user nobody
group nogroup
persist-key
persist-tun

status  {CONFDIR}/openvpn-status.log
log     {CONFDIR}/openvpn.log
verb 3
"""
    with open(SERVER_CONF, "w") as f:
        f.write(conf)
    print(f"[✓] server.conf écrit dans {SERVER_CONF}")


def enable_ip_forward():
    """Active le forwarding IP (nécessite les droits suffisants)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[✓] IP forwarding activé.")
    except PermissionError:
        print("[!] Impossible d'activer ip_forward (permissions insuffisantes). Peut être ignoré si déjà actif sur l'hôte.")


def generate_client_ovpn(server_ip):
    """Génère un fichier client.ovpn prêt à l'emploi."""
    os.makedirs(CLIENTDIR, exist_ok=True)
    pki_path = f"{CERTDIR}/pki"

    # Génération des certificats client si absents
    client_cert = f"{pki_path}/issued/client1.crt"
    if not os.path.isfile(client_cert):
        easy_rsa_dir = "/usr/share/easy-rsa"
        env = os.environ.copy()
        env["EASYRSA_PKI"] = pki_path
        env["EASYRSA_BATCH"] = "1"
        run(f"{easy_rsa_dir}/easyrsa gen-req client1 nopass", env=env)
        run(f"{easy_rsa_dir}/easyrsa sign-req client client1", env=env)

    def read(path):
        with open(path) as f:
            return f.read().strip()

    ca  = read(f"{pki_path}/ca.crt")
    crt = read(client_cert)
    key = read(f"{pki_path}/private/client1.key")
    ta  = read(f"{pki_path}/ta.key")

    ovpn = f"""client
dev tun
proto {VPN_PROTO}
remote {server_ip} {VPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
comp-lzo
verb 3
key-direction 1

<ca>
{ca}
</ca>

<cert>
{crt}
</cert>

<key>
{key}
</key>

<tls-auth>
{ta}
</tls-auth>
"""
    out = f"{CLIENTDIR}/client1.ovpn"
    with open(out, "w") as f:
        f.write(ovpn)
    print(f"[✓] Fichier client généré : {out}")


def setup():
    print("=== Setup OpenVPN – Pterodactyl ===")
    install_openvpn()
    server_ip = detect_server_ip()
    generate_pki()
    write_server_conf(server_ip)
    enable_ip_forward()
    generate_client_ovpn(server_ip)
    print("=== Setup terminé ! ===")


if __name__ == "__main__":
    setup()

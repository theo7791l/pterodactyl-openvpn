#!/usr/bin/env python3
"""
main.py - Proxy SOCKS5 chiffre (TLS) en Python pur
Zero binaire externe, zero /dev/net/tun, zero apt, zero sudo.
Tout tourne dans /home/container sur le port UDP/TCP configure.

Cote serveur : ecoute sur VPN_PORT en TLS
Cote client  : configure un proxy SOCKS5 dans ton navigateur/OS
               ou utilise Proxifier/SocksCap sur Windows
"""

import os
import sys
import ssl
import time
import socket
import signal
import threading
import subprocess
import ipaddress
from pathlib import Path

from config import VPN_PORT, WORKDIR, CERT_FILE, KEY_FILE, CLIENTS_DIR

vpn_running = True


# ─────────────────────────────────────────────
#  Generation du certificat TLS auto-signe
# ─────────────────────────────────────────────

def generate_cert():
    if Path(CERT_FILE).exists() and Path(KEY_FILE).exists():
        print("[OK] Certificat TLS deja present.")
        return
    print("[~] Generation du certificat TLS auto-signe...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"proxy-server"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        os.makedirs(os.path.dirname(CERT_FILE), exist_ok=True)
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(KEY_FILE, 0o600)
        print("[OK] Certificat TLS genere.")
    except Exception as e:
        print(f"[!] Erreur generation certificat : {e}")
        sys.exit(1)


def detect_ip():
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            ip = r.read().decode().strip()
            print(f"[OK] IP publique : {ip}")
            return ip
    except Exception:
        return "<IP_SERVEUR>"


def write_client_info(server_ip):
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    out = f"{CLIENTS_DIR}/connexion.txt"
    info = (
        f"=== Infos de connexion proxy ===\n"
        f"\n"
        f"Type    : SOCKS5 sur TLS\n"
        f"Serveur : {server_ip}\n"
        f"Port    : {VPN_PORT}\n"
        f"\n"
        f"=== Comment se connecter ===\n"
        f"\n"
        f"Option 1 - Proxifier / SocksCap (Windows) :\n"
        f"  Ajoute un serveur proxy : {server_ip}:{VPN_PORT} type SOCKS5\n"
        f"\n"
        f"Option 2 - Firefox :\n"
        f"  Parametres > Reseau > Proxy manuel\n"
        f"  Hote SOCKS : {server_ip}  Port : {VPN_PORT}  Type : SOCKS5\n"
        f"\n"
        f"Option 3 - curl (test) :\n"
        f"  curl --socks5 {server_ip}:{VPN_PORT} https://api.ipify.org\n"
        f"\n"
        f"Le certificat TLS auto-signe est dans : conf/cert.pem\n"
        f"Accepte-le dans ton client si demande.\n"
    )
    with open(out, "w") as f:
        f.write(info)
    print(f"[OK] Infos client ecrites : {out}")


# ─────────────────────────────────────────────
#  Serveur SOCKS5
# ─────────────────────────────────────────────

def socks5_handshake(client):
    """Handshake SOCKS5 (RFC 1928) sans authentification."""
    data = client.recv(262)
    if not data or data[0] != 0x05:
        return None, None
    # Reponse : pas d'auth
    client.sendall(b"\x05\x00")
    # Lire la requete
    data = client.recv(4)
    if len(data) < 4 or data[1] != 0x01:  # 0x01 = CONNECT
        client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        return None, None
    atyp = data[3]
    if atyp == 0x01:  # IPv4
        addr = socket.inet_ntoa(client.recv(4))
    elif atyp == 0x03:  # Domaine
        length = client.recv(1)[0]
        addr = client.recv(length).decode()
    elif atyp == 0x04:  # IPv6
        addr = str(ipaddress.IPv6Address(client.recv(16)))
    else:
        return None, None
    port = int.from_bytes(client.recv(2), "big")
    return addr, port


def relay(src, dst):
    """Relaie les donnees entre deux sockets."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


def handle_client(client_sock, addr):
    try:
        host, port = socks5_handshake(client_sock)
        if not host:
            client_sock.close()
            return
        # Connexion vers la destination
        remote = socket.create_connection((host, port), timeout=10)
        # Reponse succes SOCKS5
        client_sock.sendall(
            b"\x05\x00\x00\x01" +
            socket.inet_aton("0.0.0.0") +
            (0).to_bytes(2, "big")
        )
        # Relay bidirectionnel
        t = threading.Thread(target=relay, args=(remote, client_sock), daemon=True)
        t.start()
        relay(client_sock, remote)
    except Exception as e:
        try:
            client_sock.close()
        except Exception:
            pass


def start_server():
    generate_cert()
    server_ip = detect_ip()
    write_client_info(server_ip)

    # SSL context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind(("0.0.0.0", VPN_PORT))
    raw_sock.listen(50)

    server_sock = ctx.wrap_socket(raw_sock, server_side=True)
    print(f"[OK] Proxy SOCKS5+TLS en ecoute sur 0.0.0.0:{VPN_PORT}")
    print(f"     Consulte clients/connexion.txt pour les infos de connexion.")

    while vpn_running:
        try:
            client, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except ssl.SSLError:
            pass
        except Exception as e:
            if vpn_running:
                print(f"[!] Erreur acceptation : {e}")


def handle_signal(signum, frame):
    global vpn_running
    print("\n[~] Arret...")
    vpn_running = False
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    print("=== Proxy SOCKS5+TLS (zero TUN, zero apt, zero binaire) ===")
    start_server()

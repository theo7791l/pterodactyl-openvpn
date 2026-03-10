#!/usr/bin/env python3
"""
main.py - Proxy SOCKS5 pur en Python
Zero binaire, zero TUN, zero apt, zero sudo.
Compatible Firefox, Chrome, curl directement sans config speciale.
"""

import os
import sys
import socket
import signal
import threading
import ipaddress
import urllib.request

from config import VPN_PORT, WORKDIR, CLIENTS_DIR

server_running = True


def detect_ip():
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
        f"=== Proxy SOCKS5 - Infos de connexion ===\n\n"
        f"Serveur : {server_ip}\n"
        f"Port    : {VPN_PORT}\n"
        f"Type    : SOCKS5\n\n"
        f"=== Firefox ===\n"
        f"Parametres > Reseau > Config connexion\n"
        f"-> Configuration manuelle\n"
        f"-> Hote SOCKS : {server_ip}\n"
        f"-> Port       : {VPN_PORT}\n"
        f"-> SOCKS v5\n"
        f"-> Cocher : DNS via SOCKS5\n\n"
        f"=== Test curl ===\n"
        f"curl --socks5 {server_ip}:{VPN_PORT} https://api.ipify.org\n"
    )
    with open(out, "w") as f:
        f.write(info)
    print(f"[OK] Infos client : {out}")


def socks5_handshake(sock):
    """Handshake SOCKS5 RFC 1928 - sans authentification."""
    # 1. Greeting
    header = sock.recv(2)
    if len(header) < 2 or header[0] != 0x05:
        return None, None
    nmethods = header[1]
    sock.recv(nmethods)  # lire les methodes proposees
    sock.sendall(b"\x05\x00")  # repondre : pas d'auth

    # 2. Requete CONNECT
    req = b""
    while len(req) < 4:
        chunk = sock.recv(4 - len(req))
        if not chunk:
            return None, None
        req += chunk

    ver, cmd, rsv, atyp = req
    if ver != 0x05 or cmd != 0x01:  # 0x01 = CONNECT
        sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        return None, None

    if atyp == 0x01:  # IPv4
        addr = socket.inet_ntoa(sock.recv(4))
    elif atyp == 0x03:  # Nom de domaine
        length = sock.recv(1)[0]
        addr = sock.recv(length).decode("utf-8", errors="ignore")
    elif atyp == 0x04:  # IPv6
        addr = str(ipaddress.IPv6Address(sock.recv(16)))
    else:
        sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
        return None, None

    port = int.from_bytes(sock.recv(2), "big")
    return addr, port


def relay(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: s.close()
            except Exception: pass


def handle_client(client_sock):
    try:
        client_sock.settimeout(30)
        host, port = socks5_handshake(client_sock)
        if not host:
            client_sock.close()
            return

        # Connexion vers la destination
        try:
            remote = socket.create_connection((host, port), timeout=15)
        except Exception as e:
            # Connexion echouee -> repondre erreur SOCKS5
            client_sock.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            client_sock.close()
            return

        # Reponse succes
        client_sock.sendall(
            b"\x05\x00\x00\x01" +
            socket.inet_aton("0.0.0.0") +
            (0).to_bytes(2, "big")
        )

        client_sock.settimeout(None)
        remote.settimeout(None)

        # Relay bidirectionnel
        t = threading.Thread(target=relay, args=(remote, client_sock), daemon=True)
        t.start()
        relay(client_sock, remote)

    except Exception:
        try: client_sock.close()
        except Exception: pass


def start_server():
    server_ip = detect_ip()
    write_client_info(server_ip)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", VPN_PORT))
    srv.listen(100)
    srv.settimeout(1.0)

    print(f"[OK] Proxy SOCKS5 en ecoute sur 0.0.0.0:{VPN_PORT}")
    print(f"     Firefox : SOCKS5 -> {server_ip}:{VPN_PORT} + DNS via SOCKS5")

    while server_running:
        try:
            client, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if server_running:
                print(f"[!] {e}")


def handle_signal(signum, frame):
    global server_running
    print("\n[~] Arret...")
    server_running = False
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    print(f"=== Proxy SOCKS5 (zero TUN, zero apt, zero binaire) ===")
    start_server()

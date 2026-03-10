#!/usr/bin/env python3
"""
main.py – Point d'entrée Pterodactyl
Lance le setup si nécessaire, puis démarre OpenVPN et surveille le processus.
"""

import os
import subprocess
import sys
import time
import signal

from config import SERVER_CONF, CERTDIR


def check_tun():
    """Vérifie que /dev/net/tun est accessible."""
    if not os.path.exists("/dev/net/tun"):
        print("[!] ERREUR : /dev/net/tun est absent.")
        print("    Demande à l'admin du nœud Pterodactyl d'activer le device TUN pour ce conteneur.")
        sys.exit(1)
    print("[✓] /dev/net/tun disponible.")


def needs_setup():
    """Retourne True si la PKI ou la config n'existe pas encore."""
    return not os.path.isfile(SERVER_CONF)


def run_setup():
    """Lance setup.py."""
    print("[~] Premier démarrage – lancement du setup...")
    import setup
    setup.setup()


def start_openvpn():
    """Démarre OpenVPN et retourne le process."""
    print(f"[~] Démarrage d'OpenVPN avec {SERVER_CONF}...")
    proc = subprocess.Popen(
        ["openvpn", "--config", SERVER_CONF],
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    print(f"[✓] OpenVPN démarré (PID {proc.pid}).")
    return proc


def handle_signal(signum, frame):
    """Arrête proprement OpenVPN en cas de SIGTERM/SIGINT."""
    print(f"\n[~] Signal {signum} reçu – arrêt d'OpenVPN...")
    if openvpn_proc and openvpn_proc.poll() is None:
        openvpn_proc.terminate()
        openvpn_proc.wait()
    sys.exit(0)


openvpn_proc = None

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    check_tun()

    if needs_setup():
        run_setup()

    openvpn_proc = start_openvpn()

    # Surveillance : redémarre OpenVPN s'il crashe
    while True:
        ret = openvpn_proc.wait()
        print(f"[!] OpenVPN s'est arrêté (code {ret}). Redémarrage dans 5s...")
        time.sleep(5)
        openvpn_proc = start_openvpn()

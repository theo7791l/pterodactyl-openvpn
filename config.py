# =============================================================
#  Configuration OpenVPN – modifie ces valeurs avant de lancer
# =============================================================

import os

# Port UDP exposé dans le panel Pterodactyl
VPN_PORT = int(os.environ.get("VPN_PORT", 1194))

# Protocole (udp recommandé)
VPN_PROTO = os.environ.get("VPN_PROTO", "udp")

# Sous-réseau virtuel VPN
VPN_SUBNET = os.environ.get("VPN_SUBNET", "10.8.0.0")
VPN_MASK   = os.environ.get("VPN_MASK",   "255.255.255.0")

# Serveurs DNS poussés aux clients
DNS1 = os.environ.get("DNS1", "1.1.1.1")
DNS2 = os.environ.get("DNS2", "8.8.8.8")

# IP publique du serveur (laisse vide pour auto-détection)
SERVER_IP = os.environ.get("SERVER_IP", "")

# Dossiers de travail (dans /home/container)
WORKDIR   = "/home/container"
CERTDIR   = f"{WORKDIR}/pki"
CLIENTDIR = f"{WORKDIR}/clients"
CONFDIR   = f"{WORKDIR}/conf"
SERVER_CONF = f"{CONFDIR}/server.conf"

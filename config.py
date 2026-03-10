# =============================================================
#  Configuration WireGuard – prête à l'emploi, rien à modifier
# =============================================================

import os

# Port UDP exposé dans le panel Pterodactyl
VPN_PORT = int(os.environ.get("VPN_PORT", 40739))

# Sous-réseau VPN
VPN_SUBNET_CLIENT = os.environ.get("VPN_SUBNET", "10.8.0.0/24")

# Dossiers de travail
WORKDIR          = "/home/container"
WG_CONF          = f"{WORKDIR}/conf/wg0.conf"
SERVER_PRIVKEY_FILE = f"{WORKDIR}/keys/server_private"
SERVER_PUBKEY_FILE  = f"{WORKDIR}/keys/server_public"
CLIENT_PRIVKEY_FILE = f"{WORKDIR}/keys/client_private"
CLIENT_PUBKEY_FILE  = f"{WORKDIR}/keys/client_public"

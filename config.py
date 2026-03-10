# Configuration VPN - rien a modifier
import os

VPN_PORT   = int(os.environ.get("VPN_PORT", 40739))
WORKDIR    = "/home/container"
CONF_DIR   = f"{WORKDIR}/conf"
KEYS_DIR   = f"{WORKDIR}/keys"
CLIENTS_DIR = f"{WORKDIR}/clients"
WG_CONF    = f"{CONF_DIR}/wg0.conf"
BORINGTUN_BIN       = f"{WORKDIR}/boringtun"
SERVER_PRIVKEY_FILE = f"{KEYS_DIR}/server_private"
SERVER_PUBKEY_FILE  = f"{KEYS_DIR}/server_public"
CLIENT_PRIVKEY_FILE = f"{KEYS_DIR}/client_private"
CLIENT_PUBKEY_FILE  = f"{KEYS_DIR}/client_public"

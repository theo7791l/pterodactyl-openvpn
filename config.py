# Configuration - rien a modifier
import os

VPN_PORT    = int(os.environ.get("VPN_PORT", 40739))
WORKDIR     = "/home/container"
CONF_DIR    = f"{WORKDIR}/conf"
CLIENTS_DIR = f"{WORKDIR}/clients"
CERT_FILE   = f"{CONF_DIR}/cert.pem"
KEY_FILE    = f"{CONF_DIR}/key.pem"

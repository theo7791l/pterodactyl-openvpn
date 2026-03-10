# pterodactyl-openvpn (WireGuard userspace)

Serveur VPN WireGuard en **userspace** (wireguard-go), conçu pour tourner sur un panel Pterodactyl **sans `/dev/net/tun`** ni droits noyau spéciaux.

## Prérequis

- Egg Python 3.11+ sur Pterodactyl
- Un port UDP exposé (par défaut : **40739**)
- Accès `apt-get` dans le conteneur (pour installer `wireguard-tools` et `iproute2`)

## Démarrage

Dans le panel :
- **Git Repo** : `https://github.com/theo7791l/pterodactyl-openvpn`
- **Branch** : `main`
- **App PY File** : `main.py`
- **Docker Image** : Python 3.11

Lancer le serveur → tout s'installe automatiquement au premier démarrage.

## Récupérer le fichier client

Après le premier démarrage, télécharge le fichier `clients/client1.conf` depuis le panel et importe-le dans ton client WireGuard (Windows, Android, iOS).

## Architecture

```
/home/container/
├── main.py           # Point d'entrée + setup + watchdog
├── config.py         # Port, chemins, réseau
├── wireguard-go      # Binaire userspace (téléchargé auto)
├── conf/wg0.conf     # Config serveur WireGuard
├── keys/             # Clés serveur + client
└── clients/          # Fichier client1.conf à télécharger
```

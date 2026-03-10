# pterodactyl-proxy

Proxy SOCKS5 chiffre (TLS) en **Python pur**.
Zero `/dev/net/tun`, zero `apt`, zero binaire externe, zero `sudo`.
Tout tourne dans `/home/container`.

## Panel Pterodactyl

- **Git Repo** : `https://github.com/theo7791l/pterodactyl-openvpn`
- **Branch** : `main`
- **App PY File** : `main.py`
- **Requirements File** : `requirements.txt`
- **Docker Image** : Python 3.11
- **Port** : `40739 TCP`

> **Attention** : le port doit etre en **TCP** (pas UDP) dans le panel.

## Premier demarrage

Tout est automatique :
1. Generation d'un certificat TLS auto-signe
2. Demarrage du serveur SOCKS5+TLS sur le port 40739
3. Generation de `clients/connexion.txt` avec les infos de connexion

## Se connecter

Telecharge `clients/connexion.txt` depuis le panel pour les instructions.
En resume : configure un proxy SOCKS5 sur `IP_SERVEUR:40739` dans ton navigateur ou Proxifier.

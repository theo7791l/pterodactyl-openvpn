# pterodactyl-openvpn (WireGuard userspace)

Serveur VPN WireGuard **100% userspace**, sans `apt`, sans `sudo`, sans `/dev/net/tun`.
Tout tourne dans `/home/container`.

## Panel Pterodactyl

- **Git Repo** : `https://github.com/theo7791l/pterodactyl-openvpn`
- **Branch** : `main`
- **App PY File** : `main.py`
- **Requirements File** : `requirements.txt`
- **Docker Image** : Python 3.11
- **Port** : `40739 UDP`

## Premier demarrage

Tout est automatique :
1. Telechargement de `wireguard-go` dans `/home/container`
2. Generation des cles via Python (`cryptography`)
3. Ecriture des configs serveur + client
4. Demarrage du VPN

## Recuperer le fichier client

Telecharge `clients/client1.conf` depuis le panel et importe-le dans **WireGuard** (Windows/Android/iOS).

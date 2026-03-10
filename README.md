# pterodactyl-openvpn

Installation et lancement automatique d'un serveur OpenVPN depuis un panel Pterodactyl, entièrement piloté par Python.

## Prérequis

- Un serveur Pterodactyl avec un egg Python (3.10+)
- Un port UDP exposé (ex: 1194)
- `/dev/net/tun` disponible dans le conteneur (sinon voir section Dépannage)
- `openvpn` installé dans l'image Docker de l'egg (ou utilisez `setup.py` pour l'installer via pip/subprocess)

## Structure

```
pteroducktyl-openvpn/
├── main.py           # Point d'entrée principal (lanceur Pterodactyl)
├── setup.py          # Installation d'OpenVPN + génération des certificats
├── config.py         # Configuration (port, protocole, réseau VPN, DNS...)
├── requirements.txt  # Dépendances Python
└── README.md
```

## Utilisation

### 1. Configuration

Modifie `config.py` selon tes besoins :

```python
VPN_PORT = 1194       # Port UDP ouvert sur le panel
VPN_PROTO = "udp"
VPN_SUBNET = "10.8.0.0"
VPN_MASK = "255.255.255.0"
DNS1 = "1.1.1.1"
DNS2 = "8.8.8.8"
SERVER_IP = ""        # Laisse vide pour auto-détection
```

### 2. Démarrage

Dans le panel Pterodactyl, définis la commande de démarrage :
```
python main.py
```

La première exécution lance `setup.py` automatiquement (installation + génération PKI).
Les suivantes relancent directement OpenVPN.

### 3. Récupérer un fichier client `.ovpn`

Après le premier démarrage, le fichier `client.ovpn` est généré dans `/home/container/clients/`.

## Dépannage

### `/dev/net/tun` absent

Si tu vois :
```
Cannot open TUN/TAP dev /dev/net/tun: No such file or directory
```

Demande à l'admin du nœud Pterodactyl d'activer le device `/dev/net/tun` et la cap `NET_ADMIN` pour le conteneur. Ce n'est pas réglable depuis Python seul.

### OpenVPN non trouvé

`setup.py` tente de l'installer via `apt-get` dans le conteneur. Si `apt` n'est pas disponible, utilise une image Docker qui inclut `openvpn`.

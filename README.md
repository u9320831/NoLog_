# NoLog

NoLog est une base d’intégration pour ajouter une zone de traitement
confidentiel à une application Windows : enclave VBS, secrets TPM/DPAPI,
transport TCP/UDP sécurisé et stockage serveur sans connaissance du contenu.

## Architecture

```text
Application existante
        │
        │ adaptateur NoLog local
        ▼
Hôte Windows ── appelle ──> enclave VBS
   │                         │
   │                         ├─ X25519 + HKDF-SHA256
   │                         ├─ ChaCha20-Poly1305
   │                         └─ SHA-256 / nonce / anti-rejeu
   │
   ├─ cookie TPM + DPAPI
   ├─ sockets TCP/UDP ou TLS/QUIC
   └─ logs locaux minimisés
        │
        ▼
Serveur NoLog
   ├─ ne reçoit que des enveloppes chiffrées
   ├─ ne possède pas les clés de contenu
   └─ PostgreSQL stocke ciphertext + nonce + version
```

## Intégrer une application

Consulter [docs/INTEGRATION.md](docs/INTEGRATION.md). Le principe est toujours
le même :

1. ne jamais envoyer une donnée sensible en clair à l’hôte ou au serveur ;
2. faire chiffrer la donnée par l’enclave ;
3. envoyer uniquement l’enveloppe binaire et un identifiant opaque aléatoire ;
4. ne jamais écrire l’enveloppe, les clés ou les secrets dans les logs ;
5. limiter les tailles, délais, tentatives et files d’attente ;
6. séparer les sessions et ne pas partager de cache entre utilisateurs.

## Composants

| Composant | Rôle |
|---|---|
| `src/` | DLL de l’enclave VBS |
| `client/` | cookie TPM/DPAPI, réseau TCP/UDP, proxy Tor optionnel |
| `server/` | vault local des identifiants PostgreSQL |
| `dashboard/` | statistiques agrégées sans contenu confidentiel |
| `deploy/` | PostgreSQL, dashboard, Tor optionnel et scripts Windows |

## Démarrage rapide avec Docker

Depuis la racine du dépôt :

```powershell
New-Item -ItemType Directory -Force deploy\.secrets
[guid]::NewGuid().ToString("N") | Set-Content deploy\.secrets\postgres_password
[guid]::NewGuid().ToString("N") | Set-Content deploy\.secrets\dashboard_token
[guid]::NewGuid().ToString("N") | Set-Content deploy\.secrets\ingest_token
docker compose up --build -d
```

Cela démarre PostgreSQL et le dashboard. Tor reste optionnel :

```powershell
docker compose --profile tor up --build -d
```

Le conteneur Linux ne remplace pas la DLL VBS : l’enclave, le TPM et DPAPI
restent natifs Windows. Les crates portables, notamment `nolog-protocol`,
peuvent être intégrées dans une autre application Rust via le workspace ou
publiées comme dépendance Git/Cargo.

## Limite de sécurité

NoLog ne peut pas garantir qu’un administrateur ou un noyau compromis ne verra
aucune information sur un PC qu’il contrôle. Les adresses réseau, les tailles,
les horaires, le processus hôte et certains événements système peuvent rester
observables. VBS protège une partie du code et des données de l’enclave, pas
l’intégralité de la machine.

Le modèle réaliste est donc : contenu sensible protégé par l’enclave, serveur
aveugle au contenu, métadonnées minimisées et supervision explicite.

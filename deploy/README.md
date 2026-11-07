# Déploiement NoLog

L'enclave VBS et le vault TPM/DPAPI restent sur Windows. Les conteneurs
fournis ici déploient uniquement Tor et le dashboard d'observabilité.

1. Créer `.secrets/postgres_password`, `.secrets/dashboard_token` et
   `.secrets/ingest_token` avec des valeurs aléatoires d'au moins 32 caractères.
2. Lancer `docker compose up -d --build` depuis ce dossier.
3. Ouvrir `http://127.0.0.1:8080` et saisir le token dashboard.

Le dashboard n'accepte que des agrégats sur `/internal/events` : aucun nom,
identifiant, IP, destination, secret ou payload ne doit être envoyé.

PostgreSQL est publié uniquement sur `127.0.0.1:5432` pour que le serveur
Windows existant puisse s'y connecter. Son volume est persistant et son mot
de passe n'est pas écrit dans le fichier Compose.

Routes :

- `/healthz` : santé, sans authentification ;
- `/api/stats` : statistiques JSON, token dashboard ;
- `/metrics` : format Prometheus, token dashboard ;
- `/internal/events` : ingestion d'agrégats, token ingestion.

Le service Tor est désactivé par défaut. Le démarrage local n'utilise donc
aucun proxy Tor. Pour l'activer explicitement :

```text
docker compose --profile tor up -d --build
```

Le client Windows peut continuer à utiliser une connexion directe en local.

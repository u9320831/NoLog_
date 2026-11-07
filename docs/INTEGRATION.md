# Guide d’intégration NoLog

Ce guide permet à une application existante d’utiliser NoLog sans dépendre de
son langage ou de son framework. Une intégration universelle n’est pas possible
avec une simple DLL : chaque application doit placer son adaptateur à la
frontière où elle manipule ses données sensibles.

## Frontière de confidentialité

L’application doit distinguer trois zones :

```text
Donnée en clair
    │ uniquement dans l’enclave
    ▼
Envelope NoLog : version + nonce + ciphertext + key_version
    │
    ▼
Réseau / serveur / PostgreSQL
```

L’hôte ne doit recevoir de l’enclave que le résultat nécessaire à l’opération.
Il ne doit pas copier les clés, réutiliser les nonces ou conserver une copie
du texte clair.

## Contrat d’enveloppe

Chaque enregistrement doit contenir uniquement :

```text
version       : entier
record_id     : identifiant aléatoire opaque, sans nom d’utilisateur
key_version   : entier de rotation
nonce         : nonce unique pour cette clé
ciphertext    : donnée chiffrée et authentifiée
```

Le serveur peut valider la taille, la version et le format, mais ne doit pas
interpréter le contenu. `record_id` ne doit pas contenir d’e-mail, de nom, de
chemin ou d’identifiant métier.

## Règles réseau

- En local, utiliser la connexion directe ; Tor est optionnel.
- Pour TCP, utiliser un framing avec longueur maximale et TLS 1.3.
- Pour UDP, utiliser QUIC plutôt qu’un UDP brut : QUIC fournit le handshake,
  le chiffrement TLS 1.3, la congestion et les timeouts.
- Ne jamais créer de proxy ouvert : les destinations doivent être autorisées
  par configuration serveur.
- Définir un timeout de connexion, handshake, lecture, écriture et inactivité.
- Ne pas partager de pool ou de cache entre deux compartiments de confiance.

## Politique de logs

Autorisé :

- compteur de requêtes ;
- durée en classes ou histogrammes ;
- taille agrégée ;
- code d’erreur générique ;
- état de santé.

Interdit :

- payloads ;
- clés, cookies, tokens et mots de passe ;
- adresses complètes si elles ne sont pas indispensables ;
- identifiants utilisateurs ;
- traces contenant des buffers ou des URLs sensibles.

## Serveur sans connaissance

Le serveur doit recevoir une enveloppe déjà chiffrée. Il ne doit jamais
recevoir la clé de contenu ni demander à l’enclave de déchiffrer pour lui.
PostgreSQL ne stocke que `ciphertext`, `nonce`, `key_version` et un identifiant
opaque. Les opérations de recherche doivent utiliser un index aveugle ou un
identifiant opaque, jamais une valeur en clair.

## Cycle d’une requête

```text
1. L’application choisit la donnée à protéger.
2. L’enclave vérifie la taille et le contexte.
3. L’enclave dérive la clé de session et chiffre.
4. L’hôte détruit sa copie temporaire du clair.
5. L’hôte envoie l’enveloppe au serveur.
6. Le serveur valide le format et stocke l’enveloppe.
7. Le serveur renvoie uniquement un statut ou une enveloppe chiffrée.
```

## Intégration d’une application non-Rust

Créer un petit adaptateur natif qui :

1. charge et initialise la DLL d’enclave ;
2. expose uniquement `encrypt`, `decrypt`, `hash` et `session` ;
3. copie les buffers avec leurs longueurs explicites ;
4. vérifie les codes d’erreur et efface les buffers sensibles ;
5. transmet l’enveloppe via le protocole réseau choisi.

Ne jamais exposer une fonction générique du type `execute(code)` ou un pointeur
vers la mémoire interne de l’enclave.

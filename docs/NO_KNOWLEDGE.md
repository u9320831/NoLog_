# Modèle serveur No-Knowledge

Le serveur NoLog est un relais et un stockage aveugle. Il peut savoir qu’un
client a envoyé une enveloppe, quand elle est arrivée et quelle taille elle
fait, mais il ne doit pas pouvoir lire la donnée métier.

## Ce que le serveur possède

- une clé TLS du serveur ;
- des identifiants PostgreSQL protégés par le vault local ;
- des enveloppes chiffrées ;
- des compteurs opérationnels agrégés.

## Ce que le serveur ne possède pas

- la clé de contenu de l’application ;
- le texte clair ;
- les cookies utilisateurs en clair ;
- un mapping obligatoire entre `record_id` et identité réelle.

## Limites

No-Knowledge ne signifie pas absence totale de métadonnées. Le serveur peut
encore observer la disponibilité, les tailles, les horaires, les erreurs et les
connexions réseau. Pour réduire ces informations, utiliser des lots de taille
normalisée, des fenêtres temporelles et des statistiques agrégées, sans promettre
une invisibilité complète.

# Modèle de menace

## Protégé

- secrets au repos avec TPM + DPAPI ;
- clés et calculs sensibles dans l’enclave VBS ;
- contenu des enveloppes en transit et dans PostgreSQL ;
- logs applicatifs contre l’exposition accidentelle de secrets ;
- séparation des sessions et limites de taille/temps.

## Non garanti

- administrateur local disposant de privilèges élevés ;
- noyau Windows compromis ou pilote malveillant ;
- machine déjà compromise avant l’initialisation de l’enclave ;
- métadonnées réseau, horaires, tailles et disponibilité ;
- fuite volontaire depuis l’application hôte.

## Mesures de production

- signer l’enclave et désactiver le mode debug ;
- utiliser un compte de service dédié et le principe du moindre privilège ;
- ne jamais utiliser `LocalSystem` sans justification ;
- protéger les tokens Docker par secrets ;
- conserver les logs hors des données sensibles ;
- tester les rotations de clés et la révocation ;
- surveiller les compteurs agrégés sans enregistrer les payloads.

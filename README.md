# RT0802 - Échanges sécurisés

## But

Ce projet vise à mettre en avant le chiffrement et la certification des échanges.

## Démarrage

Afin de pouvoir faire la démonstration:

1. Générer paire certificat/clé publique dans root/sec/ (certificate.pem et private_key.pem)
2. Copier le certificat dans site/sec/{identifiant du site}/root.pem
3. docker compose build
4. docker compose up -d
5. Regarder les logs situées dans
> * root/logs/ca.log
> * root/logs/router.log
> * site/logs/site{identifiant du site}.log



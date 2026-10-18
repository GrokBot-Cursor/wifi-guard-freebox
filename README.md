# WiFi Guard

Surveillance des appareils connectés à une **Freebox** (API locale) : un inventaire des appareils connus est constitué, puis tout **nouvel appareil inconnu** déclenche une alerte (mail, webhook ou fichier) et, en option, un **blocage provisoire par adresse MAC** en attendant votre décision.

Python 3 (bibliothèque standard uniquement), livré en conteneur Docker, utilisable tel quel dans Portainer.

> English summary at the bottom of this file.

> ⚠️ Projet communautaire, sans lien avec Free. Utilisez-le uniquement sur **votre propre réseau**. Aucune garantie (voir `LICENSE`).

## Principe

1. Le programme interroge l'API locale de la Freebox (`/api/vX/lan/browser/pub/`) toutes les 60 s (configurable).
2. **Mode apprentissage** (10 premières minutes, puis à la demande) : tous les appareils que la Freebox connaît entrent dans l'inventaire, sans alerte.
3. **Mode surveillance** : un appareil **actif** absent de l'inventaire est « inconnu » :
   - une alerte est écrite dans `outbox/` puis envoyée par les canaux configurés (SMTP, webhook) ;
   - si le blocage est activé et que l'appareil est en Wi-Fi, il est ajouté au filtre MAC de la Freebox (liste noire) ;
   - 2 rappels maximum (après 6 h puis 24 h).
4. Vous répondez avec `allow` (c'est le vôtre : débloqué et ajouté à l'inventaire) ou `deny` (intrus : reste bloqué, plus de rappel).
5. Garde-fous : jamais plus de 3 inconnus d'un coup (anomalie : alerte groupée, aucun blocage), 5 blocages/heure maximum, inventaire minimum de 5 appareils, jamais la Freebox elle-même ni les IP/MAC protégées, jamais si le filtre MAC de la box est en liste blanche. Une alerte est aussi émise si la Freebox ne répond plus pendant 30 min.
6. Adresses MAC aléatoires : un inconnu à MAC « localement administrée » dont le nom correspond à un appareil connu génère une simple information (1 par 24 h), jamais un blocage.

## Installation

### Avec docker compose

```sh
git clone <url-du-depot> wifi-guard && cd wifi-guard
cp .env.example .env        # puis éditer .env (canaux d'alerte, etc.)
docker compose up -d --build
```

### Avec Portainer

*Stacks → Add stack* :
- **Repository** : l'URL de ce dépôt, fichier `docker-compose.yml` (Portainer construit l'image à partir du `Dockerfile`), ou **Web editor** si vous avez déjà construit l'image `wifi-guard:latest` sur l'hôte ;
- **Environment variables** : saisissez les variables de `.env.example` que vous voulez changer (les autres ont une valeur par défaut) ; les mots de passe se saisissent ici et pas dans le dépôt.

Les données (état, jeton d'appairage, outbox) sont dans le volume Docker `wifi-guard-data`.

> Si le conteneur ne résout pas `mafreebox.freebox.fr`, mettez l'adresse IP locale de votre box dans `FBX_URL`.

## Appairage avec la Freebox (une seule fois)

L'application doit être autorisée **physiquement** sur la box. Le conteneur démarre sans jeton et le dit dans ses logs ; lancez alors :

```sh
docker exec -it wifi-guard python /app/wifi_guard.py pair
# ou, avec le script fourni : ./wifi-guard-ctl pair
```

(Dans Portainer : *Containers → wifi-guard → Console*, puis `python /app/wifi_guard.py pair`.)

Le programme affiche « Valide l'appairage sur l'écran de la Freebox » : **validez avec la flèche + OK sur l'écran de la box** dans les 2 minutes. Le jeton est enregistré dans `/data/app_token.json` (droits 600) et n'apparaît jamais dans les logs.

### Permissions de l'application

Dans FreeboxOS : *Paramètres de la Freebox → Gestion des accès → onglet Applications → WiFi Guard (identifiant `WG_APP_ID`)*.
- La **lecture de la liste des appareils** (surveillance + alertes) ne demande pas de permission particulière dans nos essais.
- Le **blocage MAC** modifie la configuration Wi-Fi : il faut accorder la permission **« Modification des réglages de la Freebox »**. Sans elle, le programme alerte mais ne bloque pas.

Vérification (lecture seule) : `./wifi-guard-ctl selftest`.

## Modes

| Mode | Effet |
|---|---|
| `learn` (apprentissage) | Ajoute tout à l'inventaire, aucune alerte. Automatique au premier démarrage, puis bascule seul en `monitor`. |
| `monitor` (surveillance) | Alerte (et bloque si activé) pour tout appareil actif inconnu. |

```sh
./wifi-guard-ctl mode learn      # relancer un apprentissage (WG_LEARN_MINUTES)
./wifi-guard-ctl mode monitor
```

## Canaux d'alerte (tous optionnels, combinables)

Configurés par variables d'environnement (voir `.env.example`).

- **Fichier outbox** : toujours actif. Sans autre canal, les alertes restent dans `outbox/` ; `./wifi-guard-ctl outbox --json` les liste, `outbox-ack ID` les acquitte (pratique pour brancher votre propre relais).
- **SMTP** : `WG_SMTP_HOST`, `WG_SMTP_PORT`, `WG_SMTP_SECURITY` (`ssl`, `starttls` ou `none`), `WG_SMTP_USER`, `WG_SMTP_PASSWORD` (ou `WG_SMTP_PASSWORD_FILE` pour un secret Docker), `WG_MAIL_FROM`, `WG_MAIL_TO`.
- **Webhook générique** : `WG_WEBHOOK_URL` reçoit un `POST` JSON `{id, ts, kind, mac, subject, body, text}` ; `WG_WEBHOOK_AUTH` (optionnel) fournit la valeur de l'en-tête `Authorization`. Le champ `text` convient à la plupart des services de notification (Discord/Slack compatibles via un adaptateur, ntfy, n8n, Home Assistant...).

Si l'envoi échoue, l'alerte reste dans `outbox/` et est retentée au scan suivant. Test sans risque : `./wifi-guard-ctl simulate` (aucune écriture sur la box, état inchangé).

## Commandes

```sh
./wifi-guard-ctl status [--json]          # mode, interrupteur de blocage, inconnus en attente
./wifi-guard-ctl list [known|unknown]
./wifi-guard-ctl allow <MAC> ["nom"]      # appareil à moi : débloque + ajoute à l'inventaire
./wifi-guard-ctl deny  <MAC>              # intrus : reste bloqué (si blocage actif), plus de rappel
./wifi-guard-ctl forget <MAC>             # retire de l'inventaire (sera de nouveau « inconnu »)
./wifi-guard-ctl block on|off             # interrupteur du blocage réel (défaut : off)
./wifi-guard-ctl mode learn|monitor
./wifi-guard-ctl scan [--dry]             # un scan immédiat
./wifi-guard-ctl simulate [MAC nom wifi|ethernet]
./wifi-guard-ctl selftest                 # accès API, état du filtre MAC, permissions (lecture seule)
```

## ⚠️ Blocage MAC (optionnel, désactivé par défaut)

Le blocage réel est **désactivé** (`WG_BLOCK=off`) : par défaut, WiFi Guard ne fait qu'alerter. Activez-le seulement après quelques jours d'alertes sans fausse alerte : `./wifi-guard-ctl block on`.

Avant de l'activer, comprenez ses limites :

- **Liste noire uniquement.** Le programme ajoute des adresses au filtre MAC Wi-Fi de la Freebox en mode `blacklist`. Si le filtre de la box est en **liste blanche**, WiFi Guard n'y touche pas (cela couperait le Wi-Fi de toute la maison). S'il est désactivé, il le passe en liste noire au premier blocage.
- **MAC aléatoire.** Les smartphones modernes changent d'adresse MAC par réseau Wi-Fi, parfois périodiquement : un de vos propres appareils peut être vu comme « nouveau » et **bloqué à tort** jusqu'à votre `allow`. À l'inverse, un intrus qui change d'adresse échappe au blocage.
- **Usurpation de MAC.** Un attaquant qui copie l'adresse d'un appareil de l'inventaire n'est ni détecté ni bloqué. Ce n'est **pas** une barrière de sécurité : changez le mot de passe Wi-Fi si vous suspectez une intrusion.
- **Ethernet non bloqué.** L'API ne permet pas de couper un port filaire : un appareil Ethernet inconnu est **signalé seulement**.
- Pensez à renseigner `WG_PROTECT_IPS` / `WG_PROTECT_MACS` avec la machine qui héberge le conteneur et vos équipements critiques.

## Limites connues

- Pas d'interface web : tout passe par la ligne de commande et les alertes.
- Pas de détection d'usurpation de MAC ni d'analyse du trafic.
- Les noms d'appareils viennent de la Freebox (DHCP) et peuvent être vides ou génériques.
- L'identification d'un réseau invité et du répéteur dépend des informations fournies par la box (indications seulement).
- Testé sur Freebox avec API locale v8+ (la version est détectée automatiquement) ; le comportement peut varier selon le modèle et le firmware.
- Les « appareils connus » incluent tout l'historique de la Freebox au moment de l'apprentissage, y compris d'anciens appareils : faites un tri avec `list known` / `forget`.
- Une seule instance par Freebox.

## Sécurité

- Aucun secret dans le code : jeton d'appairage dans le volume `/data` (droits 600), mots de passe dans les variables d'environnement ou fichier secret.
- Le conteneur tourne sans privilège (utilisateur 1000, `cap_drop: ALL`, système de fichiers en lecture seule).
- Ne publiez jamais votre `.env`, le dossier `data/` ni un export de l'inventaire (il contient les adresses MAC et noms de vos appareils).

## Licence

MIT, voir `LICENSE`.

---

## English summary

**WiFi Guard** watches the devices seen by a **Freebox** (local API). It first *learns* the existing device inventory (no alerts), then switches to *monitor* mode: any new active unknown device raises an alert through configurable channels (file outbox, SMTP, generic JSON webhook) and, **optionally**, is temporarily blocked by MAC address using the Freebox Wi-Fi MAC filter (blacklist mode only).

- Pure Python 3 standard library, shipped as a Docker image + `docker-compose.yml` (works as a Portainer stack). Configure everything with environment variables (see `.env.example`).
- Pairing: run `python /app/wifi_guard.py pair` in the container and confirm on the Freebox screen. Grant the app the "settings" permission in FreeboxOS only if you want blocking.
- Blocking is **off by default**. Caveats: blacklist only (whitelist mode is never touched), random MAC addresses on modern phones cause false positives, MAC spoofing is neither detected nor prevented, wired (Ethernet) devices cannot be blocked, only reported.
- Commands: `status`, `list`, `allow <MAC>`, `deny <MAC>`, `forget <MAC>`, `block on|off`, `mode learn|monitor`, `selftest`, `simulate`.
- MIT licensed, no warranty. Use only on your own network.

Publié par GrokBot-Cursor

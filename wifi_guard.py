#!/usr/bin/env python3
"""
WiFi Guard : surveille les appareils du reseau d'une Freebox (API locale) et alerte
quand un appareil inconnu apparait.

- Apprentissage au premier demarrage (inventaire sans alerte), puis surveillance.
- Appareil inconnu : alerte (fichier outbox, + mail SMTP et/ou webhook si configures) et, si
  l'interrupteur de blocage est ON, blocage PROVISOIRE par MAC (filtre MAC Wi-Fi Freebox,
  mode blacklist uniquement). Ethernet : alerte seulement (l'API ne permet pas de bloquer).
- Decision : `allow MAC` (debloque + ajoute a l'inventaire) ou `deny MAC` (reste bloque).
- Python stdlib uniquement. Aucun secret dans le code ni dans les logs.

Variables d'environnement (toutes optionnelles, voir .env.example) :
  WG_DATA              dossier de donnees (defaut /data)
  FBX_URL              defaut http://mafreebox.freebox.fr (API locale ; l'auth HMAC protege le jeton)
  FBX_INSECURE         1 = accepter un certificat https non verifiable
  WG_APP_ID            identifiant d'application declare a la Freebox (defaut fr.example.wifiguard)
  WG_APP_NAME          nom affiche sur la Freebox (defaut WiFi Guard)
  WG_DEVICE_NAME       nom de la machine affichee sur la Freebox (defaut wifi-guard)
  WG_INTERVAL          secondes entre deux scans (defaut 60)
  WG_LEARN_MINUTES     duree de l'apprentissage initial (defaut 10)
  WG_BLOCK             "on"/"off" : valeur initiale de l'interrupteur de blocage (defaut off)
  WG_PROTECT_IPS       IP jamais bloquees (liste separee par des virgules)
  WG_PROTECT_MACS      MAC jamais bloquees (liste separee par des virgules)
  Alertes :
  WG_SMTP_HOST, WG_SMTP_PORT, WG_SMTP_SECURITY (ssl|starttls|none), WG_SMTP_USER,
  WG_SMTP_PASSWORD (ou WG_SMTP_PASSWORD_FILE), WG_MAIL_FROM, WG_MAIL_TO
  WG_WEBHOOK_URL, WG_WEBHOOK_AUTH (valeur de l'en-tete Authorization, optionnelle)
"""
import fcntl
import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path

DATA = Path(os.environ.get("WG_DATA", "/data"))
FBX_URL = os.environ.get("FBX_URL", "http://mafreebox.freebox.fr").rstrip("/")
APP_ID = os.environ.get("WG_APP_ID", "fr.example.wifiguard")
APP_NAME = os.environ.get("WG_APP_NAME", "WiFi Guard")
DEVICE_NAME = os.environ.get("WG_DEVICE_NAME", "wifi-guard")
INTERVAL = int(os.environ.get("WG_INTERVAL", "60"))
LEARN_MIN = int(os.environ.get("WG_LEARN_MINUTES", "10"))
PROTECT_IPS = {x.strip() for x in os.environ.get("WG_PROTECT_IPS", "").split(",") if x.strip()}
PROTECT_MACS = {x.strip().upper() for x in os.environ.get("WG_PROTECT_MACS", "").split(",") if x.strip()}
REMINDERS = [6 * 3600, 24 * 3600]          # rappels max : apres 6 h puis 24 h, ensuite plus rien
MAX_NEW_PER_SCAN = 3                        # au-dela : anomalie, alerte groupee, aucun blocage
MAX_BLOCKS_PER_HOUR = 5                     # disjoncteur
MIN_INVENTORY_TO_BLOCK = 5                  # inventaire trop petit = jamais de blocage
API_DOWN_AFTER = 1800                       # alerte si l'API ne repond plus depuis 30 min
GENERIC_NAMES = {"", "?", "android", "iphone", "ipad", "galaxy", "samsung", "unknown", "localhost",
                 "wlan0", "espressif", "host", "device", "phone", "mobile", "tablet", "pc"}
SSL_CTX = None
if os.environ.get("FBX_INSECURE") == "1":
    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

STATE_F, CFG_F, TOKEN_F, LOCK_F = DATA / "state.json", DATA / "config.json", DATA / "app_token.json", DATA / "state.lock"
OUTBOX, SENT = DATA / "outbox", DATA / "outbox" / "sent"


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def now():
    return int(time.time())


def fmt(ts):
    return time.strftime("%d/%m/%Y %H:%M", time.localtime(ts)) if ts else "?"


# ---------------------------------------------------------------- fichiers

def write_private(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return default


class Lock:
    def __enter__(self):
        DATA.mkdir(parents=True, exist_ok=True)
        self.f = open(LOCK_F, "a+")
        end = time.time() + 60
        while True:
            try:
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.time() > end:
                    raise RuntimeError("verrou occupe (scan en cours ?)")
                time.sleep(0.3)

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def config():
    c = load_json(CFG_F, {})
    if "block" not in c:
        c["block"] = os.environ.get("WG_BLOCK", "off").lower() == "on"
    return c


def save_config(c):
    write_private(CFG_F, json.dumps(c, indent=2))


def new_state():
    return {"version": 1, "mode": "learn", "learn_started": now(), "learn_until": now() + LEARN_MIN * 60,
            "devices": {}, "unknown": {}, "blocks": [], "api": {"fail_since": 0, "alerted": False},
            "random_alerts": {}}


# ---------------------------------------------------------------- API Freebox

class ApiError(Exception):
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


class Freebox:
    def __init__(self):
        self.base = None
        self.session = None
        self.permissions = {}
        self.tok = load_json(TOKEN_F, None)

    def _raw(self, method, path, payload=None, auth=True):
        url = FBX_URL + path
        headers = {"Content-Type": "application/json"}
        if auth and self.session:
            headers["X-Fbx-App-Auth"] = self.session
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as r:
                body = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except Exception:
                raise ApiError("HTTP %s sur %s" % (e.code, path))
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ApiError("reseau: %s" % type(e).__name__)
        if not body.get("success"):
            raise ApiError("%s sur %s" % (body.get("error_code", "erreur"), path), body.get("error_code"))
        return body.get("result")

    def discover(self):
        if self.base:
            return
        req = urllib.request.Request(FBX_URL + "/api_version")
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as r:
            v = json.loads(r.read().decode())
        major = str(v.get("api_version", "8.0")).split(".")[0]
        self.base = "%sv%s" % (v.get("api_base_url", "/api/"), major)

    def login(self):
        if not self.tok:
            raise ApiError("pas de jeton d'appairage (%s) : lancer la commande `pair`" % TOKEN_F, "no_token")
        self.discover()
        self.session = None
        ch = self._raw("GET", self.base + "/login/", auth=False)["challenge"]
        pw = hmac.new(self.tok["app_token"].encode(), ch.encode(), hashlib.sha1).hexdigest()
        res = self._raw("POST", self.base + "/login/session/", {"app_id": self.tok["app_id"], "password": pw}, auth=False)
        self.session = res["session_token"]
        self.permissions = res.get("permissions", {})

    def call(self, method, path, payload=None):
        if not self.session:
            self.login()
        try:
            return self._raw(method, self.base + path, payload)
        except ApiError as e:
            if e.code in ("auth_required", "invalid_session"):
                self.login()
                return self._raw(method, self.base + path, payload)
            raise

    # lectures
    def hosts(self):
        return self.call("GET", "/lan/browser/pub/") or []

    def wifi_config(self):
        return self.call("GET", "/wifi/config/") or {}

    def mac_filters(self):
        return self.call("GET", "/wifi/mac_filter/") or []

    def bss_labels(self):
        out = {}
        for b in self.call("GET", "/wifi/bss/") or []:
            out[str(b.get("id", "")).upper()] = (b.get("status") or {}).get("custom_key_ssid") or ""
        return out

    # ecritures (uniquement filtre MAC)
    def add_blacklist(self, mac, comment):
        return self.call("POST", "/wifi/mac_filter/", {"mac": mac, "type": "blacklist", "comment": comment[:60]})

    def del_filter(self, fid):
        return self.call("DELETE", "/wifi/mac_filter/" + urllib.request.quote(fid, safe=""))

    def set_filter_state(self, state):
        return self.call("PUT", "/wifi/config/", {"mac_filter_state": state})

    def pair(self):
        """Appairage : exige une validation PHYSIQUE sur l'ecran de la Freebox. Jamais lance automatiquement."""
        self.discover()
        res = self._raw("POST", self.base + "/login/authorize/", {
            "app_id": APP_ID, "app_name": APP_NAME, "app_version": "2.0",
            "device_name": DEVICE_NAME}, auth=False)
        print("Valide l'appairage sur l'ecran de la Freebox (fleche + OK)...")
        for _ in range(120):
            st = self._raw("GET", "%s/login/authorize/%s" % (self.base, res["track_id"]), auth=False)
            if st.get("status") == "granted":
                write_private(TOKEN_F, json.dumps({"app_id": APP_ID, "app_token": res["app_token"]}))
                print("Appairage accorde. IMPORTANT : donner la permission 'Modification des reglages de la Freebox' "
                      "a l'application dans FreeboxOS (Parametres > Gestion des acces > Applications).")
                return
            if st.get("status") in ("denied", "timeout", "unknown"):
                raise ApiError("appairage refuse: %s" % st.get("status"))
            time.sleep(1)
        raise ApiError("appairage: delai depasse")


# ---------------------------------------------------------------- hotes

def norm_mac(m):
    m = m.strip().upper().replace("-", ":")
    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", m):
        raise SystemExit("MAC invalide: %s" % m)
    return m


def is_random(mac):
    return bool(int(mac[:2], 16) & 2)


def parse_host(h):
    l2 = h.get("l2ident") or {}
    if l2.get("type") != "mac_address":
        return None
    mac = l2["id"].upper()
    name = h.get("primary_name") or ""
    if not name:
        for n in h.get("names") or []:
            if n.get("name"):
                name = n["name"]
                break
    name = name or h.get("default_name") or ""
    ips = [c for c in (h.get("l3connectivities") or []) if c.get("af") == "ipv4"]
    ips.sort(key=lambda c: (not c.get("active"), -(c.get("last_activity") or 0)))
    ap = h.get("access_point") or {}
    wi = ap.get("wifi_information") or {}
    return {
        "mac": mac, "name": name, "vendor": h.get("vendor_name") or "", "ip": ips[0]["addr"] if ips else "",
        "host_type": h.get("host_type") or "", "active": bool(h.get("active")),
        "conn": ap.get("connectivity_type") or ("inconnu" if h.get("active") else ""),
        "ssid": wi.get("ssid") or "", "band": wi.get("band") or "", "bssid": (wi.get("bssid") or "").upper(),
        "ap_type": ap.get("type") or "", "ap_uid": str(ap.get("uid") or ""), "random": is_random(mac),
    }


def normname(n):
    return re.sub(r"[^a-z0-9]", "", (n or "").lower())


def is_protected(d):
    return d["mac"] in PROTECT_MACS or d["ip"] in PROTECT_IPS or d["host_type"].startswith("freebox")


# ---------------------------------------------------------------- alertes (outbox)

def push_alert(kind, subject, body, mac="", test=False):
    OUTBOX.mkdir(parents=True, exist_ok=True)
    aid = "%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), (mac.replace(":", "")[-4:] or kind))
    a = {"id": aid, "ts": now(), "kind": kind, "mac": mac, "subject": subject, "body": body, "test": test}
    write_private(OUTBOX / (aid + ".json"), json.dumps(a, ensure_ascii=False, indent=2))
    log("ALERTE %s: %s" % (kind, subject))
    return aid


# ---------------------------------------------------------------- canaux d'alerte (SMTP, webhook, fichier)

def smtp_password():
    f = os.environ.get("WG_SMTP_PASSWORD_FILE")
    if f:
        try:
            return Path(f).read_text().strip()
        except OSError:
            return ""
    return os.environ.get("WG_SMTP_PASSWORD", "")


def channels_configured():
    ch = []
    if os.environ.get("WG_SMTP_HOST") and os.environ.get("WG_MAIL_TO"):
        ch.append("smtp")
    if os.environ.get("WG_WEBHOOK_URL"):
        ch.append("webhook")
    return ch


def send_smtp(a):
    host = os.environ["WG_SMTP_HOST"]
    security = os.environ.get("WG_SMTP_SECURITY", "starttls").lower()
    port = int(os.environ.get("WG_SMTP_PORT") or ("465" if security == "ssl" else "587"))
    user = os.environ.get("WG_SMTP_USER", "")
    sender = os.environ.get("WG_MAIL_FROM") or user or "wifi-guard@localhost"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, os.environ["WG_MAIL_TO"], a["subject"]
    msg.set_content(a["body"] + "\n\n(alerte %s)" % a["id"])
    if security == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=30, context=ssl.create_default_context())
    else:
        s = smtplib.SMTP(host, port, timeout=30)
        if security == "starttls":
            s.starttls(context=ssl.create_default_context())
    with s:
        if user:
            s.login(user, smtp_password())
        s.send_message(msg)


def send_webhook(a):
    headers = {"Content-Type": "application/json"}
    if os.environ.get("WG_WEBHOOK_AUTH"):
        headers["Authorization"] = os.environ["WG_WEBHOOK_AUTH"]
    payload = {k: a.get(k) for k in ("id", "ts", "kind", "mac", "subject", "body")}
    payload["text"] = a["subject"] + "\n\n" + a["body"]     # champ pratique (Slack, Discord, ntfy...)
    req = urllib.request.Request(os.environ["WG_WEBHOOK_URL"], data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def flush_outbox():
    """Envoie les alertes en attente par les canaux configures. Sans canal : elles restent dans outbox/
    (a recuperer avec `outbox --json`). Une alerte n'est acquittee que si tous les canaux ont reussi."""
    chans = channels_configured()
    if not chans or not OUTBOX.exists():
        return
    for p in sorted(OUTBOX.glob("*.json")):
        a = load_json(p, None)
        if not a:
            continue
        if a.get("test"):
            cmd_outbox_ack(a["id"])
            continue
        try:
            if "smtp" in chans:
                send_smtp(a)
            if "webhook" in chans:
                send_webhook(a)
        except Exception as e:
            log("envoi d'alerte impossible (%s) : nouvel essai au prochain scan" % type(e).__name__)
            return
        cmd_outbox_ack(a["id"])
        log("alerte envoyee : %s" % a["id"])


def describe(d):
    t = []
    t.append("Nom       : %s" % (d["name"] or "(sans nom)"))
    t.append("MAC       : %s%s" % (d["mac"], "  (adresse aleatoire / 'locally administered' : telephone avec MAC privee ?)" if d["random"] else ""))
    t.append("IP        : %s" % (d["ip"] or "?"))
    t.append("Fabricant : %s" % (d["vendor"] or "inconnu"))
    t.append("Type      : %s" % (d["host_type"] or "?"))
    if d["conn"] == "wifi":
        t.append("Connexion : Wi-Fi %s %s%s%s" % (d["band"], d["ssid"],
                 " (reseau invite)" if d.get("guest") else "",
                 " via repeteur" if d["ap_type"] == "repeater" else ""))
    else:
        t.append("Connexion : %s" % (d["conn"] or "?"))
    return "\n".join(t)


RESP = ("Reponse : wifi-guard-ctl allow %(mac)s   (c'est un de mes appareils : debloque et ajoute a l'inventaire)\n"
        "          wifi-guard-ctl deny %(mac)s    (inconnu : reste bloque / plus de rappel)")


def unknown_alert(d, u, blocked, reason, reminder=0):
    if blocked:
        st = "BLOQUE provisoirement (filtre MAC Wi-Fi) en attendant votre decision."
    else:
        st = "NON bloque : %s" % reason
    pre = "RAPPEL %d : " % reminder if reminder else ""
    subject = "[WIFI-GUARD] %sappareil inconnu : %s (%s)" % (pre, d["name"] or "sans nom", d["mac"])
    body = ("WIFI-GUARD alerte appareil inconnu\n\n%s\n\nPremiere detection : %s\nEtat : %s\n\n%s\n"
            "Verifiez si c'est un de vos appareils.\n") % (
        describe(d), fmt(u["first_seen"]), st, RESP % {"mac": d["mac"]})
    return push_alert("unknown_device" if not reminder else "reminder", subject, body, d["mac"])


# ---------------------------------------------------------------- blocage

def can_block(fb, st, d, cfg):
    """Retourne (ok, raison_si_non)."""
    if not cfg.get("block"):
        return False, "blocage desactive (interrupteur OFF), alerte seulement"
    if d["conn"] != "wifi":
        return False, "appareil en %s : l'API Freebox ne permet pas de le bloquer (filtre MAC Wi-Fi seulement)" % (d["conn"] or "connexion inconnue")
    if is_protected(d):
        return False, "appareil protege (Freebox / liste de protection)"
    if len(st["devices"]) < MIN_INVENTORY_TO_BLOCK:
        return False, "inventaire trop petit, securite"
    recent = [t for t in st["blocks"] if t > now() - 3600]
    if len(recent) >= MAX_BLOCKS_PER_HOUR:
        return False, "disjoncteur : trop de blocages cette heure"
    try:
        cur = fb.wifi_config().get("mac_filter_state")
    except ApiError as e:
        return False, "etat du filtre MAC illisible (%s)" % e
    if cur == "whitelist":
        return False, "le filtre MAC Freebox est en WHITELIST : je n'y touche pas (couperait le Wi-Fi de la maison)"
    if cur not in ("disabled", "blacklist"):
        return False, "etat du filtre MAC inattendu (%s)" % cur
    if not fb.permissions.get("settings"):
        return False, "l'application n'a pas la permission 'settings' sur la Freebox"
    return True, ""


def do_block(fb, mac, comment):
    ent = fb.add_blacklist(mac, comment)
    fid = ent.get("id") or (mac + "-blacklist")
    try:
        cur = fb.wifi_config().get("mac_filter_state")
        if cur == "disabled":
            fb.set_filter_state("blacklist")
        cur = fb.wifi_config().get("mac_filter_state")
        listed = any(f.get("mac", "").upper() == mac and f.get("type") == "blacklist" for f in fb.mac_filters())
        if cur != "blacklist" or not listed:
            raise ApiError("verification du blocage echouee (etat=%s, liste=%s)" % (cur, listed))
    except Exception:
        try:
            fb.del_filter(fid)
        except Exception:
            pass
        raise
    return fid


def do_unblock(fb, mac):
    n = 0
    for f in fb.mac_filters():
        if f.get("mac", "").upper() == mac and f.get("type") == "blacklist":
            fb.del_filter(f["id"])
            n += 1
    return n


# ---------------------------------------------------------------- scan

def known_names(st):
    names = {}
    for mac, dv in st["devices"].items():
        for n in [dv.get("name")] + dv.get("aliases", []):
            k = normname(n)
            if k and k not in GENERIC_NAMES:
                names[k] = dv.get("name") or n
    return names


def process(fb, st, hosts, cfg, dry=False, test=False):
    """Traite une liste d'hotes bruts. Modifie st. Retourne la liste de messages de log."""
    out = []
    t = now()
    parsed = [p for p in (parse_host(h) for h in hosts) if p]
    if st["mode"] == "learn":
        for d in parsed:
            if d["mac"] not in st["devices"]:
                st["devices"][d["mac"]] = {"name": d["name"], "vendor": d["vendor"], "ip": d["ip"], "host_type": d["host_type"],
                                           "conn": d["conn"], "ssid": d["ssid"], "band": d["band"], "random": d["random"],
                                           "first_seen": t, "last_seen": t if d["active"] else 0, "aliases": [], "learned": True}
            else:
                st["devices"][d["mac"]]["last_seen"] = t if d["active"] else st["devices"][d["mac"]].get("last_seen", 0)
        if t >= st["learn_until"]:
            st["mode"] = "monitor"
            out.append("fin de l'apprentissage : %d appareils, passage en surveillance" % len(st["devices"]))
        return out

    new = []
    for d in parsed:
        dv = st["devices"].get(d["mac"])
        if dv:
            if d["active"]:
                dv["last_seen"] = t
                dv["ip"] = d["ip"] or dv.get("ip", "")
                dv["conn"] = d["conn"] or dv.get("conn", "")
                if d["name"] and d["name"] != dv.get("name"):      # nom change : pas d'alerte, on garde l'historique
                    al = dv.setdefault("aliases", [])
                    if dv.get("name") and dv["name"] not in al:
                        al.append(dv["name"])
                    del al[:-5]
                    dv["name"] = d["name"]
            continue
        if not d["active"]:
            continue
        u = st["unknown"].get(d["mac"])
        if u is None:
            u = st["unknown"][d["mac"]] = {"first_seen": t, "last_seen": t, "status": "pending", "blocked": False,
                                           "filter_id": "", "alerted_at": 0, "reminders": 0, "name": d["name"]}
            new.append((d, u))
        else:
            u["last_seen"] = t
            u["name"] = d["name"] or u.get("name", "")
            u.update({"ip": d["ip"]})
            if u["status"] == "pending" and u["reminders"] < len(REMINDERS) and t - u["alerted_at"] >= REMINDERS[u["reminders"]]:
                u["reminders"] += 1
                u["alerted_at"] = t
                unknown_alert(d, u, u["blocked"], "pas de blocage actif", reminder=u["reminders"])
            if u["status"] == "denied" and not u["blocked"]:
                pass  # maintien : traite par la commande deny
    if not new:
        return out

    try:
        labels = fb.bss_labels() if (not dry and any(d["conn"] == "wifi" for d, _ in new)) else {}
    except ApiError:
        labels = {}
    for d, u in new:
        lab = labels.get(d["bssid"], "")
        d["guest"] = ("invit" in lab.lower()) if lab else None

    anomaly = len(new) > MAX_NEW_PER_SCAN
    if anomaly:
        lines = "\n".join("- %s (%s) %s" % (d["name"] or "sans nom", d["mac"], d["conn"]) for d, _ in new)
        push_alert("anomaly", "[WIFI-GUARD] %d appareils inconnus d'un coup (aucun blocage)" % len(new),
                   "WIFI-GUARD : %d appareils inconnus detectes dans le meme scan. Soupcon d'anomalie "
                   "(inventaire perdu ? coupure ?). Aucun blocage automatique.\n\n%s\n\nFaire `wifi-guard-ctl list unknown` "
                   "puis allow/deny un par un." % (len(new), lines), test=test)
        for d, u in new:
            u["alerted_at"] = t
        return out + ["anomalie : %d inconnus" % len(new)]

    kn = known_names(st)
    for d, u in new:
        # MAC aleatoire dont le nom correspond a un appareil connu : alerte groupee, jamais de blocage
        if d["random"] and normname(d["name"]) in kn and normname(d["name"]) not in GENERIC_NAMES:
            key = normname(d["name"])
            u["status"] = "probable_random"
            u["random_of"] = kn[key]
            last = st["random_alerts"].get(key, 0)
            u["alerted_at"] = t
            if t - last > 24 * 3600:
                st["random_alerts"][key] = t
                push_alert("probable_random",
                           "[WIFI-GUARD] info : MAC aleatoire probable de '%s' (%s)" % (kn[key], d["mac"]),
                           "WIFI-GUARD (information, pas d'urgence) : nouvelle adresse MAC %s au meme nom que "
                           "l'appareil connu '%s'. Probablement un telephone avec adresse MAC privee/aleatoire. "
                           "Non bloque.\n\n%s\n\nSi c'est bien lui : wifi-guard-ctl allow %s" % (d["mac"], kn[key], describe(d), d["mac"]),
                           d["mac"], test=test)
            out.append("MAC aleatoire probable de %s : %s" % (kn[key], d["mac"]))
            continue
        ok, why = (False, "simulation (aucun appel a la Freebox)") if dry else can_block(fb, st, d, cfg)
        blocked = False
        if ok:
            try:
                u["filter_id"] = do_block(fb, d["mac"], "wifi-guard provisoire " + time.strftime("%d/%m %H:%M"))
                u["blocked"] = blocked = True
                st["blocks"].append(t)
                del st["blocks"][:-50]
                u["status"] = "blocked"
                out.append("BLOQUE %s" % d["mac"])
            except Exception as e:
                why = "blocage tente mais echoue (%s)" % e
        u["alerted_at"] = t
        u["block_reason"] = why
        unknown_alert(d, u, blocked, why) if not test else push_alert(
            "unknown_device", "[WIFI-GUARD] TEST appareil inconnu : %s (%s)" % (d["name"] or "sans nom", d["mac"]),
            "TEST (aucun blocage reel, a ignorer)\n\n" + describe(d) + "\n\nEtat : " + (why or "bloque") + "\n\n" + RESP % {"mac": d["mac"]},
            d["mac"], test=True)
        out.append("inconnu %s : %s" % (d["mac"], why or "bloque"))
    return out


def api_health(st, ok, err=""):
    a = st["api"]
    t = now()
    if ok:
        if a["alerted"]:
            push_alert("api_up", "[WIFI-GUARD] info : la Freebox repond a nouveau", "WIFI-GUARD : l'API Freebox repond de nouveau (information).")
        a.update({"fail_since": 0, "alerted": False})
    else:
        if not a["fail_since"]:
            a["fail_since"] = t
        if not a["alerted"] and t - a["fail_since"] >= API_DOWN_AFTER:
            a["alerted"] = True
            push_alert("api_down", "[WIFI-GUARD] la surveillance ne joint plus la Freebox",
                       "WIFI-GUARD : l'API de la Freebox ne repond plus depuis plus de 30 min (%s). "
                       "Verifier la Freebox, le jeton d'appairage ou le conteneur." % err)


def scan_once(fb, dry=False):
    with Lock():
        st = load_json(STATE_F, None) or new_state()
        try:
            hosts = fb.hosts()
        except Exception as e:
            api_health(st, False, str(e))
            write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
            raise
        api_health(st, True)
        msgs = process(fb, st, hosts, config(), dry=dry)
        if not dry:
            write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
        return st, msgs


def run():
    log("wifi-guard demarre (intervalle %ss, API %s, canaux d'alerte : %s)" % (INTERVAL, FBX_URL, ", ".join(channels_configured()) or "fichier outbox seul"))
    fb = Freebox()
    backoff = 0
    while True:
        try:
            st, msgs = scan_once(fb)
            for m in msgs:
                log(m)
            backoff = 0
            flush_outbox()
        except Exception as e:
            backoff = min(300, (backoff or 15) * 2)
            log("erreur: %s (nouvel essai dans %ss)" % (e, backoff))
            fb.session = None
        time.sleep(max(INTERVAL, backoff))


# ---------------------------------------------------------------- commandes

def cmd_allow(mac, label=None):
    mac = norm_mac(mac)
    fb = Freebox()
    with Lock():
        st = load_json(STATE_F, None) or new_state()
        u = st["unknown"].pop(mac, None)
        removed = 0
        try:
            removed = do_unblock(fb, mac)
        except Exception as e:
            print("ATTENTION : deblocage Freebox impossible (%s)" % e)
            if u:
                st["unknown"][mac] = u
                write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
            return 1
        dv = st["devices"].setdefault(mac, {"first_seen": now(), "aliases": []})
        dv.update({"name": label or (u or {}).get("name") or dv.get("name", ""), "last_seen": now(), "allowed_by": "user",
                   "random": is_random(mac)})
        write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
    print("OK : %s autorise, ajoute a l'inventaire (%d filtre(s) MAC retire(s))." % (mac, removed))
    return 0


def cmd_deny(mac):
    mac = norm_mac(mac)
    fb = Freebox()
    cfg = config()
    with Lock():
        st = load_json(STATE_F, None) or new_state()
        u = st["unknown"].setdefault(mac, {"first_seen": now(), "last_seen": now(), "blocked": False, "reminders": 99,
                                           "alerted_at": now(), "name": ""})
        u["status"] = "denied"
        u["reminders"] = 99
        msg = ""
        if not u.get("blocked"):
            d = {"mac": mac, "ip": "", "host_type": "", "conn": "wifi", "ap_type": ""}
            if mac in st["devices"]:
                print("REFUS : %s est dans l'inventaire, je ne le bloque pas (utilise forget d'abord)." % mac)
                return 1
            ok, why = can_block(fb, st, d, cfg)
            if ok:
                u["filter_id"] = do_block(fb, mac, "wifi-guard refuse")
                u["blocked"] = True
                st["blocks"].append(now())
                msg = "bloque."
            else:
                msg = "non bloque : %s." % why
        else:
            msg = "reste bloque."
        write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
    print("OK : %s refuse, %s Plus de rappel." % (mac, msg))
    return 0


def cmd_forget(mac):
    mac = norm_mac(mac)
    with Lock():
        st = load_json(STATE_F, None) or new_state()
        a = st["devices"].pop(mac, None)
        b = st["unknown"].pop(mac, None)
        write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
    print("OK : %s oublie (%s)." % (mac, "inventaire" if a else "inconnu" if b else "absent"))


def cmd_status(as_json=False):
    st = load_json(STATE_F, None)
    cfg = config()
    if not st:
        print("pas encore d'etat (le daemon n'a pas fait de scan)")
        return
    unk = st["unknown"]
    info = {"mode": st["mode"], "block_switch": "ON" if cfg["block"] else "OFF (alerte seulement)",
            "learn_until": fmt(st["learn_until"]) if st["mode"] == "learn" else None,
            "known_devices": len(st["devices"]),
            "unknown": {m: {"name": u.get("name"), "status": u["status"], "blocked": u["blocked"], "since": fmt(u["first_seen"])}
                        for m, u in unk.items()},
            "outbox_pending": len(list(OUTBOX.glob("*.json"))) if OUTBOX.exists() else 0,
            "api_fail_since": fmt(st["api"]["fail_since"]) if st["api"]["fail_since"] else None}
    if as_json:
        print(json.dumps(info, ensure_ascii=False, indent=1))
    else:
        for k, v in info.items():
            print("%s: %s" % (k, v))


def cmd_list(which):
    st = load_json(STATE_F, None) or new_state()
    if which == "unknown":
        for m, u in st["unknown"].items():
            print("%s  %-14s bloque=%s  %s  %s" % (m, u["status"], u["blocked"], fmt(u["first_seen"]), u.get("name", "")))
    else:
        for m, d in sorted(st["devices"].items(), key=lambda x: x[1].get("name", "")):
            print("%s  %-28s %-5s derniere vue %s%s" % (m, (d.get("name") or "")[:28], d.get("conn", ""), fmt(d.get("last_seen", 0)),
                                                         "  [MAC aleatoire]" if d.get("random") else ""))


def cmd_outbox(as_json):
    items = sorted(OUTBOX.glob("*.json")) if OUTBOX.exists() else []
    data = [json.loads(p.read_text()) for p in items]
    if as_json:
        print(json.dumps(data, ensure_ascii=False))
    else:
        for a in data:
            print("%s  %s  %s" % (a["id"], a["kind"], a["subject"]))


def cmd_outbox_ack(aid):
    p = OUTBOX / (re.sub(r"[^0-9A-Za-z_-]", "", aid) + ".json")
    if not p.exists():
        print("introuvable")
        return 1
    SENT.mkdir(parents=True, exist_ok=True)
    p.rename(SENT / p.name)
    for old in sorted(SENT.glob("*.json"))[:-200]:
        old.unlink()
    print("ack %s" % aid, flush=True)
    return 0


def cmd_simulate(args):
    """Test sec : fait traiter un faux appareil inconnu (aucun appel d'ecriture, etat non modifie)."""
    mac = norm_mac(args[0]) if args else ":".join(["02", "00", "00", "00", "00", "99"])
    name = args[1] if len(args) > 1 else "TEST-appareil-factice"
    conn = args[2] if len(args) > 2 else "wifi"
    host = {"l2ident": {"id": mac, "type": "mac_address"}, "active": True, "primary_name": name, "vendor_name": "Test",
            "host_type": "smartphone", "l3connectivities": [{"addr": "192.0.2.250", "af": "ipv4", "active": True}],
            "access_point": {"connectivity_type": conn, "type": "freebox",
                             "wifi_information": {"ssid": "WIFI", "band": "5g", "bssid": ""}} if conn == "wifi"
            else {"connectivity_type": "ethernet", "type": "freebox"}}
    st = load_json(STATE_F, None) or new_state()
    st = json.loads(json.dumps(st))
    st["mode"] = "monitor"
    st["unknown"].pop(mac, None)
    for m in process(Freebox(), st, [host], config(), dry=True, test=True):
        print(m)


def cmd_selftest():
    """Verifie l'acces API, le mode du filtre MAC et les permissions (lecture seule)."""
    fb = Freebox()
    fb.login()
    c = fb.wifi_config()
    print("api:", fb.base, "| permissions settings:", fb.permissions.get("settings"))
    print("filtre MAC:", c.get("mac_filter_state"), "| entrees:", len(fb.mac_filters()))
    print("hotes:", len(fb.hosts()))


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__ + "\nCommandes : run | status [--json] | list [known|unknown] | allow MAC [nom] | deny MAC | forget MAC |\n"
              "  mode learn|monitor | block on|off | outbox [--json] | outbox-ack ID | simulate [MAC nom wifi|ethernet] |\n"
              "  scan [--dry] | selftest | pair | flush")
        return 0
    c = a[0]
    if c == "run":
        run()
    elif c == "status":
        cmd_status("--json" in a)
    elif c == "list":
        cmd_list(a[1] if len(a) > 1 else "known")
    elif c == "allow":
        return cmd_allow(a[1], " ".join(a[2:]) or None)
    elif c == "deny":
        return cmd_deny(a[1])
    elif c == "forget":
        cmd_forget(a[1])
    elif c == "mode":
        with Lock():
            st = load_json(STATE_F, None) or new_state()
            st["mode"] = a[1]
            if a[1] == "learn":
                st["learn_until"] = now() + LEARN_MIN * 60
            write_private(STATE_F, json.dumps(st, ensure_ascii=False, indent=1))
        print("mode:", a[1])
    elif c == "block":
        cfg = config()
        cfg["block"] = a[1] == "on"
        save_config(cfg)
        print("blocage:", "ON" if cfg["block"] else "OFF (alerte seulement)")
    elif c == "outbox":
        cmd_outbox("--json" in a)
    elif c == "outbox-ack":
        return cmd_outbox_ack(a[1])
    elif c == "simulate":
        cmd_simulate(a[1:])
    elif c == "scan":
        st, msgs = scan_once(Freebox(), dry="--dry" in a)
        print("mode=%s connus=%d inconnus=%d" % (st["mode"], len(st["devices"]), len(st["unknown"])))
        for m in msgs:
            print(m)
    elif c == "selftest":
        cmd_selftest()
    elif c == "flush":
        flush_outbox()
    elif c == "pair":
        Freebox().pair()
    else:
        print("commande inconnue")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

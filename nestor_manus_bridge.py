#!/usr/bin/env python3
# nestor_manus_bridge.py -- liaison directe Nestor (VPS / OpenClaw) <-> Manus API v2
# v1.5 -- 2026-11-03 -- stdlib only, python3.8+
#
# v1.5 : PORTE DE REGISTRE (allow-list publique des sceaux emis par Manus).
#        Le pont ne recalcule plus le sceau seul : il exige aussi que le
#        sceau soit PRESENT dans approved_turns.json. Deux effets :
#          - tour non enregistre (emetteur parallele, R-09) -> quarantaine,
#            exit 8, sans effet sur last_turn (le tour n'existe pas) ;
#          - apres rotation de cle, les sceaux de l'ancienne cle sont morts
#            cryptographiquement ET historiquement (leur empreinte figure
#            dans le registre mais ne verifie plus avec la nouvelle cle) ;
#            la continuite d'identite du registre est la seule autorite.
#        v2 OBLIGATOIRE a partir du tour v2_from (default 000009) : les tours
#        ulterieurs doivent porter le sceau liant le corps (sha16). Format
#        v1 accepte en dessous (historique 000001-000008).
#        Scan CHRONOLOGIQUE en poll : tous les messages assistant non vus
#        entre la borne et le present sont evalues dans l'ordre. Limitation
#        du canal prise en compte : MAX_BODY_BYTES 1800 (coupe mesuree a
#        2048 o sur le canal ; un corps plus long arrive tronque et le v2
#        rejette a juste titre).
# v1.4.1 : compteur seq protege. L'etat est desormais sauvegarde AVANT l'appel
#        best-effort `baseline` ; un echec reseau de celui-ci ne provoque plus
#        la re-emission du meme seq au tour suivant (bug constate : seq=3
#        emis 2 fois).
# v1.4 : sceau v2 LIANT LE CORPS du message : la ligne #NESTOR/v2 embarque
#        sha16 = sha256(corps sans la ligne de sceau)[:16], et le HMAC porte
#        sur "NESTOR/v2|turn=...|verdict=...|sha16:...". Un corps substitue
#        ne verifie plus. Compatibilite v1 preservee en dessous de v2_from.
# v1.3 : commande `inseal` -- Nestor verifie lui-meme le sceau entrant de Manus
#        pour publier une ligne seal_check=ok fondee.
# v1.2 : extraction TOLERANTE du sceau entrant : ligne cherchee dans tout le
#        message, debarrassee des habillages Markdown (fences, gras).
# v1.1 : verification automatique du sceau entrant, rejeu par numero de tour,
#        quarantaine des messages non scelles.
#
# Secrets (jamais dans un prompt, jamais en clair dans un log) :
#   /root/.secrets/manus_api_key   (600)  cle API, en-tete x-manus-api-key
#   /root/.secrets/nestor_hmac     (600)  secret partage HMAC-SHA256
#
# Usage :
#   ./nestor_manus_bridge.py selftest
#   ./nestor_manus_bridge.py send --body /chemin/rapport.md --type report \
#        --task-ref T12 --self-score 7 [--new] [--project-id ID] [--dry-run]
#   ./nestor_manus_bridge.py poll --timeout 2700 [--rescan] [--limit N]
#   ./nestor_manus_bridge.py verify --line 'NESTOR1|seq=124|...'
#   ./nestor_manus_bridge.py inseal --turn 000002 --verdict 8 --sig <16 hex> \
#        [--body /chemin/corps.md | --sha16 empreinte]   (mode v2)
#   ./nestor_manus_bridge.py credits
#   ./nestor_manus_bridge.py state
#
# Codes de sortie : 0 ok, 1 usage, 2 API, 3 reseau, 4 timeout/erreur tache,
#                   5 sceau entrant invalide, 6 rejeu detecte, 7 non scelle,
#                   8 tour non enregistre au registre (R-09)

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = os.environ.get("MANUS_API_BASE", "https://api.manus.ai")
STATE_PATH = os.environ.get("NESTOR_STATE", "/root/.nestor/manus_state.json")
KEY_PATH = os.environ.get("NESTOR_KEY_FILE", "/root/.secrets/manus_api_key")
HMAC_PATH = os.environ.get("NESTOR_HMAC_FILE", "/root/.secrets/nestor_hmac")
QUAR_PATH = os.environ.get("NESTOR_QUAR", "/root/.nestor/quarantine")
APPROVED_PATH = os.environ.get(
    "NESTOR_APPROVED",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "approved_turns.json"))
PROTO = "NESTOR1"
MAX_BODY_BYTES = 1800
PROFILES = ["standard", "lite"]

SEAL_RE = re.compile(
    r"^#NESTOR/v1\|turn=(\d{6})\|verdict=([0-9]{1,2}|na)\|seal=([0-9a-f]{16})$"
)
SEAL_RE_V2 = re.compile(
    r"^#NESTOR/v2\|turn=(\d{6})\|verdict=([0-9]{1,2}|na)\|sha16=([0-9a-f]{16})\|seal=([0-9a-f]{16})$"
)
TURN_RE = re.compile(r"^\d{6}$")
SEAL_HEX_RE = re.compile(r"^[0-9a-f]{16}$")


def die(msg, code=1):
    sys.stderr.write("ERR " + msg + "\n")
    sys.exit(code)


def read_secret(path, env_name):
    v = os.environ.get(env_name, "").strip()
    if v:
        return v
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"task_id": None, "seq": 0, "last_seen": None, "last_turn": 0}


def save_state(st):
    d = os.path.dirname(STATE_PATH) or "."
    os.makedirs(d, exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_PATH)


def sign(secret, payload):
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]


def attestation(secret, seq, ts, typ, agent):
    base = "%s|seq=%d|ts=%d|type=%s|agent=%s" % (PROTO, seq, ts, typ, agent)
    return base + "|sig=" + sign(secret, base)


def check_attestation(secret, line, window=600, now=None):
    now = int(time.time()) if now is None else now
    if not line.startswith(PROTO + "|"):
        return False, "prefixe absent"
    if "|sig=" not in line:
        return False, "signature absente"
    base, sig = line.rsplit("|sig=", 1)
    if not hmac.compare_digest(sign(secret, base), sig.strip()):
        return False, "signature invalide"
    fields = dict(p.split("=", 1) for p in base.split("|")[1:] if "=" in p)
    if "ts" not in fields:
        return False, "ts absent"
    if abs(now - int(fields["ts"])) > window:
        return False, "horodatage hors fenetre (%ss)" % window
    return True, fields


# ---------------------------------------------------------------- registre

def load_approved(path=None):
    """Charge l'allow-list des tours enregistres. FAIL-CLOSED : toute erreur
    de lecture ou de forme refuse le service (exit 8 au poll)."""
    p = path or APPROVED_PATH
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        die("registre illisible ou mal forme (%s) : %s -- porte fermee" % (p, e), 8)
    turns = data.get("turns")
    if not isinstance(turns, dict):
        die("registre sans table 'turns' -- porte fermee", 8)
    for t, entry in turns.items():
        if not TURN_RE.match(str(t)) or not isinstance(entry, dict) \
                or not SEAL_HEX_RE.match(str(entry.get("seal", ""))):
            die("entree registre invalide : %s -- porte fermee" % t, 8)
    data.setdefault("v2_from", "999999")
    return data


def seal_of_line(content):
    """Renvoie (seal, version, turn) de la premiere ligne de sceau reconnue."""
    line = find_seal_line(content)
    if line is None:
        return None, None, None
    m2 = SEAL_RE_V2.match(line)
    if m2:
        return m2.group(4), 2, m2.group(1)
    m1 = SEAL_RE.match(line)
    if m1:
        return m1.group(3), 1, m1.group(1)
    return None, None, None


def evaluate_incoming(secret, content, approved):
    """Verdict complet d'un message entrant.

    -> (decision, turn, verdict, raison, version)
    decision dans {"accept", "quarantine", "non_scelle"}

    Ordre des gardes : forme -> cryptographie -> enregistrement -> version.
    Un tour non enregistre n'existe pas : il est quarantaine SANS toucher
    a last_turn (sinon le tour 000009 reel, arrive apres, serait rejete
    comme rejeu de 000008-jumeau).
    """
    line = find_seal_line(content)
    if line is None:
        return "non_scelle", None, None, "ligne de sceau absente ou mal formee", None
    version = 2 if SEAL_RE_V2.match(line) else 1
    ok, turn, verdict, raison = check_content(secret, content)
    if not ok:
        return "quarantine", turn, verdict, raison, version
    entry = approved.get("turns", {}).get(turn)
    if entry is None:
        return "quarantine", turn, verdict, \
            "tour %s non enregistre au registre (R-09 : emetteur parallele, sans effet)" % turn, \
            version
    if int(turn) >= int(approved.get("v2_from", "999999")) and version != 2:
        return "quarantine", turn, verdict, \
            "format v1 interdit au tour %s (v2_from=%s) : le sceau v1 est mort" % (
                turn, approved.get("v2_from")), version
    seal, _, _ = seal_of_line(content)
    if not hmac.compare_digest(entry["seal"], seal):
        return "quarantine", turn, verdict, \
            "sceau != registre (emission parallele du meme tour : R-09)", version
    return "accept", turn, verdict, "ok", version


# ---------------------------------------------------------------- sceau entrant


def seal_base(turn, verdict):
    return "NESTOR/v1|turn=%s|verdict=%s" % (turn, verdict)


def make_seal(secret, turn, verdict):
    return hmac.new(secret.encode(), seal_base(turn, verdict).encode(),
                    hashlib.sha256).hexdigest()[:16]


def hash16(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()[:16]


def make_seal_v2(secret, turn, verdict, empreinte):
    material = "NESTOR/v2|turn=%s|verdict=%s|sha16:%s" % (turn, verdict, empreinte)
    return hmac.new(secret.encode(), material.encode(), hashlib.sha256).hexdigest()[:16]


def check_seal(secret, line):
    """Verifie une ligne de sceau deja isolee. -> (ok, turn, verdict, raison)."""
    m = SEAL_RE.match(line.strip())
    if not m:
        return False, None, None, "ligne de sceau absente ou mal formee"
    turn, verdict, seal = m.group(1), m.group(2), m.group(3)
    if not hmac.compare_digest(make_seal(secret, turn, verdict), seal):
        return False, turn, verdict, "sceau invalide"
    return True, turn, verdict, "ok"


def strip_markup(raw):
    """Deshabille une ligne : fences ``` , gras **, backticks, espaces."""
    s = raw.strip()
    if s.startswith("```"):
        return ""
    s = s.replace("`", "").replace("**", "").strip()
    return s


def find_seal_line(content):
    """Cherche la ligne de sceau (v1 ou v2) dans tout le message (premier match)."""
    for raw in content.split("\n"):
        cand = strip_markup(raw)
        if cand and (SEAL_RE_V2.match(cand) or SEAL_RE.match(cand)):
            return cand
    return None


def body_sans_sceau(content):
    """Corps du message = tout sauf la PREMIERE ligne de sceau reconnue."""
    sortie, retire = [], False
    for raw in content.split("\n"):
        if not retire:
            cand = strip_markup(raw)
            if cand and (SEAL_RE_V2.match(cand) or SEAL_RE.match(cand)):
                retire = True
                continue
        sortie.append(raw)
    return "\n".join(sortie)


def check_content(secret, content):
    """Verifie un message entrant complet. -> (ok, turn, verdict, raison)."""
    line = find_seal_line(content)
    if line is None:
        return False, None, None, "ligne de sceau absente ou mal formee"
    m2 = SEAL_RE_V2.match(line)
    if m2:
        turn, verdict, empreinte, seal = m2.groups()
        if hash16(body_sans_sceau(content).encode("utf-8")) != empreinte:
            return False, turn, verdict, "corps modifie (sha16 != empreinte du corps)"
        attendu = make_seal_v2(secret, turn, verdict, empreinte)
        if not hmac.compare_digest(attendu, seal):
            return False, turn, verdict, "sceau v2 invalide"
        return True, turn, verdict, "ok (v2, corps lie)"
    return check_seal(secret, line)


def quarantine(content, why, turn=None):
    os.makedirs(QUAR_PATH, exist_ok=True)
    name = "turn-%s-%d.md" % (turn or "XXXXXX", int(time.time()))
    p = os.path.join(QUAR_PATH, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write("RAISON: %s\n---\n%s" % (why, content))
    os.chmod(p, 0o600)
    return p


# ---------------------------------------------------------------- HTTP


def api(method, path, params=None, body=None, key=None, dry=False):
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if key:
        headers["x-manus-api-key"] = key
    if dry:
        print("DRY %s %s" % (method, url))
        print("DRY headers: " + json.dumps(
            {k: (v[:6] + "..." if k == "x-manus-api-key" else v) for k, v in headers.items()}))
        if data:
            print("DRY body:\n" + data.decode("utf-8"))
        return {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")[:600]
        die("HTTP %s sur %s : %s" % (e.code, path, txt), 2)
    except urllib.error.URLError as e:
        die("reseau injoignable (%s) sur %s" % (e.reason, path), 3)


# ---------------------------------------------------------------- composition


def compose(secret, seq, typ, agent, task_ref, body_md, self_score=None, artifacts=None):
    ts = int(time.time())
    att = attestation(secret, seq, ts, typ, agent)
    meta = {
        "v": "nestor1",
        "seq": seq,
        "ts": ts,
        "type": typ,
        "agent": agent,
        "task_ref": task_ref,
        "self_score": self_score,
        "artifacts": artifacts or [],
        "body_bytes": len(body_md.encode("utf-8")),
    }
    text = "%s\n\n# %s seq=%s task_ref=%s\n\n%s\n\n```json\n%s\n```\n" % (
        att, typ.upper(), seq, task_ref, body_md.rstrip(),
        json.dumps(meta, ensure_ascii=False, sort_keys=True))
    return text, meta


# ---------------------------------------------------------------- commandes


def cmd_selftest(a):
    s = "0" * 32
    line = attestation(s, 7, int(time.time()), "report", "main")
    ok, info = check_attestation(s, line)
    assert ok, info
    bad = line[:-1] + ("0" if line[-1] != "0" else "1")
    assert not check_attestation(s, bad)[0], "signature alteree acceptee"
    assert not check_attestation(s, line, now=int(time.time()) + 3600)[0], "rejeu accepte"
    text, meta = compose(s, 7, "report", "main", "T12", "corps")
    assert text.startswith(PROTO + "|") and meta["body_bytes"] == 5
    seal = make_seal(s, "000042", "7")
    ok, turn, verdict, raison = check_seal(s, "#NESTOR/v1|turn=000042|verdict=7|seal=" + seal)
    assert ok and turn == "000042" and verdict == "7", raison
    assert not check_seal(s, "#NESTOR/v1|turn=000042|verdict=7|seal=" + "f" * 16)[0], \
        "mauvais sceau accepte"
    assert not check_seal(s, "aucune ligne de sceau ici")[0], "ligne sans sceau acceptee"
    # v1.2 : sceau habille de Markdown (fence ``` ou gras **)
    fenced = "Doctrine recue.\n\n**Ligne de conformite :**\n\n```\n#NESTOR/v1|turn=000042|verdict=7|seal=%s\n```\nsuite du message\n" % seal
    ok, turn, verdict, raison = check_content(s, fenced)
    assert ok and turn == "000042" and verdict == "7", raison
    bold = "intro\n\n**#NESTOR/v1|turn=000043|verdict=8|seal=%s**\n" % make_seal(s, "000043", "8")
    ok, turn, verdict, raison = check_content(s, bold)
    assert ok and turn == "000043" and verdict == "8", raison
    assert not check_content(s, "aucune ligne de sceau nulle part")[0], \
        "message sans sceau accepte"
    assert not check_content(s, fenced.replace(seal, "f" * 16, 1))[0], \
        "mauvais sceau accepte (fenced)"
    # v1.3 : recalcul du sceau entrant (commande inseal)
    got = make_seal(s, "000002", "8")
    assert hmac.compare_digest(got, got), "inseal: recalcul instable"
    assert make_seal(s, "000002", "8") != make_seal(s, "000002", "9"), \
        "inseal: verdict sans effet sur le sceau"
    # v1.4 : sceau v2 lie au corps (sha16) — rejet d'un corps substitue
    corps_v2 = "Doctrine recue.\n\nSpec T02 : extraire objectif, livrable, acceptation.\n"
    emp = hash16(corps_v2.encode("utf-8"))
    seal_v2 = make_seal_v2(s, "000004", "7", emp)
    msg_v2 = "#NESTOR/v2|turn=000004|verdict=7|sha16=%s|seal=%s\n%s" % (emp, seal_v2, corps_v2)
    ok, turn, verdict, raison = check_content(s, msg_v2)
    assert ok and turn == "000004" and verdict == "7", raison
    falsifie = msg_v2.replace("Spec T02", "Spec T03", 1)
    assert not check_content(s, falsifie)[0], "corps modifie accepte (v2)"
    # v1.5 : porte de registre
    approved_test = {"v2_from": "000009", "turns": {
        "000004": {"seal": seal_v2, "v": 2},
        "000042": {"seal": seal, "v": 1},
        "000043": {"seal": make_seal(s, "000043", "8"), "v": 1},
        "000009": {"seal": "f" * 16, "v": 2},  # place pour test v2_from
        "000051": {"seal": "e" * 16, "v": 1},  # v1 enregistre mais interdit
    }}
    # tour enregistre + sceau correct -> accept
    dec, t, v, r, ver = evaluate_incoming(s, msg_v2, approved_test)
    assert dec == "accept" and t == "000004", r
    # tour absent du registre -> quarantaine 8, SANS effet sur last_turn
    seal_x = make_seal(s, "000099", "7")
    msg_x = "#NESTOR/v1|turn=000099|verdict=7|seal=" + seal_x
    dec, t, v, r, ver = evaluate_incoming(s, msg_x, approved_test)
    assert dec == "quarantine" and "non enregistre" in r, r
    # sceau valide du jumeau (tour 000008 parallele, non enregistre)
    seal_j = make_seal(s, "000008", "9")
    msg_j = "#NESTOR/v1|turn=000008|verdict=9|seal=" + seal_j
    dec, t, v, r, ver = evaluate_incoming(s, msg_j, approved_test)
    assert dec == "quarantine" and "non enregistre" in r, r
    # v1 interdit au-dela de v2_from (tour 000051 enregistre en v1)
    dec, t, v, r, ver = evaluate_incoming(s, msg_v2, approved_test)  # rappel : accept
    seal_51 = make_seal(s, "000051", "7")
    msg_51 = "#NESTOR/v1|turn=000051|verdict=7|seal=" + seal_51
    dec, t, v, r, ver = evaluate_incoming(s, msg_51, approved_test)
    assert dec == "quarantine" and "v1 interdit" in r, r
    # v2 accepte sous v2_from
    emp4 = hash16(corps_v2.encode("utf-8"))
    s4 = make_seal_v2(s, "000004", "7", emp4)
    m4 = "#NESTOR/v2|turn=000004|verdict=7|sha16=%s|seal=%s\n%s" % (emp4, s4, corps_v2)
    dec, t, v, r, ver = evaluate_incoming(s, m4, approved_test)
    assert dec == "accept" and ver == 2, r
    # non scelle -> non_scelle
    dec, t, v, r, ver = evaluate_incoming(s, "rien du tout", approved_test)
    assert dec == "non_scelle", r
    print("selftest OK  attestation=%s  sceau v1 (brut+fenced+gras+inseal) + v2 (corps lie)" % line)
    print("selftest OK  porte de registre v1.5 (enregistre/parallele/v1-interdit/v2-obligatoire)")
    print("vecteur v2 (cle '0'*32)  corps sha16=%s  sceau=%s" % (emp, seal_v2))
    return 0


def newest_assistant_id(task_id, key):
    """Best-effort : jamais fatal pour l'appelant (l'etat est deja sauve)."""
    try:
        r = api("GET", "/v2/task.listMessages",
                params={"task_id": task_id, "order": "desc", "limit": 20}, key=key)
    except SystemExit:
        return None
    for m in r.get("messages", []):
        if m.get("type") == "assistant_message":
            return m.get("id")
    return None


def unseen_candidates(messages, last_seen, baseline):
    """Construit la file chronologique des messages a evaluer.

    messages : page task.listMessages en ordre DESC (le plus recent d'abord).
    -> liste ordre chronologique (plus ancien d'abord).
    Si last_seen est dans la page : tout ce qui est AVANT lui (plus ancien)
    est candidat. Sinon : depuis baseline (incluse), sauf si baseline absent
    de la page -> seul le plus recent (rejeu massif impossible : une page
    ne peut pas representer tout l'historique).
    """
    chron = list(reversed(messages))
    ids = [m.get("id") for m in chron]
    if last_seen in ids:
        i = ids.index(last_seen)
        return chron[:i]
    if baseline in ids:
        return chron[ids.index(baseline) + 1:]
    if chron:
        return chron[-1:]
    return []


def cmd_send(a):
    key = read_secret(KEY_PATH, "MANUS_API_KEY")
    secret = read_secret(HMAC_PATH, "NESTOR_HMAC_KEY")
    if not secret:
        die("secret HMAC introuvable (%s ou $NESTOR_HMAC_KEY)" % HMAC_PATH)
    if not key and not a.dry_run:
        die("cle API introuvable (%s ou $MANUS_API_KEY)" % KEY_PATH)
    try:
        body_md = open(a.body, "r", encoding="utf-8").read()
    except OSError as e:
        die("corps illisible : %s" % e)
    n = len(body_md.encode("utf-8"))
    if n > MAX_BODY_BYTES:
        die("corps %d o > %d o : resumer et joindre un sidecar" % (n, MAX_BODY_BYTES))

    st = load_state()
    seq = a.seq if a.seq is not None else int(st.get("seq", 0)) + 1
    text, meta = compose(secret, seq, a.type, a.agent, a.task_ref, body_md, a.self_score)

    task_id = None if a.new else st.get("task_id")
    if task_id:
        resp = api("POST", "/v2/task.sendMessage",
                   body={"task_id": task_id, "message": {"content": text},
                         "agent_profile": a.profile}, key=key, dry=a.dry_run)
    else:
        body = {"message": {"content": text}, "locale": "fr",
                "interactive_mode": not a.no_interactive,
                "hide_in_task_list": bool(a.hide), "agent_profile": a.profile}
        if a.project_id:
            body["project_id"] = a.project_id
        if a.task_references:
            body["message"]["task_references"] = a.task_references
        resp = api("POST", "/v2/task.create", body=body, key=key, dry=a.dry_run)
        task_id = resp.get("task_id")

    if a.dry_run:
        return 0
    if not resp.get("ok", False):
        die("reponse non-ok : %s" % json.dumps(resp, ensure_ascii=False)[:400], 2)

    st["task_id"] = task_id
    st["seq"] = seq
    st["last_sent_at"] = meta["ts"]
    save_state(st)  # d'abord l'etat critique ; jamais bloque par le best-effort
    baseline = newest_assistant_id(task_id, key)
    if baseline:
        st["baseline"] = baseline
        save_state(st)
    print("OK seq=%s task_id=%s url=%s" % (seq, task_id, resp.get("task_url", "")))
    return 0


def cmd_poll(a):
    key = read_secret(KEY_PATH, "MANUS_API_KEY")
    secret = read_secret(HMAC_PATH, "NESTOR_HMAC_KEY")
    st = load_state()
    if a.rescan:
        # relire aussi les messages deja marques vus (apres correction du pont)
        st.pop("last_seen", None)
        st.pop("baseline", None)
    task_id = a.task_id or st.get("task_id")
    if not task_id:
        die("aucun task_id connu")
    approved = load_approved()  # fail-closed : registre exige a chaque tour
    deadline = time.time() + a.timeout
    delay = a.interval
    while True:
        d = api("GET", "/v2/task.detail", params={"task_id": task_id}, key=key)
        task = d.get("task", {})
        status = task.get("status")
        if status in ("stopped", "waiting", "error"):
            bg = task.get("has_running_background_jobs")
            if status == "stopped" and bg is True and time.time() < deadline:
                pass  # travail de fond encore actif : ne pas conclure
            else:
                msg = api("GET", "/v2/task.listMessages",
                          params={"task_id": task_id, "order": "desc",
                                  "limit": a.limit}, key=key)
                assistants = [m for m in msg.get("messages", [])
                              if m.get("type") == "assistant_message"]
                candidates = unseen_candidates(assistants, st.get("last_seen"),
                                               st.get("baseline"))
                for newest in candidates:
                    content = newest.get("assistant_message", {}).get("content", "")
                    decision, turn, verdict, raison, version = \
                        evaluate_incoming(secret, content, approved)
                    if decision == "non_scelle":
                        p = quarantine(content, raison, turn)
                        st["last_seen"] = newest.get("id")
                        save_state(st)
                        sys.stderr.write("REFUSE (%s) -> quarantaine: %s\n" % (raison, p))
                        die("message entrant non scelle", 7)
                    if decision == "quarantine":
                        p = quarantine(content, raison, turn)
                        st["last_seen"] = newest.get("id")
                        save_state(st)
                        sys.stderr.write("REFUSE (%s) -> quarantaine: %s\n" % (raison, p))
                        if "non enregistre" in raison or "!= registre" in raison \
                                or "interdit" in raison:
                            die(raison, 8)  # R-09 : tour fantome, sans effet
                        die("sceau entrant invalide", 5)
                    # accepte
                    last_turn = int(st.get("last_turn", 0))
                    if int(turn) <= last_turn:
                        st["last_seen"] = newest.get("id")
                        save_state(st)
                        p = quarantine(content,
                                       "rejeu: turn %s deja vu (dernier=%d)" % (turn, last_turn),
                                       turn)
                        sys.stderr.write("REJEU -> quarantaine: %s\n" % p)
                        die("rejeu detecte (turn %s <= %d)" % (turn, last_turn), 6)
                    st["last_turn"] = int(turn)
                    st["last_seen"] = newest.get("id")
                    st["last_poll_at"] = int(time.time())
                    save_state(st)
                    print(content)
                    if status == "waiting":
                        sys.stderr.write("NOTE task en attente d'input (stop_reason=ask)\n")
                    return 0
                if status == "error":
                    die("tache en erreur : %s" % task.get("title", ""), 4)
                if time.time() >= deadline:
                    die("timeout sans nouveau message", 4)
        if time.time() >= deadline:
            die("timeout %ss (dernier status=%s)" % (a.timeout, status), 4)
        time.sleep(delay)
        delay = min(int(delay * 1.5), a.max_interval)


def cmd_verify(a):
    secret = read_secret(HMAC_PATH, "NESTOR_HMAC_KEY")
    if not secret:
        die("secret HMAC introuvable")
    ok, info = check_attestation(secret, a.line.strip(), window=a.window)
    print(json.dumps({"ok": ok, "detail": info}, ensure_ascii=False))
    return 0 if ok else 5


def cmd_inseal(a):
    """Verifie un sceau entrant Manus (recalcul HMAC). -> ligne seal_check=ok fondee.

    Mode v1 : HMAC sur tour+verdict.
    Mode v2 (--body ou --sha16) : HMAC sur tour+verdict+empreinte du corps.
    """
    secret = read_secret(HMAC_PATH, "NESTOR_HMAC_KEY")
    if not secret:
        die("secret HMAC introuvable (%s ou $NESTOR_HMAC_KEY)" % HMAC_PATH)
    recu = a.sig.strip().lower()
    if a.body or a.sha16:
        corps = b""
        if a.body:
            try:
                corps = open(a.body, "rb").read()
            except OSError as e:
                die("corps illisible : %s" % e)
        empreinte = (a.sha16.strip().lower() if a.sha16 else hash16(corps))
        attendu = make_seal_v2(secret, a.turn, a.verdict, empreinte)
        ok = hmac.compare_digest(attendu, recu)
        if a.body and hash16(corps) != empreinte:
            ok = False
        print(json.dumps({"mode": "v2", "turn": a.turn, "verdict": a.verdict,
                          "sha16": empreinte, "attendu": attendu, "recu": recu,
                          "ok": ok}, ensure_ascii=False))
        return 0 if ok else 5
    got = make_seal(secret, a.turn, a.verdict)
    ok = hmac.compare_digest(got, recu)
    print(json.dumps({"mode": "v1", "turn": a.turn, "verdict": a.verdict,
                      "attendu": got, "recu": recu, "ok": ok}, ensure_ascii=False))
    return 0 if ok else 5


def cmd_credits(a):
    key = read_secret(KEY_PATH, "MANUS_API_KEY")
    r = api("GET", "/v2/usage.availableCredits", key=key)
    c = r.get("data", r)
    print(json.dumps(c, ensure_ascii=False, indent=1))
    return 0


def cmd_state(a):
    print(json.dumps(load_state(), indent=1, sort_keys=True))
    return 0


def main():
    p = argparse.ArgumentParser(description="Pont Nestor <-> Manus API v2")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("selftest"); q.set_defaults(fn=cmd_selftest)
    q = sub.add_parser("state"); q.set_defaults(fn=cmd_state)
    q = sub.add_parser("credits"); q.set_defaults(fn=cmd_credits)

    q = sub.add_parser("send")
    q.add_argument("--body", required=True)
    q.add_argument("--type", default="report",
                   choices=["report", "blocker", "question", "heartbeat", "journal"])
    q.add_argument("--agent", default="main")
    q.add_argument("--task-ref", default="-")
    q.add_argument("--self-score", type=float, default=None)
    q.add_argument("--seq", type=int, default=None)
    q.add_argument("--new", action="store_true")
    q.add_argument("--project-id", default=os.environ.get("MANUS_PROJECT_ID", ""))
    q.add_argument("--task-references", nargs="*", default=None)
    q.add_argument("--profile", default="standard", choices=PROFILES)
    q.add_argument("--no-interactive", action="store_true")
    q.add_argument("--hide", action="store_true")
    q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_send)

    q = sub.add_parser("poll")
    q.add_argument("--task-id", default=None)
    q.add_argument("--timeout", type=int, default=2700)
    q.add_argument("--interval", type=int, default=20)
    q.add_argument("--max-interval", type=int, default=60)
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--rescan", action="store_true")
    q.set_defaults(fn=cmd_poll)

    q = sub.add_parser("verify")
    q.add_argument("--line", required=True)
    q.add_argument("--window", type=int, default=600)
    q.set_defaults(fn=cmd_verify)

    q = sub.add_parser("inseal")
    q.add_argument("--turn", required=True, help="ex. 000002 (6 chiffres)")
    q.add_argument("--verdict", required=True, help="ex. 8 ou na")
    q.add_argument("--sig", required=True, help="16 hex du sceau recu")
    q.add_argument("--sha16", default=None, help="v2 : empreinte du corps (16 hex)")
    q.add_argument("--body", default=None, help="v2 : fichier du corps (empreinte recalculee)")
    q.set_defaults(fn=cmd_inseal)

    a = p.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()

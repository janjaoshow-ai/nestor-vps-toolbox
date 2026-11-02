# nestor-vps-toolbox

Outils d'administration du VPS de Nestor (agent OpenClaw de JJ, Hua Hin).

## Contenu

- `nestor_manus_bridge.py` — pont securise Nestor <-> Manus API v2
  (sceau HMAC-SHA256 dans les deux sens, quarantaine des messages non scelles,
  anti-rejeu par compteur de tours, stdlib uniquement, python3.8+).

## Regles d'or

1. **AUCUN secret dans ce depot** — jamais de cle API, de token, de mot de passe,
   ni de valeur derivee. Les secrets vivent sur le VPS dans `/root/.secrets/` (600 root)
   et dans les instructions du projet Manus.
2. Le VPS recupere les fichiers par `curl` depuis l'URL raw : pas besoin de SSH/scp.

## Mise a jour sur le VPS

    curl -fsSL https://raw.githubusercontent.com/janjaoshow-ai/nestor-vps-toolbox/main/nestor_manus_bridge.py \
      -o /opt/agents/nestor/workspace/scripts/nestor_manus_bridge.py
    chmod 700 /opt/agents/nestor/workspace/scripts/nestor_manus_bridge.py
    python3 /opt/agents/nestor/workspace/scripts/nestor_manus_bridge.py selftest

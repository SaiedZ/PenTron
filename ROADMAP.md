# 🔱 PenTron — Product Roadmap

Ce document liste les pistes d'évolution envisagées pour élargir la couverture
d'audit de sécurité de domaine, au-delà des 8 outils de recon actuels
(nmap, whois, whatweb, curl headers, dig DNS, nikto, sslscan, testssl.sh).

Classement par intérêt réel / risque / facilité d'intégration. Rien ici n'est
implémenté — c'est une liste de candidats à discuter avant tout développement.

---

## Fort intérêt, faible risque, faciles à ajouter

Ces pistes sont cohérentes avec la philosophie "detection only" du projet et
présentent peu de risque opérationnel.

### ✅ Découverte de sous-domaines — implémenté
Le trou le plus important identifié à ce jour. Auparavant PenTron ne testait
que le domaine exact déclaré (`clubs.ma`), jamais `mail.clubs.ma`,
`dev.clubs.ma`, `staging.clubs.ma`... Or c'est souvent là que se trouvent les
vraies failles (environnements de dev oubliés, sous-domaines mal sécurisés).

Implémenté avec 3 niveaux de config (réglage "Subdomain discovery" dans
Settings, `subdomain_discovery_level` : 0/1/2) :
- **0 — Désactivé** (par défaut) : comportement inchangé, scope guard strict.
- **1 — Passif** (`crt.sh`, certificate transparency logs) : une requête HTTP
  vers un service public, zéro trafic vers la cible. Résultats listés dans le
  rapport, purement informatifs — le scope guard reste strict.
- **2 — Actif** (`crt.sh` + `subfinder`) : ajoute la résolution DNS active,
  trouve aussi les sous-domaines sans certificat public. Les sous-domaines
  découverts deviennent des cibles valides pour le scope guard (l'IA peut
  ensuite lancer nmap/whatweb dessus) — extension de scope explicite et
  opt-in, pas automatique.

`amass` a été écarté après test : son premier lancement télécharge plusieurs
Go de données géographiques (libpostal, utilisées pour le reverse whois),
totalement disproportionné pour une simple énumération DNS. `subfinder` seul
couvre le besoin (léger, rapide, pas de téléchargement de données).

Voir `tools.py::discover_subdomains`, `tests/test_subdomain_discovery.py`,
`tests/test_scope_guard.py` (tests `test_subdomain_in_allowed_set_is_permitted`
/ `test_subdomain_not_in_allowed_set_still_blocked`).

### ✅ Détection de WAF (`wafw00f`) — implémenté
Savoir si un pare-feu applicatif protège la cible change l'interprétation des
résultats — un scan "propre" derrière un WAF ne veut pas dire grand-chose.

Ajouté comme 9e outil du menu (checkbox dédiée, comme sslscan/testssl —
opt-in, pas dans le bundle par défaut). Teste http et https en un seul
appel. Les codes couleur ANSI que wafw00f émet systématiquement (même sans
tty) sont retirés du texte transmis à l'IA.

Bug de build rencontré et corrigé au passage : l'installation apt de
wafw00f entraîne `python3-urllib3`/`requests`/`certifi`/`idna` en paquets
Debian, ce qui fait échouer `pip install` sur `requirements.txt` (impossible
de désinstaller un paquet apt sans fichier RECORD). Fix : `--ignore-installed`
sur la commande pip du Dockerfile.

Voir `tools.py::run_waf_detect`, `tests/test_waf_detection.py`.

### ✅ Enregistrements DNS de sécurité email (SPF/DKIM/DMARC) — implémenté
Extension du `dig` existant : en plus des A/MX/NS/TXT habituels, `run_dig`
interroge maintenant `_dmarc.<domaine>` et `default._domainkey.<domaine>`,
et signale explicitement si SPF/DMARC/DKIM sont présents ou absents dans le
rapport lu par l'IA (l'absence de DMARC = risque de spoofing/phishing sur le
domaine, un vrai point d'audit).

Limite assumée : le check DKIM ne teste que le sélecteur `default` (le plus
courant) — son absence ne prouve pas l'absence de DKIM sous un autre
sélecteur (`google._domainkey`, `selector1._domainkey`...), le rapport le
précise explicitement pour ne pas induire l'IA en erreur.

Voir `tools.py::run_dig`, `tests/test_email_security_dig.py`.

### ✅ Analyse des en-têtes de sécurité HTTP — implémenté
CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy. Pas de nouvel outil externe — `run_curl_headers` (http ET
https) est enrichi d'une couche d'analyse qui signale explicitement chaque
en-tête comme présent ou absent, avec une courte explication de son rôle.

Un cas d'erreur géré explicitement : si la requête échoue (timeout, connexion
refusée), le texte n'est pas une vraie réponse HTTP — on ne doit pas
prétendre que "tous les en-têtes sont absents" alors qu'on n'a en fait rien
pu vérifier. Le rapport dit "Could not check" dans ce cas.

Voir `tools.py::_analyze_security_headers`, `tests/test_security_headers.py`.

### ✅ Vérification robots.txt / security.txt — implémenté
Ajouté comme 10e outil du menu (`run_robots_and_security_txt`), opt-in.
`robots.txt` peut révéler des chemins que l'admin ne veut pas indexer (un
signal faible, pas une vulnérabilité en soi). `security.txt` (RFC 9116,
vérifié sur `/.well-known/security.txt` puis, à défaut, sur le chemin
historique `/security.txt`) indique si la cible a un processus de
divulgation de vulnérabilités documenté.

Testé en réel sur `github.com` : robots.txt et security.txt (contact
HackerOne) récupérés correctement. Sortie plafonnée en longueur pour éviter
de saturer le contexte de l'IA avec un fichier volumineux.

Voir `tools.py::run_robots_and_security_txt`, `tests/test_robots_security_txt.py`.

---

## Intérêt réel mais plus intrusif — à discuter avant d'ajouter

Discussion approfondie menée pour chacun des trois candidats (intérêt, risque,
comment l'encadrer si on l'ajoute) :

### Découverte de répertoires/fichiers (`gobuster`, `ffuf`)
**Intérêt** : trouve des chemins qu'aucun outil actuel ne détecte — panels
admin oubliés, `.git/` exposé, backups (`.sql`, `.zip`), fichiers de config.
Un vrai angle mort de PenTron aujourd'hui.

**Risque** : contrairement à tout ce qui a été ajouté jusqu'ici, ça envoie
potentiellement des milliers de requêtes à la cible — ce n'est plus de la
recon passive. Risque de rate-limiting/bannissement IP côté cible, d'effet
DoS involontaire sur un site fragile, et ça sort du cadre "detection only"
formalisé dans le README.

**Encadrement si ajouté** : wordlist courte et ciblée (quelques centaines
d'entrées, pas SecLists complet), délai entre requêtes (`-delay` sur
gobuster), timeout global strict, et un warning explicite dans l'UI avant
lancement ("génère du trafic significatif vers la cible"). C'est le plus
facile à rendre raisonnable des trois — risque gérable avec une config
prudente.

### `nuclei`
**Intérêt** : bibliothèque de templates énorme et à jour, couvre
fingerprinting/misconfig/exposition de fichiers sensibles.

**Risque** : le plus dangereux pour la philosophie du projet. Les templates
vont du simple fingerprinting jusqu'à des PoC d'exploitation active
(injection, CVE avec payload réel). Le filtrage par tags
(`-tags exposure,tech,misconfig` en excluant `cve,vuln,exploit`) aide, mais
le tagging communautaire n'est pas parfaitement fiable, et les templates sont
mis à jour en continu (`nuclei -update-templates`) — le périmètre "safe" peut
dériver dans le temps sans qu'on s'en aperçoive.

**Encadrement si ajouté** : figer une version de templates (pas
d'auto-update), probablement une allowlist explicite de templates validés à
la main plutôt que de faire confiance aux tags seuls. Plus de travail de
maintenance que gobuster/ffuf pour un gain pas évident vu qu'on a déjà
whatweb/nikto pour le fingerprinting.

### `wpscan`
**Intérêt** : réel mais niche — seulement si la cible est WordPress.

**Risque** : le mode par défaut peut tenter l'énumération d'utilisateurs et,
si mal configuré, du bruteforce de comptes — à ne jamais activer.

**Encadrement si ajouté** : conditionnel à whatweb qui détecte WordPress
d'abord (pas de scan wpscan si la cible n'est pas WP), restreint à
l'énumération passive (`--enumerate vp,vt` — plugins/thèmes vulnérables via
la base wpscan, jamais d'énumération d'utilisateurs ni de login bruteforce).

### Priorité recommandée entre les trois
1. **gobuster/ffuf** (wordlist courte + délai) — le meilleur ratio
   valeur/risque maîtrisable.
2. **wpscan conditionnel** — niche mais simple et sûr une fois bien restreint.
3. **nuclei** — en attente ; ratio valeur/risque de maintenance moins bon, et
   celui qui menace le plus la philosophie "detection only".

Aucun des trois n'est implémenté — en attente d'un accord explicite avant
tout développement.

---

## Écarté pour l'instant

### Shodan / Censys (lookup passif)
Pourrait être intéressant (recon totalement passive, zéro trafic vers la
cible) mais nécessite une clé API tierce payante — pas prioritaire face au
reste de la liste.

---

## Autres pistes en discussion (hors outils recon)

Ces sujets ont été discutés séparément et restent ouverts, sans implémentation
actée :

- **Rotation de proxy** — mise de côté volontairement, discussion à reprendre
  avant toute implémentation.
- **Mode "dangerous" / exploitation assistée** — discuté en profondeur
  (intérêt réel en pré-prod vs. risque d'actions irréversibles pilotées par
  l'IA sans revue humaine). Non implémenté, ne doit pas être repris sans
  accord explicite.
- **Journalisation structurée (export JSON)** — évoqué comme piste, statut à
  clarifier.

---

## Priorisation recommandée

~~1. Découverte de sous-domaines (crt.sh + subfinder)~~ — **fait**, voir
ci-dessus.
~~2. Vérification SPF/DKIM/DMARC via dig~~ — **fait**, voir ci-dessus.
~~3. Détection de WAF (wafw00f)~~ — **fait**, voir ci-dessus.
~~4. Analyse des en-têtes de sécurité HTTP~~ — **fait**, voir ci-dessus.
~~5. robots.txt / security.txt~~ — **fait**, voir ci-dessus.

Toute la catégorie "fort intérêt, faible risque, facile à ajouter" est
maintenant implémentée. Prochaine étape : discuter des candidats "plus
intrusifs" (gobuster/ffuf, nuclei, wpscan) ci-dessus avant d'aller plus loin.

---

## 🏗️ Refactor d'architecture envisagé

Analyse demandée pour tendre vers une racine de repo plus simple et une
architecture Python modulaire, notamment pour faciliter l'ajout d'outils.
Rien n'est implémenté — analyse seule, en attente de décision.

### État actuel

Racine du repo : 21 fichiers à plat, dont 7 fichiers Python métier mélangés
aux fichiers de config (`pyproject.toml`, `Dockerfile`,
`docker-compose*.yml`, `.env`, `README.md`, `ROADMAP.md`, `Modelfile`,
`LICENSE`...) :

| Fichier | Lignes | Responsabilité(s) |
|---|---|---|
| `tools.py` | 906 | recon runners + garde-fous + orchestration + menu CLI (7 concerns différents, détail ci-dessous) |
| `export.py` | 539 | génération PDF + génération HTML (2 concerns, gros blocs de template inline) |
| `db.py` | 476 | connexion + CRUD × 5 tables + settings (bien découpé en sections, mais un seul fichier) |
| `pentron.py` | 467 | banner + menu CLI + tout le pipeline scan (dupliqué avec `api/scan_runner.py`) |
| `llm.py` | 453 | prompt système + dispatch IA + parsing réponse |
| `providers.py` | 306 | 4 providers IA (Ollama/OpenAI/Anthropic/Google) dans un seul fichier |
| `search.py` | 187 | correct, taille raisonnable |

`api/` (805 lignes, déjà en package avec sous-dossier `routers/`) et
`tests/` (826 lignes, déjà un fichier par sujet) sont, eux, déjà dans une
structure propre. Le problème est concentré sur les 7 fichiers racine.

### Le vrai point de friction : `tools.py`

C'est le fichier le plus touché à chaque ajout d'outil, et le plus
monolithique. Il mélange, dans un seul fichier de 906 lignes :

1. Garde-fou cible privée/loopback (`_is_unsafe_ip`, `check_target_safety`)
2. Primitive générique d'exécution (`run_tool`)
3. 9 runners d'outils individuels (`run_nmap`, `run_whois`,
   `run_curl_headers`, `run_dig`, `run_nikto`, `run_sslscan`, `run_testssl`,
   `run_waf_detect`, `run_robots_and_security_txt`) + leurs helpers privés
   (`_analyze_security_headers`, `_fetch_headers_guarded`,
   `_SECURITY_HEADERS`...)
4. Découverte de sous-domaines (`_discover_subdomains_passive/active`,
   `discover_subdomains`)
5. Orchestration/planification (`TOOLS_MENU`, `resolve_tool_plan`,
   `run_default_recon`, `run_selected_tools`, `format_recon_for_llm`)
6. Scope guard pour les commandes `[TOOL:]` que l'IA émet en texte libre
   (`_resolve_host`, `_extract_positional_tokens`, `ALLOWED_TOOLS`,
   `run_tool_by_command`)
7. Menu interactif spécifique à la CLI (`interactive_tool_run`)

Aujourd'hui, ajouter un outil touche au minimum 3 endroits : une fonction
`run_xxx()` dans `tools.py`, une entrée dans `TOOLS_MENU` (même fichier),
une entrée dans `ALLOWED_TOOLS` si l'IA doit pouvoir l'invoquer — et un 4e
endroit si l'outil doit apparaître côté web, parce que
`web/templates/dashboard.html` a la liste des 10 outils codée en dur dans
des checkboxes HTML (`value="1"` … `value="10"`, noms en toutes lettres),
complètement déconnectée de `TOOLS_MENU`. C'est le symptôme concret du
souci de synchro CLI/web déjà noté dans `CLAUDE.md`.

### Autres points secondaires

- `export.py` : `export_pdf()` et `export_html()` sont deux générateurs
  indépendants avec du HTML/CSS inline conséquent — candidats à un
  découpage `export/pdf.py` + `export/html.py` (+ template HTML
  externalisé plutôt qu'en f-string géante).
- `providers.py` : 4 classes de provider dans un fichier — pas urgent
  (chacune est courte et le pattern `BaseProvider` est déjà propre), mais
  un `providers/` avec un fichier par provider serait cohérent avec le
  reste.
- `pentron.py` vs `api/scan_runner.py` : déjà documenté dans `CLAUDE.md`,
  pas un problème de fichiers mais de logique dupliquée entre les deux
  interfaces.

### Pistes envisagées

**Option A — package `pentron/` classique** : déplacer les 7 fichiers
racine dans `pentron/` (`pentron/db.py`, `pentron/llm.py`, `pentron/tools/`,
etc.), avec `pentron/cli.py` comme point d'entrée CLI. Layout Python
standard, mais casse tous les imports actuels (`from db import ...` partout
dans `api/`, les tests, entre modules eux-mêmes) et demande d'adapter
`pyproject.toml` (`py-modules` → `packages`) ainsi que de revalider la
résolution de `web/` par `api/main.py` (`Path(__file__).resolve()...`, à
revérifier si `api/` change de profondeur).

**Option B — éclater seulement `tools.py` en sous-package**, sans toucher
au reste : `tools/base.py` (le `run_tool` générique + garde-fous),
`tools/registry.py` (`TOOLS_MENU`/`ALLOWED_TOOLS` construits à partir des
modules d'outils plutôt qu'écrits à la main), un fichier par outil ou par
petit groupe cohérent (`tools/nmap.py`, `tools/web_headers.py` regroupant
curl headers + robots/security.txt + WAF puisqu'ils partagent des helpers
HTTP, `tools/dns.py` pour dig + subdomains). Effort plus faible, résout
directement le "ajouter un outil = 3-4 endroits" en un seul point
d'enregistrement. `db.py`, `llm.py`... restent à plat pour l'instant.

**Option C — A puis B, en deux passes séparées** : d'abord B (le gain le
plus concret pour la modularité de l'ajout d'outils), puis A plus tard si
le nombre de fichiers racine reste gênant une fois `tools.py` éclaté.

**Décision** : Option C, mais en commençant par **A** (pas B comme
recommandé initialement) — pour pouvoir ensuite regarder le pattern
d'extensibilité de `tools.py` (B) comme un sujet dédié à part entière,
plutôt que de le faire dans la foulée de la réorganisation générale.

### ✅ Option A — implémenté

Les 7 fichiers racine déplacés dans un package `pentron/` :
`pentron/db.py`, `pentron/llm.py`, `pentron/providers.py`,
`pentron/tools.py`, `pentron/search.py`, `pentron/export.py`, et
`pentron.py` renommé `pentron/cli.py`. Imports internes au package passés
en relatif (`from .db import ...`) ; `api/` et `tests/` importent depuis
l'extérieur (`from pentron import db`, `from pentron.tools import ...`).

Point d'entrée CLI exposé comme script console via `[project.scripts]`
dans `pyproject.toml` (`pentron = "pentron.cli:main"`) — `uv sync`/
`pip install -e .` installe la commande `pentron` directement. Le
Dockerfile en profite : `CMD ["pentron"]` au lieu de
`CMD ["python3", "pentron.py"]`.

`api/main.py` n'a pas bougé (reste hors du package `pentron/`), donc sa
résolution de `web/` via `Path(__file__).resolve().parent.parent` reste
valide sans changement.

Vérifié : `ruff format .` / `ruff check .` propres, tous les modules
s'importent correctement (`pentron.cli`, `api.main`), `pytest tests/ -q`
toujours 63/63, script console `pentron` confirmé généré dans `.venv`.

**Option B (éclater `tools.py`) reste à faire** — sujet dédié à venir,
pour discuter spécifiquement du pattern à utiliser (registre de plugins,
un fichier par outil ou par groupe cohérent, etc.) avant de l'implémenter.

# 🔱 PenTron — Product Roadmap

Ce document liste les pistes d'évolution envisagées pour élargir la couverture
d'audit de sécurité de domaine, au-delà des 10 outils de recon actuels
(nmap, whois, whatweb, curl headers, dig DNS, nikto, sslscan, testssl.sh,
wafw00f, robots/security.txt).

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

- ✅ `export.py` — **découpé**, voir plus bas.
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

### ✅ Option B — implémenté

`pentron/tools.py` (906 lignes) éclaté en sous-package `pentron/tools/`,
avec le pattern retenu après discussion : **un registre à décorateur** +
**un fichier par outil du menu** (règle uniforme, pas d'exception à
géométrie variable) :

- `base.py` — `run_tool()` générique. Toujours appelé via `from . import
  base` puis `base.run_tool(...)` dans chaque module d'outil (jamais
  `from .base import run_tool`), pour que les tests puissent monkeypatcher
  une seule cible (`pentron.tools.base.run_tool`) quel que soit l'outil
  qui l'appelle en interne.
- `safety.py` — `check_target_safety` / `_is_unsafe_ip` (garde-fou pré-scan).
- `registry.py` — `ToolSpec` + `@register_tool(key, name, command_name)` ;
  `TOOLS_MENU` et `ALLOWED_TOOLS` sont maintenant *dérivés* du registre au
  lieu d'être écrits à la main à deux endroits.
- `nmap.py`, `whois.py`, `whatweb.py`, `http_headers.py`,
  `robots_security_txt.py`, `dig.py`, `nikto.py`, `sslscan.py`,
  `testssl.py`, `waf.py` — un fichier par entrée du menu (10 fichiers pour
  10 outils), chacun avec son `run_xxx()` décoré.
- `subdomains.py` — `discover_subdomains` (pas dans le menu, pas un
  "outil" sélectionnable, donc pas dans le registre).
- `dispatch.py` — `run_tool_by_command` + le scope guard IA
  (`_resolve_host`, `_extract_positional_tokens`, `_resolved_ips`),
  `ALLOWED_TOOLS` désormais lu depuis `registry.allowed_commands()`.
- `pipeline.py` — `run_default_recon`, `run_selected_tools`,
  `run_single_tool`, `resolve_tool_plan`, `format_recon_for_llm`.
- `interactive.py` — `interactive_tool_run` (menu CLI, print/input).
- `__init__.py` — importe tous les modules d'outils (effet de bord :
  déclenche leur `@register_tool`) et réexporte l'API publique, donc
  `api/`, `tests/`, `pentron/cli.py` continuent d'écrire
  `from pentron.tools import check_target_safety` / `from pentron import
  tools` exactement comme avant — aucun appelant externe à toucher.

**Ajouter un outil, maintenant** : créer `pentron/tools/<nom>.py` avec un
`run_<nom>(target, user_agent=None)` décoré `@register_tool(...)`,
l'ajouter à la liste d'imports de `__init__.py`. Un seul fichier créé, un
seul fichier touché (l'import) — plus besoin de toucher `TOOLS_MENU` ni
`ALLOWED_TOOLS` à la main.

Les 8 fichiers de tests qui monkeypatchaient `tools.run_tool` ont été mis
à jour pour cibler `tools.base.run_tool` (mécanique, même principe que les
imports lors de l'Option A) ; ceux qui appelaient des helpers privés
directement (`_fetch_headers_guarded`, `_analyze_security_headers`,
`_fetch_text_file`, `_resolved_ips`, `tools.requests`) ciblent maintenant
le sous-module qui les possède (`tools.http_headers`, `tools.dispatch`,
`tools.subdomains`, etc.).

Vérifié : `ruff format .` / `ruff check .` propres, `pytest tests/ -q`
63/63, registre reproduit exactement le `TOOLS_MENU`/`ALLOWED_TOOLS`
d'origine (vérifié par introspection), rebuild Docker complet
`--no-cache` + `pentron.cli`/`api.main` importés avec succès dans le
conteneur.

### ✅ 4e point de friction (`dashboard.html`) — implémenté

`web/templates/dashboard.html` avait les 10 outils codés en dur en
checkboxes HTML (`value="1"`…`value="10"`, noms en toutes lettres) + une
liste dupliquée dans l'objet JS `PRESETS` — déconnecté du registre.

Ajout d'un flag `default: bool` sur `ToolSpec` (registry.py) +
`registry.default_tool_names()` / `default_keys()` / `find_by_name()`.
La route `api/routers/pages.py::dashboard()` passe maintenant la liste
des outils et les clés par défaut au template ; les checkboxes sont une
boucle Jinja, et les presets JS sont du JSON pré-sérialisé côté serveur
depuis la même donnée (Starlette n'a pas de filtre `tojson`). Au passage,
`pipeline.py::resolve_tool_plan()` utilise aussi `registry.default_tool_names()`
au lieu de sa propre liste en dur — plus qu'une seule source de vérité.

Côté CLI, rien à faire : `interactive_tool_run()` bouclait déjà sur
`registry.all_tools()` depuis l'implémentation de l'Option B.

Vérifié : rendu réel de la page via `TestClient` dans le conteneur
rebuild (DB réelle) — mêmes 5 outils cochés par défaut, même contenu
JSON pour les presets qu'avant.

### ✅ `export.py` → package `pentron/export/` — implémenté

Même schéma que `tools.py` (Option B) : un fichier par génération de
rapport + les bouts partagés extraits une fois pour toutes, au lieu de
dupliqués :

- `common.py` — `SEVERITY_COLORS`/`RISK_COLORS` + deux helpers qui
  étaient copiés-collés à l'identique dans `export_pdf` ET `export_html` :
  `safe_filename()` (construction du nom de fichier `pentron_SL<n>_<target>.<ext>`)
  et `session_summary()` (extraction `sl/target/date/risk/ai` depuis
  `data["history"]`/`data["summary"]`).
- `pdf.py` — `export_pdf()` (ReportLab), inchangé sauf pour passer par
  `common.*`.
- `html.py` — `export_html()` (le gros f-string HTML/CSS), inchangé pour
  la même raison. L'externalisation du template HTML (évoquée comme
  piste secondaire) n'a **pas** été faite — décision séparée si voulue un
  jour, pas la même portée qu'un découpage de fichiers.
- `menu.py` — `export_menu()` (menu interactif CLI, print/input).
- `__init__.py` — réexporte `export_pdf`/`export_html`/`export_menu`,
  donc `api/routers/exports.py` (`from pentron.export import
  export_html, export_pdf`) et `pentron/cli.py` (`from .export import
  export_menu`) n'ont rien eu à changer.
- `__main__.py` — l'ancien bloc `if __name__ == "__main__":` du script
  autonome (liste les sessions en DB, exporte celle choisie), maintenant
  lancable via `python -m pentron.export`.

Pas de registre à décorateur ici (contrairement à `tools/`) : seulement
deux générateurs fixes (PDF/HTML), pas une liste ouverte d'unités
interchangeables — un registre aurait été de l'abstraction sans un
second cas d'usage pour la justifier.

Vérifié : `ruff`/`pytest` propres (63/63, aucun test dédié à `export.py`
n'existait), rebuild Docker `--no-cache`, génération réelle d'un PDF et
d'un HTML avec des données synthétiques dans le conteneur (tailles de
fichier non nulles, contenu du HTML vérifié — cible/risque/vuln présents),
`pentron.cli`/`api.main` importés avec succès.

**Refactor d'architecture : tout ce qui était planifié est maintenant fait**
(Option A, Option B, le point de friction web, et `export.py`). Seul
point secondaire restant, non actée : `providers.py` (4 classes de
provider dans un fichier) en package `providers/` un fichier par
provider — pas urgent, chacune est déjà courte et propre.

---

## 💬 Chat contextuel par session — étude assistant conversationnel

Demande : un bouton flottant (bas droite) sur la page d'une session de scan
(`session_detail.html`) ouvrant un chat pour poser des questions sur le scan
en cours (cible, outils lancés, vulnérabilités copiées-collées par
l'utilisateur). Rien n'est implémenté — étude et décisions de principe
actées ci-dessous (discussion du 2026-09-20), développement à faire.

### Contrainte de départ : fenêtre de contexte

Le modèle par défaut (Ollama, `huihui_ai/qwen3.5-abliterated:9b`) tourne avec
`num_ctx=16384` (voir `Modelfile`) — trop petit pour accumuler un historique
de chat sans gestion explicite, contrairement aux providers cloud
(OpenAI/Anthropic/Google, déjà supportés via `providers.py`) qui ont des
fenêtres bien plus larges mais doivent rester couverts par la même logique
puisque le provider actif peut changer via Settings.

### Décision : pas de LangChain

Évalué et écarté. `providers.py` (4 classes, contrat unique `send()`/
`list_models()`, ne lève jamais d'exception) fait déjà ce qu'il faut ;
LangChain ajouterait plusieurs paquets liés par version (`langchain-core` +
un par provider) sur un projet qui pin ses dépendances exactement, sans
supprimer le besoin d'une couche d'adaptation (format de message, contrat
d'erreur) — pas une simplification nette. Le résumé de conversation façon
`ConversationSummaryBufferMemory` est ~30 lignes à écrire à la main, sur le
modèle de `summarize_tool_output` (`llm.py`) qui fait déjà exactement ça
pour les sorties d'outils. Et le tool-calling de LangChain suppose le
function-calling natif des providers — incompatible avec le dispatch
`[TOOL:]/[SEARCH:]` par tags regex actuel, conçu justement parce que le
modèle local abliterated n'a pas de function-calling fiable.

### Décisions actées

- **Portée** : chat contextuel à une session de scan, pas un assistant
  global. Bouton uniquement sur `session_detail.html`.
- **Contexte injecté au démarrage** : une fiche de session compacte et
  bornée — cible, outils lancés, `risk_level`, synthèse courte, puis inventaire
  minimal des constats (`vuln_name`, sévérité, port, service). Jamais
  `raw_scan`, l'analyse IA complète, les descriptions longues ni les textes
  complets des corrections/exploits. Le modèle sait ainsi quels constats
  existent sans être noyé dans le rapport ; l'utilisateur peut ensuite fournir
  le détail utile ou utiliser une action « Discuter de ce constat » qui
  n'ajoute que le constat choisi à la conversation.
- **Persistance** : aucune en base. Historique tenu côté client
  (`sessionStorage`, perdu à la fermeture de l'onglet) et renvoyé en entier
  à chaque requête ; le serveur reste stateless (pas de dict in-memory à
  gérer/nettoyer comme `api/jobs.py`).
- **Budget de contexte interne** : 16 000 tokens, volontairement non exposé
  dans Settings en v1. Répartition cible : fiche de session plafonnée à
  environ 2 000 tokens, environ 2 000 tokens réservés à la réponse, reste pour
  la conversation. Cette limite conservatrice garantit une expérience
  compatible avec le modèle Ollama local par défaut ; un provider cloud peut
  disposer d'une fenêtre plus large, mais la v1 ne dépend pas de métadonnées
  variables selon chaque modèle.
- **Compression du contexte** : par seuil (~70–75% du budget), pas un résumé
  systématique à chaque message — la majorité des échanges resteront courts,
  et résumer à chaque tour coûterait un aller-retour LLM pour rien. La
  compression remplace les anciens tours par un résumé de conversation mais
  conserve intégralement les 4 à 6 derniers messages ; la fiche de session
  reste séparée et est toujours réinjectée. Comptage de tokens par heuristique
  (`len(texte)//4`), pas de dépendance type `tiktoken` (ne collerait qu'à
  l'encodage OpenAI).
- **Transparence utilisateur** : le premier message du widget explique ce que
  l'assistant connaît (fiche compacte), ce qu'il ne connaît pas (sorties brutes
  et détails longs), et la limite d'environ 16 000 tokens du modèle local.
  L'IHM rappelle aussi le compromis : traitement local et contexte limité avec
  Ollama ; contexte potentiellement plus large avec un provider cloud, mais
  transmission des messages et éléments de session à ce provider.
- **Langue** : répondre dans la langue du premier message utilisateur lorsque
  le modèle en est capable, avec repli en anglais si la langue ne peut pas être
  déterminée ou correctement prise en charge.
- **Format des réponses** : Markdown restreint (paragraphes, listes, titres
  courts, emphase, code inline et blocs de code). Le HTML brut est désactivé
  et le rendu est assaini avant insertion dans le DOM. Les blocs de code
  affichent le langage si fourni, autorisent le défilement horizontal et
  proposent une action « Copier ».
- **v1 sans outils** : le chat ne déclenche pas `[TOOL:]/[SEARCH:]`, reste
  conversationnel. Ajout d'outils dans le chat = évolution séparée, à
  discuter après usage réel de la v1 (dupliquerait le dispatch + garde-fous
  scope/SSRF une 3e fois, après `cli.py` et `scan_runner.py`).

### Plan par phases

**✅ Phase 0 — prérequis : stocker la synthèse courte — terminée**
- La refonte du pipeline d'analyse structuré a ajouté `short_summary` au schéma
  initial et à la migration idempotente des volumes existants.
- `pentron/analysis_pipeline.py` et `db.save_analysis_result()` ont remplacé le
  plan initial fondé sur `db.save_summary()` : CLI et Web partagent désormais
  la même validation et la même sauvegarde transactionnelle.
- Le champ est sérialisé par `api/serializers.py::summary_to_dict()` et affiché
  sur la page de session.
- Le développement du chat part d'une base neuve, sans anciennes sessions à
  migrer : le fallback historique depuis une ligne `SUMMARY:` est donc hors
  périmètre et ne sera pas implémenté en v1.

**✅ Phase 1 — backend, cœur partagé — terminée**
- ✅ `pentron/chat.py` créé avec budget interne de 16 000 tokens, réserve de
  réponse de 2 000 tokens et estimation heuristique sans tokenizer externe.
- ✅ `build_seed_context(session_data)` construit une fiche bornée à environ
  2 000 tokens à partir de la cible, du niveau de risque, de `short_summary` et
  de l'inventaire minimal des constats. `raw_scan`, `ai_analysis` et les
  descriptions longues en sont explicitement exclus et couverts par les tests.
- ✅ Prompt système dédié : langue de l'utilisateur, Markdown restreint,
  transparence sur les informations absentes et interdiction de produire ou
  déclencher `[TOOL:]` / `[SEARCH:]`.
- ✅ Historique client normalisé : seuls les rôles `user` et `assistant` sont
  conservés, les contenus sont nettoyés et plafonnés, les champs inattendus et
  rôles privilégiés sont rejetés. Son coût est estimé avec un overhead par
  message (`estimate_history_tokens()`).
- ✅ `maybe_compress()` résume les anciens messages au-delà du seuil de 75 %,
  tient compte du contexte fixe et de la réserve de réponse, conserve les six
  derniers messages et garde l'historique intact si le provider échoue.
- ✅ `send_chat_message()` valide le nouveau message, assemble le prompt et la
  fiche de session, compresse au besoin, appelle le provider puis renvoie la
  réponse et l'historique client resynchronisé. Les erreurs provider sont
  converties en `ChatProviderError` sans produire d'historique partiel.
- Tests actuels : 52 tests dédiés au chat, suite complète à 120 tests réussis.

**🚧 Phase 2 — endpoint API — en cours**
- ✅ Modèles Pydantic `ChatMessage`, `ChatRequest` et `ChatResponse` ajoutés
  dans `api/schemas.py`. Les rôles sont limités à `user`/`assistant`, les
  contenus et le nombre de messages sont bornés, et les chaînes vides sont
  rejetées (18 tests dédiés).
- ⏳ Créer `api/routers/chat.py` : `POST /api/scans/{sl_no}/chat`, body
  `{history, message}`, réponse `{reply, history}` (historique
  potentiellement compressé renvoyé pour resynchroniser le client).
  Réutilise `get_provider()` existant, sans nouvelle table ni changement dans
  `db.py`, puis enregistrer le router dans `api/main.py`.
- Suite complète actuelle : 138 tests réussis.

**Phase 3 — IHM**
- Bouton flottant + panel ajoutés dans `session_detail.html` uniquement.
  JS vanilla (`classList.toggle`, `fetch` via `apiFetch` déjà dans
  `app.js`) — pas de librairie de composants (Flowbite/Tailwind UI) : le
  composant est trop simple pour justifier une dépendance, et casserait la
  cohérence de style (`CLAUDE.md` — pas de framework JS, pas de design
  system custom).
- Un widget bouton+panel existe déjà, non câblé, dans
  `design-concepts/concept-a/session.html` (voir section "Migration
  visuelle" plus bas) — accent cyan, classes `.chat-toggle`/`.chat-panel`/
  `.chat-bubble-*` définies dans `design-concepts/concept-a/style.css`.
  Point de départ pour cette phase : reprendre son markup/CSS (adapté aux
  classes réelles de `web/input.css`, ex. `.panel`) plutôt que redessiner
  le widget de zéro, et le brancher sur l'historique client + l'endpoint de
  la Phase 2 au lieu des 3 messages bidons et de l'écho local de la
  maquette.
- Afficher dès l'ouverture le message de transparence sur le périmètre du
  contexte, la limite du modèle local et l'envoi à un tiers lorsqu'un provider
  cloud est actif.
- Ajouter sur chaque constat une action « Discuter de ce constat » qui ouvre le
  widget et prépare un message avec le détail de ce seul constat ; l'utilisateur
  garde le contrôle et doit confirmer l'envoi.
- Rendre le Markdown avec une liste fermée de constructions autorisées, sans
  HTML brut, et fournir un bouton « Copier » sur les blocs de code.

**Phase 4 (optionnelle, après usage réel de la v1)**
- Discussion séparée sur l'ajout d'outils (`[TOOL:]/[SEARCH:]`) dans le
  chat, si le besoin se confirme à l'usage.

Les Phases 0 et 1 sont terminées. Continuer phase par phase
avec les mêmes vérifications que le reste du projet (`ruff format .`,
`ruff check .`, `pytest tests/ -q`).

---

## ✅ Migration visuelle "ops console" — implémenté

Discussion du 2026-09-20 : le besoin de départ était de rendre l'IHM plus
moderne/attractive. Plutôt que d'itérer directement sur l'existant, trois
directions visuelles complètes ont été maquettées en statique (HTML/CSS/JS
autonome, données bidons, aucun lien avec l'app réelle) dans `design-concepts/`
à la racine du repo :
- `concept-a/` — "ops console" : sombre, dense, mono, accent cyan.
- `concept-b/` — "enterprise SaaS" : clair, aéré, accent indigo.
- `concept-c/` — "éditorial contrasté" : noir/lime/cyan, typo forte.

Choix retenu : **concept-a**, jugé le plus cohérent avec la nature de l'outil
(usage technique répété, pas un produit grand public) — en reprenant deux
idées du concept B avant migration : le donut SVG de répartition des
sévérités, et les lignes d'historique entièrement cliquables (au lieu d'un
petit lien "view" en bout de ligne).

`design-concepts/` est gardé tel quel après la migration, comme référence
visuelle historique — pas maintenu, pas synchronisé avec l'app réelle. Le
widget de chat flottant présent dans `concept-a/session.html` (3 messages
bidons, envoi simulé côté client) n'a délibérément pas été porté dans l'app
réelle : c'est un point de départ pour la Phase 3 de la section "Chat
contextuel par session" ci-dessus, pas une fonctionnalité livrée.

**Décision actée : dark-only.** Le concept A n'existe qu'en sombre ; plutôt
que de dessiner une variante claire équivalente (travail de design
supplémentaire non fait), l'app abandonne le mode clair et les variantes
`dark:` de Tailwind entièrement. Voir `CLAUDE.md` section "UI web" pour le
détail des tokens/classes et l'implication pour les futurs changements d'IHM.

Périmètre migré : `web/input.css` (tokens + classes composants), toutes les
pages (`base.html`, `dashboard.html`, `history_list.html`,
`session_detail.html`, `settings.html`, `scan_progress.html` +
`_scan_status_fragment.html`), `web/static/js/app.js` (navbar scroll-reactive
+ lien actif). Fonctionnalités existantes non touchées (édition inline,
suppression, export PDF/HTML, polling HTMX, statut GPU) — uniquement un
changement de classes CSS, vérifié par rendu Jinja de chaque template après
migration. Ajout net : donut de répartition des sévérités sur
`session_detail.html` (calculé depuis les vraies vulnérabilités de la
session, pas de données figées) et lignes d'historique cliquables sur toute
leur largeur.

Non fait dans cette passe, volontairement hors périmètre : une sidebar
"détails de session" (provider/modèle utilisés) sur `session_detail.html` —
cette info n'est pas trackée par session dans la base aujourd'hui
(`pentron/db.py::get_session` ne renvoie que history/vulnérabilités/fixes/
exploits/summary), seulement au niveau global via `settings`. À reconsidérer
si le besoin se confirme (nécessiterait de stocker provider/modèle utilisés
au moment du scan, pas seulement le réglage courant).

## Tentatives d'exploitation autorisées — évolution séparée

Le rapport distingue désormais les pistes d'exploitation suggérées des appels
d'outils réellement dispatchés pendant l'analyse. Une future évolution pourra
ajouter un type d'appel explicite pour les tentatives d'exploitation, limité à
une liste fermée d'actions sûres, soumis aux garde-fous de scope existants et à
une autorisation opérateur claire. Cette capacité offensive n'est pas incluse
dans le pipeline actuel.

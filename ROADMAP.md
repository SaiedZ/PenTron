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

### Découverte de répertoires/fichiers (`gobuster`, `ffuf`)
Utile pour trouver des chemins exposés (panels admin, backups, `.git/`...),
mais génère beaucoup de requêtes vers la cible (bruteforce de wordlist =
potentiellement des milliers de requêtes). C'est plus agressif que tout ce
qu'on a actuellement, peut ressembler à une attaque DoS légère si mal
configuré, et pourrait déclencher des alertes/bannissements IP chez la
cible. À encadrer sérieusement (wordlist courte, délai entre requêtes) si on
l'ajoute.

### `nuclei`
Puissant, mais c'est un piège pour la philosophie "detection only" qu'on
vient de formaliser dans le README : ses templates vont du simple
fingerprinting jusqu'à des tentatives d'exploitation actives (CVE PoC,
injection...). Si on l'intègre un jour, il faudrait restreindre strictement
aux catégories `exposure`/`technologies`/`misconfiguration`, jamais
`vulnerabilities`/`exploits` — sinon on réintroduit par la porte de derrière
ce qu'on a explicitement exclu.

### `wpscan`
Pertinent seulement si la cible est WordPress (donc conditionnel à whatweb
qui le détecte d'abord), et uniquement en mode énumération passive, jamais
avec bruteforce de comptes.

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

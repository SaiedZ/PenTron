# PENTRON — Roadmap restante

Cette roadmap ne contient que les évolutions encore ouvertes. Les
fonctionnalités déjà livrées sont documentées dans le code, les tests et
l'historique Git.

## Priorité recommandée

### 1. Découverte prudente de répertoires et fichiers

Statut : à discuter avant implémentation.

Candidat recommandé : `gobuster` ou `ffuf` avec :

- une wordlist courte et ciblée ;
- un délai entre les requêtes ;
- un timeout global strict ;
- un avertissement explicite dans l'interface ;
- les garde-fous de scope existants ;
- aucune exécution implicite par l'IA.

Cette fonctionnalité génère nettement plus de trafic que les outils actuels
et peut provoquer du rate-limiting ou affecter une cible fragile.

Décision attendue : choix de l'outil, wordlist, cadence et activation manuelle.

### 2. Enregistrer le provider et le modèle par session

Statut : non implémenté.

- Stocker le provider et le modèle utilisés au moment du scan.
- Ajouter la migration de base de données correspondante.
- Sérialiser ces informations avec la session.
- Les afficher dans une section « Session details ».

Les réglages globaux actuels ne permettent pas de retrouver de façon fiable
le modèle réellement utilisé pour une ancienne session.

## Évolutions optionnelles

### Chat avec outils — phase 4

Statut : à décider après retour d'usage de la v1.

- Étudier l'ajout contrôlé d'appels `[TOOL:]` ou `[SEARCH:]`.
- Ne jamais reprendre directement les tags générés par le modèle sans
  validation.
- Réutiliser les contrôles de scope, SSRF et les allowlists existantes.
- Exiger une confirmation humaine pour toute action générant du trafic.

La v1 du chat reste volontairement conversationnelle et sans outils.

### Nuclei avec templates figés

Statut : faible priorité.

- Utiliser une version figée des templates.
- Maintenir une allowlist de templates examinés manuellement.
- Désactiver les mises à jour automatiques.
- Exclure les templates d'exploitation active.

Le coût de maintenance et le risque de dérive du périmètre restent élevés.

### Découpage de `providers.py`

Statut : refactor secondaire, non urgent.

Transformer `providers.py` en package avec un fichier par provider seulement
si le fichier devient difficile à maintenir ou si de nouveaux providers sont
ajoutés.

## Pistes différées nécessitant un accord explicite

### Rotation de proxy

Mise de côté. Reprendre la discussion sur les objectifs, les risques et la
traçabilité avant toute implémentation.

### Exploitation assistée ou mode « dangerous »

Non autorisé dans le périmètre actuel. Toute évolution devra prévoir :

- une liste fermée d'actions ;
- une confirmation humaine explicite ;
- des contrôles de scope stricts ;
- une journalisation complète ;
- des limites empêchant les actions irréversibles.

### Shodan ou Censys

Différé : nécessite une clé API tierce, potentiellement payante, et n'est pas
prioritaire actuellement.

---
title: "Collecte de Documents : Automatiser les Relances"
description: "Un acheteur verse l'acompte, puis le dossier s'enlise. Comment un agent IA relance les pièces KYC et bancaires sur WhatsApp et met à jour le CRM."
date: "2026-10-03"
category: "Automatisation des Tâches Métier"
readingTime: "8"
keywords: "collecte de documents automatisée, automatisation collecte de documents, relance documents clients, collecte de documents WhatsApp, collecte KYC immobilier, agent IA mise à jour CRM"
noBrandSuffix: "true"
---

# Collecte de Documents : Automatiser les Relances

## La Signature de la Réservation N'est Pas la Ligne d'Arrivée

Un chargé de relation client d'un promoteur résidentiel de Pune conclut une réservation le samedi. L'acheteur verse l'acompte, serre la main et repart satisfait. Le mercredi, le dossier est bloqué.

La banque exige des bulletins de salaire et trois mois de relevés. L'équipe conformité du promoteur veut une pièce d'identité et un justificatif de domicile pour chaque co-emprunteur. L'acte d'attribution doit revenir signé. L'acheteur, qui a un emploi à plein temps, envoie à 23 h une photo floue d'une seule carte PAN sur le WhatsApp personnel du chargé de relation et considère l'affaire réglée.

Personne ici n'est négligent. La tâche est conçue pour échouer à la main : une seule personne gère quarante dossiers ouverts, chacun avec deux ou trois pièces manquantes différentes, et les relances se font quand il reste dix minutes.

Cet article porte sur cette tâche précise : collecter les documents dus par l'acheteur après la réservation, et garder la liste de contrôle du CRM exacte pendant ce temps. L'exemple est un promoteur résidentiel indien ; le schéma s'applique partout où l'onboarding s'arrête faute de papiers que le client doit fournir.

## Ce Qu'est Vraiment la Tâche

« Collecter les documents » ressemble à un seul métier. Ce sont quatre.

1. **Savoir ce qui est dû.** La liste varie selon le profil de l'acheteur. Un salarié résident, un travailleur indépendant, un non-résident (NRI) et un dossier à plusieurs co-emprunteurs déclenchent chacun un ensemble différent, et la banque qui finance l'achat peut ajouter ses propres exigences à celles du promoteur.
2. **Demander, puis redemander.** Chaque pièce manquante appelle une demande, puis une relance, puis une relance différente quand la première reste sans réponse.
3. **Contrôler ce qui arrive.** Un fichier qui n'est pas le bon document, qui appartient à une autre personne, qui est rogné ou périmé est pire que l'absence de fichier, car la liste affiche désormais « reçu ».
4. **L'enregistrer.** Le CRM doit montrer, par acheteur et par document, ce qui a été demandé, ce qui est revenu et qui l'a accepté.

La plupart des équipes gèrent ces quatre tâches avec un tableur et de la mémoire. La première automatisation se limite en général à la deuxième, une salve de rappels programmés, et elle échoue.

## Pourquoi les Salves de Rappels Ne Fonctionnent Pas

Un rappel générique (« Merci d'envoyer vos documents en attente ») oblige l'acheteur à deviner lesquels. Une demande dont l'effort reste flou se reporte facilement, et une demande reportée un jour de semaine chargé le reste souvent.

Une demande utile est précise et petite : « Il nous manque encore votre dernier bulletin de salaire. Une photo suffit ; veillez à ce que les quatre coins soient visibles. » Une pièce, une consigne, une réponse.

Le modèle de la salve présente un second défaut : il ignore ce qui est déjà arrivé. Si un document est arrivé à 14 h et que le rappel part à 17 h, l'acheteur est relancé pour une pièce qu'il a déjà envoyée. Son message suivant à un humain sera agacé.

Le rappel doit lire la liste de contrôle avant de parler. C'est le moment où l'outil cesse d'être un planificateur et devient un employé IA doté d'une mission définie.

## Ce Que Fait l'Employé IA, Étape par Étape

L'agent travaille sur [WhatsApp](/whatsapp-donna-agents.html), où se trouvent déjà les acheteurs indiens, et écrit dans le CRM que l'équipe des opérations commerciales utilise déjà. La comparaison avec le processus manuel :

| Étape | Manuel | Employé IA |
|---|---|---|
| Construire la liste | Le chargé de relation s'en souvient ou copie le dossier précédent | La génère à partir du profil acheteur, du mode de financement et des co-emprunteurs saisis dans le CRM |
| Demander | Message ponctuel depuis le téléphone du chargé de relation | Envoie une demande par pièce, dans la langue de l'acheteur, depuis le numéro de l'entreprise |
| Recevoir | La photo atterrit dans une conversation personnelle | L'image ou le PDF arrive dans le stockage documentaire de l'entreprise, relié à la fiche acheteur |
| Contrôler | Accepté s'il semble à peu près correct | Vérifie le type, la lisibilité, la concordance du nom avec l'acheteur et la validité des dates |
| Corriger | Détecté plus tard, souvent au stade du prêt | Répond aussitôt : « Il semble s'agir de la page 2 seulement ; pouvez-vous envoyer la page 1 ? » |
| Enregistrer | Tableur, s'il est à jour | Le statut de la liste change par document, avec date de réception et référence du fichier |
| Escalader | Le chargé de relation y pense tôt ou tard | Après un nombre d'essais défini, signale le dossier avec le motif et s'arrête |

Deux limites comptent. D'abord, l'agent vérifie qu'un document est exploitable. Savoir si une pièce d'identité est authentique et si l'acheteur satisfait aux règles KYC du promoteur reste du ressort d'une personne désignée de l'équipe conformité. La mission de l'agent est de lui remettre un dossier complet et lisible, pas de prendre la décision de conformité. Ensuite, il n'improvise jamais la liste. Si le profil de l'acheteur ne correspond à aucune liste définie, il interroge le chargé de relation au lieu de deviner.

Pour l'étape en amont, c'est-à-dire la manière dont la demande est devenue un acheteur qualifié, voir [ce que pose vraiment un qualificateur de leads IA](/blog/fr/ai-lead-qualification-what-it-asks.html). La collecte de documents commence là où la qualification s'arrête.

## Quatre Faits de Canal Qui Façonnent la Conception

Ce sont des propriétés de WhatsApp et de la réglementation indienne sur les données qui changent la manière de construire le flux. Chacune est vérifiée auprès de la source de la plateforme ou des autorités.

Le premier fait est la fenêtre de 24 heures. Quand un acheteur écrit à votre numéro professionnel, une fenêtre de service client de 24 heures s'ouvre, et vous pouvez répondre librement pendant cette durée. En dehors de cette fenêtre, Meta impose un message modèle (template) préapprouvé ([Meta for Developers, documentation de la WhatsApp Business Platform](https://developers.facebook.com/documentation/business-messaging/whatsapp/messages/send-messages/)). Pour la collecte de documents, la première demande après une semaine de silence doit donc partir sous forme de modèle approuvé ; elle doit réclamer la pièce la plus utile, car la réponse de l'acheteur rouvre la fenêtre.

Le deuxième est la taille des fichiers. L'API Cloud accepte les images jusqu'à 5 Mo et les PDF jusqu'à 100 Mo ([référence média de Meta](https://developers.facebook.com/docs/whatsapp/cloud-api/reference/media/)). Un document d'une page photographié au téléphone peut dépasser 5 Mo, et un relevé bancaire de plusieurs pages se demande mieux en PDF. L'agent doit préciser le format attendu.

Le troisième est que les médias ne restent pas sur WhatsApp. Meta indique que les fichiers médias envoyés via l'API sont conservés 30 jours, sauf suppression anticipée. Un promoteur qui prend WhatsApp pour un classeur perdra des documents. L'agent doit télécharger chaque fichier à réception et l'écrire dans le stockage documentaire de l'entreprise, le CRM conservant la référence.

Le quatrième est le consentement et la finalité. L'Inde a notifié les règles DPDP 2025 (Digital Personal Data Protection Rules), qui mettent en application la loi DPDP de 2023, avec un calendrier de mise en conformité échelonné sur 18 mois. Ces règles exigent des avis de consentement distincts et clairs, qui expliquent la finalité précise de la collecte ([annonce du Press Information Bureau](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2190014)). Pour la collecte de documents, cela implique que le premier message indique ce qui est collecté et pourquoi, que l'agent ne demande que ce que la liste exige, et que la règle de conservation soit définie avant l'arrivée du premier fichier. Un conseil juridique doit confirmer l'application des règles à votre traitement.

## Concevoir le Calendrier de Relance

Une conception de départ raisonnable, à ajuster d'après vos propres délais de clôture de dossier :

- **Demande.** Envoyée dans la journée suivant la réservation, avec une ou deux pièces les plus urgentes et la raison (« la banque en a besoin pour lancer l'accord de prêt »).
- **Première relance.** Deux jours plus tard, uniquement pour les pièces encore manquantes, en nommant la pièce précise.
- **Aide au format.** Si une pièce est refusée à l'arrivée, la correction part aussitôt, avec un exemple de ce qui est attendu.
- **Seconde relance, sous un autre angle.** Propose de l'aide : « Un appel serait-il plus simple ? Je peux en organiser un avec votre chargé de relation. »
- **Arrêt et passage de relais.** Après le nombre de tentatives convenu, l'agent cesse d'écrire et signale au chargé de relation le dossier, la pièce et l'historique. Il ne continue pas.

La règle d'arrêt compte autant que les rappels. Un acheteur qui a versé un acompte et reçoit chaque jour un message automatique se sent surveillé, pas servi. La même retenue vaut pour les autres tâches de suivi : l'article sur la [coordination de rendez-vous quand l'agenda change](/blog/fr/appointment-coordination-when-slots-move.html) décrit une autre tâche de relance répétitive qu'un coordinateur humain assume aujourd'hui et qu'un agent WhatsApp peut reprendre.

## Ce Que la Fiche CRM Doit Contenir

Le CRM transforme une pile de conversations en un statut que le directeur commercial lit d'un coup d'œil. Chaque fiche acheteur doit porter, par document :

| Champ | Exemple |
|---|---|
| Type de document | Bulletin de salaire, mois 1 |
| Requis pour | Accord de prêt bancaire |
| Statut | Demandé / Reçu / À corriger / Accepté |
| Reçu le | Horodatage de la conversation |
| Référence du fichier | Lien vers le stockage documentaire de l'entreprise |
| Accepté par | Agent (lisibilité) ou responsable conformité nommé (vérification) |
| Code motif | Rogné, mauvaise personne, périmé, mauvais type |

Distinguer « reçu » d'« accepté », et séparer le contrôle de lisibilité de la vérification de conformité, permet au responsable des opérations commerciales de se fier au tableau de bord. Un dossier marqué complet signifie qu'une personne de l'équipe conformité l'a examiné.

Si l'agent ne peut pas écrire proprement dans le CRM, l'ensemble se réduit à un outil de messagerie de plus. La page [chatbot IA pour l'immobilier](/industries/real-estate-ai-chatbot.html) montre comment se met en place l'amont de ce flux : la qualification sur WhatsApp, avec le dossier acheteur inscrit dans le CRM. La collecte de documents prolonge la même intégration vers les semaines qui suivent la réservation.

## Quoi Mesurer

Mesurez l'achèvement de la tâche, pas le volume de messages.

- **Jours entre la réservation et un dossier complet.** Le chiffre principal. Relevez la valeur de départ avant la mise en service de l'agent.
- **Dossiers complets sans intervention du chargé de relation.** La part que l'agent clôt seul.
- **Secondes demandes par document.** Un chiffre élevé signale une première demande peu claire ou une liste erronée.
- **Refusés à l'arrivée contre refusés par la banque.** Le second chiffre doit tendre vers zéro.
- **Passages de relais et leurs motifs.** Les tendances montrent où le processus, et non l'agent, est défaillant.

Fixez la méthode de mesure et la période avant le lancement ; une comparaison avant/après sans valeur de départ ne prouve rien.

## Où Cela Se Passe Mal

Un acheteur envoie la photo d'une photo, prise sur un autre écran, et le contrôle laisse passer un fichier que la banque refusera plus tard. La parade : un contrôle de lisibilité plus strict et une image d'exemple dans la demande.

Le document d'un co-emprunteur arrive dans la conversation de l'acheteur principal ; l'agent demande alors à qui il appartient avant de le classer.

Un acheteur répond en hindi ou en marathi à une demande en anglais. L'agent doit répondre dans la langue de l'acheteur, et les intitulés de la liste doivent exister dans chaque langue. C'est là que le [support multilingue](/blog/fr/multilingual-support-specialty-brands.html) prend toute sa valeur sur un marché non anglophone.

Un acheteur ignore le texte et préfère parler. Un suivi vocal, transmis via la même fiche CRM, reprend là où la conversation s'est arrêtée. Le canal est une propriété de l'acheteur, pas du système.

## FAQ

### L'agent vérifie-t-il les documents KYC ?

Non. Il contrôle que le document est du type attendu, lisible, à jour et au nom de l'acheteur, puis le transmet à un responsable conformité désigné qui décide. La vérification relève de la conformité, et le CRM doit consigner qui l'a effectuée.

### Quels documents relance-t-il ?

Ceux de la liste définie pour ce profil d'acheteur et ce mode de financement, et rien d'autre. La liste est configurée avec vos équipes opérations commerciales et conformité, jamais déduite. Collecter moins fait partie de la conception.

### Que se passe-t-il quand un acheteur ne répond plus ?

Après le nombre de tentatives convenu, l'agent s'arrête et signale le dossier au chargé de relation avec son historique. Celui-ci décide d'appeler, de rendre visite ou de mettre le dossier en attente.

### Remplace-t-il le chargé de relation ?

Il supprime les relances, la part du métier que personne n'apprécie. Le chargé de relation garde la relation, la négociation et chaque exception que l'agent lui transmet.

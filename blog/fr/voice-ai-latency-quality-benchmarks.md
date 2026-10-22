---
title: "Voice AI : latence, interruptions et transferts à évaluer"
description: "La confiance dans une voice AI tient au délai de réponse, aux interruptions et aux transferts. Chiffres sourcés, sept questions, seuils de départ pour un test."
noBrandSuffix: "true"
date: "2026-10-22"
category: "Voice AI"
readingTime: "9"
keywords: "latence voice AI, benchmarks qualité voice AI, latence bouche-à-oreille, temps de réponse IA conversationnelle, gestion des interruptions voice AI, transfert voice AI, précision reconnaissance vocale, critères d'évaluation voice AI"
---

# À Quoi Ressemble une « Bonne » Voice AI : Latence, Interruptions et Transferts

Trois mesures décident si les appelants font confiance à un agent vocal : l'écart entre le dernier mot de l'appelant et le premier son de l'agent, la fréquence à laquelle l'agent s'arrête à tort ou parle à tort par-dessus l'appelant, et la capacité d'un transfert à atteindre un humain avec un résumé exploitable. Les recommandations publiées par Twilio pour un agent standard (reconnaissance vocale, modèle de langage, synthèse vocale) prévoient environ 1,1 seconde entre le dernier mot de l'appelant et l'arrivée de la réponse à son oreille. Un éditeur qui annonce bien moins vous doit donc les conditions de mesure.

Ce guide vous donne les chiffres sourcés qui existent, dit clairement là où il n'y en a pas, et se termine par des questions et des seuils de départ pour un test de recette, utilisables dans un cahier des charges.

## L'Écart Entre la Démo et la Réalité

La démo de chaque éditeur est soignée. Trois mois après le déploiement, les opérations reçoivent des plaintes : le système sonne « robotique », coupe la parole aux clients en pleine phrase, ou se tait au moment précis où il devrait passer la main à une personne. La cause est rarement le modèle. C'est la distance entre les conditions de la démo et les conditions réelles : accents, bruit de fond, paroles qui se chevauchent, charge de pointe et variabilité du réseau.

## Dimension 1 : La Latence

En voice AI, la latence est le temps qui sépare la fin de la phrase de l'appelant du moment où le premier son de l'agent arrive à son oreille. Les ingénieurs parlent de délai de tour de parole (« turn gap »). C'est le signal de qualité le plus net, car il décide si l'appel ressemble à une conversation ou à une mauvaise ligne.

### À quoi ressemble une conversation entre humains

Stivers et ses collègues ont mesuré le timing des réponses dans dix langues et l'ont publié dans [PNAS en 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2705608/). Le décalage moyen de réponse sur l'ensemble de leurs données est de +208 ms, les moyennes par langue s'écartant d'environ 250 ms de part et d'autre. Les gens s'attendent à ce qu'une réponse commence en une fraction de seconde.

Les normes de télécommunication offrent une seconde référence. La recommandation [UIT-T G.114](https://www.itu.int/dms_pubrec/itu-t/rec/g/T-REC-G.114-200305-I!!SUM-HTM-E.htm) juge acceptable, pour la plupart des applications, un délai réseau unidirectionnel jusqu'à 150 ms, et recommande de ne pas dépasser 400 ms dans la planification générale des réseaux. Elle précise aussi que les tâches très interactives, dont les appels vocaux, peuvent être affectées par des délais bien inférieurs. La G.114 porte sur le temps de transmission sur le réseau, pas sur le temps de traitement d'un agent.

Aucune de ces sources ne dit combien de temps un appelant attend un agent IA, et nous n'avons trouvé aucune étude publiée qui le fasse. Ces chiffres décrivent ce à quoi les appelants sont habitués, pas un seuil prouvé au-delà duquel ils raccrochent. Tout tableau d'éditeur qui associe des tranches de latence à des taux d'abandon (« au-delà de deux secondes, l'appelant croit la ligne coupée ») est l'opinion de cet éditeur, sauf s'il cite des données.

### Où passe le temps

En novembre 2025, Twilio a publié des plages de budget pour un agent en cascade, c'est-à-dire un agent qui fait passer l'audio successivement par la reconnaissance vocale, un modèle de langage et la synthèse vocale :

| Mesure | Cible (ms) | Limite haute (ms) |
|---|---|---|
| Reconnaissance vocale | 350 | 500 |
| Modèle de langage, délai avant le premier jeton | 375 | 750 |
| Synthèse vocale, délai avant le premier octet | 100 | 250 |
| Délai de tour côté plateforme | 885 | 1 100 |
| Délai de tour bouche-à-oreille | 1 115 | 1 400 |

Source : Twilio, [Core Latency in AI Voice Agents](https://www.twilio.com/en-us/blog/developers/best-practices/guide-core-latency-ai-voice-agents), 17 novembre 2025. Il s'agit de recommandations d'ingénierie publiées par un éditeur. Twilio les présente comme des repères médians pour le lancement initial d'un agent en cascade simple, et comme des points de départ, pas comme la meilleure performance possible. Le délai côté plateforme exclut le trajet de l'audio sur Internet ou sur le réseau téléphonique. Le délai bouche-à-oreille l'inclut.

Deux enseignements se dégagent du tableau. Les trois modèles représentent 825 ms sur la cible de 1 115 ms. Le reste correspond au transport de l'audio, à la mise en mémoire tampon et aux échanges entre services : un modèle plus rapide ne suffit donc pas à récupérer tout l'écart.

Le second concerne la queue de distribution. Twilio avertit que la détection intelligente de fin de parole, qui fait patienter le système quand il croit que l'appelant parle encore, peut abaisser la médiane tout en provoquant des pics soudains de latence quand la prédiction est fausse. La médiane seule peut flatter un système qui fait attendre un appelant sur vingt.

### Comment lire une annonce de latence

Posez quatre questions avant de comparer deux chiffres :

- **Points de départ et d'arrivée.** Délai côté plateforme ou bouche-à-oreille ? Le second est ce que vit l'appelant.
- **Médiane ou 95e percentile.** Demandez les deux, ainsi que la cause des pires appels.
- **Trafic.** Des appels téléphoniques réels à votre pic de simultanéité, ou une ligne de démo tranquille ?
- **Appels d'outils.** Les chiffres de Twilio sont une latence de base et excluent les pics dus aux appels d'outils. Si l'agent consulte une commande dans votre ERP en cours de tour, cette consultation s'ajoute au délai.

Demandez aussi si la pile fonctionne en streaming. Celle qui transmet des résultats partiels de la reconnaissance au modèle puis à la synthèse commence à parler avant que la réponse complète n'existe. Celle qui attend la transcription ou la réponse entière ajoute cette attente à chaque tour.

## Dimension 2 : La Gestion des Interruptions

La gestion des interruptions, ou barge-in, détermine ce que fait le système quand l'appelant parle pendant que l'agent parle encore. C'est la fonctionnalité le plus souvent derrière les plaintes « robotique » qui arrivent après le lancement.

### Les deux modes d'échec

**Faux positifs, l'agent est trop sensible.** Il s'arrête dès qu'il entend un son : bruit de fond, toux, l'appelant qui dit « mm-hmm ». L'agent se coupe sans cesse et semble dysfonctionner. Les appelants dans un atelier, une voiture ou un open space le ressentent le plus.

**Faux négatifs, l'agent n'est pas assez sensible.** Il parle par-dessus une vraie tentative d'interruption. Un appelant dit « attendez, ce n'est pas ça » ou demande une personne, et l'agent poursuit. C'est l'échec qui abîme la confiance le plus vite, car l'appelant voit qu'on l'a ignoré.

### Ce qu'il faut demander

Les systèmes d'interruption combinent généralement le volume par rapport à un plancher de bruit, le contenu audio de type parole et une durée minimale de parole avant que l'agent ne s'arrête. Les éditeurs diffèrent sur la façon dont ces paramètres sont fixés et sur la possibilité de les modifier pour vos appelants. Nous ne donnons aucun seuil chiffré, car aucun n'est standard d'une pile à l'autre.

Demandez les taux de faux positifs et de faux négatifs dans trois conditions : un bureau calme, un centre de contact avec du bruit ambiant, et un appelant mobile dans un véhicule. Un éditeur qui ne peut pas les produire à partir de déploiements réels n'a pas testé dans vos conditions.

La reprise compte autant que la détection. Après une interruption, l'agent doit en prendre acte et revenir là où en était la conversation, sans que l'appelant ait à recommencer. Cela suppose que la couche du modèle conserve l'état de la conversation, pas seulement le dernier énoncé.

## Dimension 3 : La Qualité des Transferts

Le transfert est le moment où l'agent passe un appelant à une personne, et l'événement à plus fort enjeu d'un déploiement. Bien fait, il est presque invisible. Mal fait, il annule l'efficacité que le reste du système apporte.

### Un plafond pour le temps de transfert

Nous retenons trois secondes, entre le « je vous mets en relation » de l'agent et la présence d'une personne en ligne, comme plafond de recette. C'est notre règle empirique, pas une norme publiée. Au-delà de quelques secondes de silence, un appelant au téléphone ne distingue plus un transfert d'une coupure : il raccroche, et vos rapports comptent un transfert raté.

### Le résumé de contexte

Quand l'agent transfère, que reçoit la personne ? Le minimum que nous accepterions :

- Nom de l'appelant et identifiant de compte, s'il est authentifié
- Motif de l'appel en une phrase
- Étapes déjà réalisées par l'agent, par exemple « numéro de commande confirmé, compte vérifié, remboursement demandé pour l'article 4821 »
- Un signal de sentiment : neutre, frustré ou en escalade

Une personne qui démarre avec le résumé n'a pas à demander à l'appelant de répéter le motif de son appel. Demandez à l'éditeur un transfert en direct et regardez l'écran de réception au moment du transfert. S'il est vide, ou n'affiche que le numéro de téléphone, la mise en œuvre est incomplète.

### Transferts à chaud et à froid

- **Transfert à froid :** l'agent connecte l'appelant à la prochaine personne disponible puis se déconnecte. La personne reçoit un résumé par le CRM ou une fenêtre contextuelle, et l'appelant patiente pendant le routage.
- **Transfert à chaud :** l'agent reste en ligne, présente l'appelant, livre le résumé puis se retire. Il n'y a pas d'attente, au prix d'une intégration plus poussée.

Si un éditeur ne propose que le transfert à froid, demandez quel temps d'attente cela représente pour votre file avant de signer.

## Sept Questions Avant de Déployer

| # | Question | Pourquoi c'est important |
|---|---|---|
| 1 | Quelles sont vos latences bouche-à-oreille médiane et au 95e percentile en charge de pointe ? | La médiane masque la queue. Le 95e percentile est ce que vivent vos pires appelants. |
| 2 | Ces mesures viennent-elles d'appels téléphoniques réels, appels d'outils inclus ? | Les lignes de démo n'ont ni charge simultanée ni consultation de systèmes. |
| 3 | Quels sont vos taux de faux positifs et de faux négatifs de barge-in pour les appelants mobiles ? | Demandez la mesure, pas une affirmation. |
| 4 | Qu'entend un appelant s'il interrompt en pleine réponse ? | Parcourez le scénario pendant la démo. |
| 5 | Que reçoit la personne lors du transfert, et à quelle vitesse ? | Regardez un transfert en direct avec l'écran de réception visible. |
| 6 | Proposez-vous le transfert à chaud ? Sinon, quel est le temps d'attente ? | Il fixe l'expérience de l'appelant à chaque escalade. |
| 7 | Quel est votre taux d'erreur de mots sur mes accents et mon vocabulaire ? | Un benchmark sur de l'audio de studio propre dit peu de chose des appels téléphoniques. |

## Seuils de Départ pour un Test de Recette

Nous n'avons trouvé aucune norme publiée de qualité acceptable pour les agents téléphoniques IA. Voici des points de départ que nous inscririons dans un accord de pilote, à ajuster selon votre propre trafic. Ils relèvent de notre jugement, pas de normes sectorielles.

- **Délai de tour.** Mesurez la médiane et le 95e percentile, bouche-à-oreille, sur des appels réels en pointe. Comparez la médiane aux chiffres de lancement publiés par Twilio : cible de 1 115 ms et limite haute de 1 400 ms. Un éditeur qui annonce bien mieux doit montrer ses conditions.
- **Barge-in.** Annotez un échantillon de vos propres appels, comptez les deux types d'erreur et convenez du taux toléré avant le début du pilote.
- **Reconnaissance vocale.** Faites transcrire par des personnes un ensemble de vos propres enregistrements, calculez le taux d'erreur de mots par rapport à cette référence et convenez à l'avance du seuil de réussite.
- **Transfert.** Trois secondes ou moins jusqu'à une personne connectée, avec le motif, l'état d'authentification, les étapes réalisées et le sentiment à l'écran au moment du décroché.

La même horloge tourne pour un outil de coaching qu'un commercial lit en pleine phrase, ce qui explique que [Rocket Sales Agent](/rocket-sales-agent.html) se mesure en secondes jusqu'à l'écran plutôt qu'en réponses par appel. Pour le choix du canal et le fonctionnement de la technologie, voir [Voice AI vs Chatbots](/blog/fr/voice-ai-vs-chatbots-channel-strategy.html) et [Comment la Voice AI Fonctionne Vraiment](/blog/fr/voice-ai-technology-explained-executives.html).

Si vous cadrez un projet vocal autour de vos propres parcours d'appel, notre page [développement d'agents vocaux IA](/ai-voice-agents.html) décrit notre méthode. Tout chiffre de latence que nous vous donnons doit s'accompagner des quatre conditions ci-dessus, et vous devez nous y tenir.

## FAQ

### Quelles sont les causes d'une latence élevée dans les systèmes de voice AI ?
La reconnaissance vocale, le délai du modèle avant le premier jeton et la synthèse vocale, auxquels s'ajoutent le transport audio et les échanges entre services. Une détection de fin de parole trop patiente, un traitement par lots au lieu du streaming, des appels d'outils vers les systèmes internes et une infrastructure sous-dimensionnée en pointe aggravent le délai.

### Une latence d'une seconde est-elle acceptable pour un agent téléphonique voice AI ?
La cible de lancement de Twilio pour un agent standard est d'environ 1,1 seconde bouche-à-oreille à la médiane : une seconde est donc ordinaire aujourd'hui. Les humains se répondent en environ 200 ms, si bien qu'une simple confirmation paraîtra lente. Testez avec vos propres appelants et surveillez les répétitions et les abandons.

### Comment tester la qualité d'une voice AI avant de signer un contrat ?
Demandez un pilote sur du trafic d'appels réels, pas une démo en bac à sable. Règle empirique : attendez plusieurs centaines d'appels réels avant de lire les percentiles, pour que le 95e ne dépende pas d'une poignée d'appels. Demandez un tableau de bord des percentiles de latence, des événements de barge-in et des résultats de transfert.

### Qu'est-ce que le taux d'erreur de mots et quelle cible viser ?
Le taux d'erreur de mots (WER) est la part des mots qu'un système de reconnaissance vocale transcrit incorrectement par rapport à une transcription humaine. Il n'existe pas de bonne cible universelle, car il dépend de la qualité audio, des accents et du vocabulaire. Convenez du seuil de réussite à l'avance, mesurez-le sur vos propres enregistrements et écartez tout chiffre obtenu sur de la parole de studio propre.

### La voice AI gère-t-elle les interruptions aussi bien qu'une personne ?
Pas dans toutes les conditions. Un agent qui travaille à partir de l'audio peut être trompé par le bruit de fond et par les courtes marques d'écoute comme « mm-hmm ». Nous n'avons trouvé aucun benchmark indépendant comparant agents et humains : testez avec vos appelants et gardez un chemin simple vers un humain.

Sources consultées le 22 octobre 2026 : Stivers et al., PNAS 2009 (via PubMed Central) ; résumé de l'UIT-T G.114 (2003) ; Twilio, Core Latency in AI Voice Agents (17 novembre 2025).

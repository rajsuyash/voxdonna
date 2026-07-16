/*
 * Juliette — Concierge immobilier WhatsApp Breteuil · scénarios de démo.
 * Chaque scénario est un petit graphe de nœuds : message client → messages du bot → réponses rapides.
 * Données illustratives. Types de renderer : text, reco, cards, rate, alloc, store, appt,
 * order, profile, campaign, voiceIn, voiceOut, rag, lead, system.
 */
window.SCENARIOS = {

  /* 1 ──────────────────────────── DÉCOUVERTE DU BIEN ─────────────────── */
  discovery: {
    title: 'Trouver mon bien', emoji: '🏙️', persona: 'Antoine · cadre dirigeant',
    blurb: '"3 pièces à Passy, ~1,7 M€" → biens sélectionnés avec le pourquoi.',
    entry: 'start',
    nodes: {
      start: {
        user: "Bonjour, je cherche un 3 pièces à Passy, budget autour de 1,7 M€",
        bot: [
          { t:'text', text:"Excellent brief, Antoine ! 🏡 Passy donc — je confronte cela à nos biens disponibles dans le *16ᵉ* (avec une belle alternative à Neuilly)." },
          { t:'reco', query:{ budget: 1700000, config: '3 pièces', city: 'Paris' }, n:3 },
          { t:'text', text:"Le *3 pièces de Passy* est le meilleur candidat — au calme, double séjour, proche écoles et commerces. Je vous envoie le dossier complet, ou j'organise une visite privée ?" },
        ],
        choices: [
          { label:'📄 Dossier complet', goto:'dossier' },
          { label:'🏡 Et à Neuilly ?', goto:'neuilly' },
          { label:'📅 Organiser une visite', goto:'visite' },
        ],
      },
      dossier: {
        user: 'Envoyez-moi le dossier',
        bot: [
          { t:'text', text:"J'envoie le dossier du *3 pièces Passy* 📄 — prix, surface loi Carrez, DPE, taxe foncière, charges de copropriété et frais de notaire estimés. Rien de caché." },
          { t:'system', text:'Dossier PDF envoyé · DPE inclus · accusé de lecture activé' },
          { t:'text', text:"La plupart des acquéreurs demandent aussi les frais annexes : dans l'ancien, comptez ~7–8 % de frais de notaire. Je peux tout détailler avant que vous ne signiez quoi que ce soit." },
        ],
        choices: [ { label:'📅 Organiser une visite', goto:'visite' }, { label:'Parfait, merci !', goto:'wrap' } ],
      },
      neuilly: {
        user: 'Et à Neuilly, qu\'auriez-vous ?',
        bot: [
          { t:'text', text:"Neuilly offre plus d'espace pour un budget proche — voici deux références :" },
          { t:'cards', ids:['NE-4P-09','NE-MV-08'], note:"*Neuilly-sur-Seine* — quartiers Les Sablons & Saint-James" },
          { t:'text', text:"Mon avis franc : Passy pour la vie parisienne et la revente facile ; Neuilly pour l'espace, le calme et les écoles si vous pensez famille. Certains clients visitent les deux le même jour. 🙂" },
        ],
        choices: [ { label:'Rester sur Passy', goto:'visite' }, { label:'📅 Voir les deux', goto:'visite' } ],
      },
      visite: {
        user: 'Organisez une visite',
        bot: [
          { t:'store', city:'Paris' },
          { t:'appt', kind:'visit', store:'Paris', when:'Sam. 19 juil., 11h00' },
          { t:'text', text:"C'est fait ! Votre conseiller *Laurent* vous accueille à l'agence Victor Hugo — visite du bien, tour du quartier et point sur le dossier, environ 60 minutes. Je vous envoie un rappel la veille au soir. 🙂" },
        ],
        choices: [ { label:'Parfait, merci !', goto:'wrap' } ],
      },
      wrap: {
        bot: [
          { t:'lead', data:{ nom:'Antoine', bien:'3 pièces', secteur:'Paris 16ᵉ · Passy', budget:'1,6–1,7 M€', horizon:'≤ 3 mois', prochaine_étape:'Visite sam. 11h' }, score:'CHAUD' },
          { t:'system', text:'Lead transmis au CRM · conseiller Laurent assigné · rappel programmé' },
        ],
        choices: [],
      },
    },
  },

  /* 2 ──────────────────────────── VISITE PRIVÉE ─────────────────────── */
  sitevisit: {
    title: 'Visite privée', emoji: '📅', persona: 'Claire & Marc · famille',
    blurb: 'Créneau de visite réservé en moins d\'une minute — avec l\'itinéraire.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Peut-on visiter la maison de Neuilly ce dimanche ?',
        bot: [
          { t:'text', text:"Bien sûr ! L'agence *Neuilly* propose dimanche des créneaux à *11h00*, *14h30* et *17h00* — lequel vous convient à tous les deux ?" },
        ],
        choices: [
          { label:'11h00', goto:'confirm' },
          { label:'17h00', goto:'confirm' },
          { label:'Impossible — visite vidéo ?', goto:'virtual' },
        ],
      },
      confirm: {
        user: 'Dimanche nous va !',
        bot: [
          { t:'store', city:'Neuilly' },
          { t:'appt', kind:'visit', store:'Neuilly', when:'Dim. 20 juil., 11h00' },
          { t:'text', text:"Réservé ! 🎉 Petit conseil : stationnement facile avenue Charles de Gaulle le dimanche. Vous verrez la maison de ville, le jardin et le quartier Saint-James — comptez une bonne heure." },
          { t:'lead', data:{ nom:'Claire & Marc', bien:'Maison', secteur:'Neuilly', budget:'à préciser', horizon:'3–6 mois', prochaine_étape:'Visite dim. 11h' }, score:'TIÈDE' },
        ],
        choices: [],
      },
      virtual: {
        user: 'On ne peut pas se déplacer ce week-end — visite vidéo ?',
        bot: [
          { t:'store', city:'Virtual' },
          { t:'appt', kind:'visit', store:'Virtual', when:'Dim. 20 juil., 16h00' },
          { t:'text', text:"Noté ! Un conseiller vous appellera en visio sur ce numéro et parcourra la *maison en direct* — vous dirigez, il marche. La moitié de nos acquéreurs internationaux réservent ainsi avant de venir une seule fois pour finaliser. 📱" },
          { t:'lead', data:{ nom:'Claire & Marc', bien:'Maison', secteur:'Neuilly', budget:'à préciser', horizon:'3–6 mois', prochaine_étape:'Visite vidéo dim. 16h' }, score:'TIÈDE' },
        ],
        choices: [],
      },
    },
  },

  /* 3 ──────────────────────────── ÉCHÉANCIER VEFA ───────────────────── */
  payment: {
    title: 'Échéancier VEFA', emoji: '🧾', persona: 'Sophie · investisseuse',
    blurb: 'Échéancier légal sur un vrai montant — plus ce qui réserve le lot.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Si je réserve le 3 pièces neuf de Boulogne, comment se passent les paiements ?',
        bot: [
          { t:'text', text:"Bonne question à poser *avant* de tomber amoureux d'un bien 😄 En VEFA, les 980 000 € se répartissent selon un échéancier légal :" },
          { t:'alloc', total: 980000 },
          { t:'text', text:"Vous ne payez qu'au fur et à mesure de l'avancement, sécurisé par la Garantie Financière d'Achèvement. Et frais de notaire réduits (2–3 %) contre 7–8 % dans l'ancien." },
        ],
        choices: [
          { label:'Comment réserver le lot ?', goto:'token' },
          { label:'Et les frais de notaire ?', goto:'frais' },
        ],
      },
      token: {
        user: 'Que faut-il pour réserver le lot aujourd\'hui ?',
        bot: [
          { t:'rag', q:'compromis séquestre réservation vefa' },
          { t:'text', text:"En clair : un contrat de réservation avec un dépôt de garantie séquestré fige votre lot et votre étage, avec délai de rétractation de 10 jours. Je fais réserver le *lot B24* (le 3 pièces avec balcon que vous aimiez) par votre conseiller ?" },
        ],
        choices: [ { label:'Oui, réservez le B24', goto:'hold' }, { label:'Laissez-moi réfléchir', goto:'END' } ],
      },
      frais: {
        user: 'Et les frais de notaire ?',
        bot: [
          { t:'rag', q:'frais de notaire neuf vefa' },
          { t:'text', text:"Sur du neuf comme Boulogne, comptez 2–3 % contre 7–8 % dans l'ancien — un vrai avantage. Si vous préférez l'ancien avec du cachet, j'ai de belles références à Paris et à Neuilly." },
        ],
        choices: [ { label:'Oui, réservez le B24', goto:'hold' }, { label:'Voir des biens anciens', goto:'ready' } ],
      },
      ready: {
        user: 'Montrez-moi des biens anciens',
        bot: [ { t:'reco', query:{ style:'ancien', budget: 1200000 }, n:3 } ],
        choices: [ { label:'Réservez-en un pour moi', goto:'hold' } ],
      },
      hold: {
        user: 'Réservez-le pour moi',
        bot: [
          { t:'appt', kind:'reserve', product:'BB-NF-12' },
          { t:'text', text:"Réservé ! Votre conseiller vous appelle dans l'heure avec le contrat de réservation — dépôt de garantie chez le notaire, reçu directement ici. Le délai de rétractation de 10 jours commence à la signature. 🤝" },
          { t:'lead', data:{ nom:'Sophie', bien:'3 pièces neuf', secteur:'Boulogne-Billancourt', budget:'980 k€', horizon:'≤ 3 mois', prochaine_étape:'Contrat de réservation envoyé' }, score:'CHAUD' },
        ],
        choices: [],
      },
    },
  },

  /* 4 ──────────────────────────── FINANCEMENT ───────────────────────── */
  emi: {
    title: 'Financement & crédit', emoji: '🏦', persona: 'Julien · acquéreur Paris',
    blurb: 'Taux, mensualités et 3 offres de banques privées sans quitter la conversation.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Quelle mensualité pour le 4 pièces haussmannien du parc Monceau ?',
        bot: [
          { t:'text', text:"Calculons. Le 4 pièces Monceau est à *2,3 M€*. Voici les repères du moment :" },
          { t:'rate' },
          { t:'text', text:"Avec 30 % d'apport (690 k€), vous empruntez *1,61 M€* → environ *9 350 €/mois* sur 20 ans à 3,55 %, ou près de *8 150 €* sur 25 ans. Chaque banque vous prive différemment — c'est là qu'on intervient." },
        ],
        choices: [
          { label:'Obtenez-moi des offres', goto:'offers' },
          { label:'Suis-je finançable ?', goto:'eligible' },
        ],
      },
      eligible: {
        user: 'Comment savoir si je suis finançable ?',
        bot: [
          { t:'rag', q:'crédit financement banque taux' },
          { t:'text', text:"Règle simple : les banques veulent une mensualité sous ~35 % des revenus nets — soit environ 27 k€/mois de revenus pour 9 350 €, seul ou à deux. Le patrimoine et l'apport assouplissent vite ce seuil en banque privée." },
        ],
        choices: [ { label:'Obtenez-moi des offres', goto:'offers' } ],
      },
      offers: {
        user: 'Obtenez-moi les offres',
        bot: [
          { t:'text', text:"C'est parti. Notre bureau financement présente votre profil à *LCL Banque Privée, BNP et Société Générale* et rapporte des offres concurrentes — généralement sous *5 jours ouvrés*, sans frais." },
          { t:'system', text:'Dossier financement FIN-2841 créé · consentement recueilli · liste de pièces envoyée' },
          { t:'lead', data:{ nom:'Julien', bien:'4 pièces', secteur:'Paris 17ᵉ · Monceau', budget:'2,3 M€', horizon:'3–6 mois', prochaine_étape:'Pré-accord · 3 banques' }, score:'CHAUD' },
        ],
        choices: [],
      },
    },
  },

  /* 5 ──────────────────────────── SUIVI DE CHANTIER ─────────────────── */
  status: {
    title: 'Suivi de chantier', emoji: '🏗️', persona: 'Acquéreur VEFA · Boulogne',
    blurb: 'Avancement par étape, garantie d\'achèvement et date de livraison — 24/7.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Où en est mon appartement ? Réservation BB-B-204',
        bot: [
          { t:'text', text:"Ravie de vous retrouver ! 👷 Je sors le suivi en direct de votre lot au programme *Rives de Seine · Boulogne* :" },
          { t:'order', data:{ id:'BB-B-204 · Rives de Seine', item:'3 pièces · 72 m² · 4ᵉ étage, balcon', status:'Mise hors d\'eau atteinte — gros œuvre 70 %', eta:'Livraison maintenue : T4 2027', note:'Dernier point chantier : 4 juil. · prochain appel de fonds à l\'achèvement (T2 2027, est.)' } },
          { t:'text', text:"Vous voulez les photos du chantier du mois, ou votre position de paiement sur l'échéancier VEFA ?" },
        ],
        choices: [
          { label:'📸 Photos du chantier', goto:'photos' },
          { label:'💰 Position de paiement', goto:'ledger' },
        ],
      },
      photos: {
        user: 'Envoyez les photos du chantier',
        bot: [
          { t:'system', text:'Album d\'avancement juillet envoyé · 6 photos + clip drone 40s · lot mis en avant' },
          { t:'text', text:"Envoyé ! 📸 Vous les recevrez automatiquement le premier vendredi de chaque mois — sans avoir à demander. Autre chose sur votre réservation ?" },
        ],
        choices: [ { label:'💰 Position de paiement', goto:'ledger' }, { label:'Tout est clair, merci !', goto:'END' } ],
      },
      ledger: {
        user: 'Où en sont mes paiements ?',
        bot: [
          { t:'order', data:{ id:'Échéancier · BB-B-204', item:'Payé : 686 k€ sur 980 k€ (70 %)', status:'Aucun appel de fonds en attente', eta:'Prochaine étape : achèvement (~245 k€, T2 2027 est.)', note:'Tous les reçus et le contrat dans votre coffre-fort numérique — tapez "documents" à tout moment.' } },
          { t:'text', text:"Vous êtes parfaitement à jour ✅ Je vous préviendrai ici le jour où l'appel de fonds d'achèvement sera émis, avec le RIB." },
        ],
        choices: [],
      },
    },
  },

  /* 6 ──────────────────────────── FRAIS & FISCALITÉ (RAG) ───────────── */
  docs: {
    title: 'Frais & fiscalité', emoji: '📚', persona: 'Acquéreur prudent',
    blurb: 'Frais de notaire, plus-value, IFI, DPE — réponses ancrées, avec sources.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Concrètement, à combien s\'élèvent les frais de notaire ?',
        bot: [
          { t:'rag', q:'frais de notaire ancien neuf' },
          { t:'text', text:"Posez-moi n'importe quelle question côté paperasse — je réponds à partir de nos vrais documents, jamais au doigt mouillé." },
        ],
        choices: [
          { label:'Plus-value à la revente ?', goto:'plusvalue' },
          { label:'Suis-je concerné par l\'IFI ?', goto:'ifi' },
        ],
      },
      plusvalue: {
        user: 'Et la plus-value si je revends ?',
        bot: [
          { t:'rag', q:'plus-value fiscalité revente exonération' },
          { t:'text', text:"En résidence principale, exonération totale. En secondaire ou investissement, l'imposition décroît avec la durée de détention. Sur un bien conservé longtemps, elle finit par disparaître — je peux chiffrer un cas précis." },
        ],
        choices: [ { label:'Suis-je concerné par l\'IFI ?', goto:'ifi' }, { label:'Ça m\'aide, merci !', goto:'END' } ],
      },
      ifi: {
        user: 'Est-ce que je suis concerné par l\'IFI ?',
        bot: [
          { t:'rag', q:'ifi fortune immobilière patrimoine' },
          { t:'text', text:"Au-delà de 1,3 M€ de patrimoine immobilier net, oui — mais plusieurs montages (SCI, démembrement, dette d'acquisition) réduisent l'assiette. Notre notaire partenaire fait le point avec vous, en toute transparence. 🙂" },
        ],
        choices: [],
      },
    },
  },

  /* 7 ──────────────────────────── ACQUÉREUR INTERNATIONAL (VOIX) ────── */
  nri: {
    title: 'Acquéreur international · notes vocales', emoji: '🌏', persona: 'Mr. Okonkwo · Londres',
    blurb: 'Note vocale en anglais, réponse vocale en français — procuration, change, visite vidéo.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'voiceIn', lang:'EN', dur:'0:12', text:"I'm based in London, looking for a pied-à-terre in central Paris. Can everything be handled remotely?", gloss:"Je suis à Londres, je cherche un pied-à-terre dans le centre de Paris. Tout peut-il se faire à distance ?" },
          { t:'voiceOut', lang:'FR', dur:'0:15', text:"Absolument ! Visite en visio, financement, acte — tout peut se faire à distance. Seule la signature chez le notaire nécessite une procuration, que nous préparons pour vous.", gloss:"Absolutely — video viewing, financing, deed can all be remote. Only the notary signature needs a power of attorney, which we prepare for you." },
          { t:'rag', q:'non-résident international procuration change' },
        ],
        choices: [
          { label:'Réserver ma visite vidéo', goto:'tour' },
          { label:'Quel bien me conviendrait ?', goto:'reco' },
        ],
      },
      reco: {
        user: 'Quels biens conviennent le mieux à un acquéreur international ?',
        bot: [
          { t:'reco', query:{ audience:'pied-a-terre', budget: 1200000 }, n:3 },
          { t:'text', text:"Un pied-à-terre dans le 6ᵉ ou le 7ᵉ reste la valeur sûre des acquéreurs internationaux — emplacement, liquidité à la revente et location facile entre deux séjours. Je peux joindre une note de gestion locative à votre dossier." },
        ],
        choices: [ { label:'Réserver ma visite vidéo', goto:'tour' } ],
      },
      tour: {
        user: 'Réserver la visite vidéo',
        bot: [
          { t:'appt', kind:'visit', store:'Virtual', when:'Ven. 18 juil., 19h00 CET (18h00 GMT)' },
          { t:'text', text:"Réservé à une heure confortable pour Londres 🌆 Votre conseillère du desk international, *Élodie*, vous appellera sur ce numéro — visite du bien en direct, puis questions procuration et change." },
          { t:'lead', data:{ nom:'Mr. Okonkwo (Londres)', bien:'Pied-à-terre', secteur:'Paris centre', budget:'~1,2 M€', horizon:'3–6 mois', prochaine_étape:'Visite vidéo ven. 19h · desk international' }, score:'CHAUD' },
        ],
        choices: [],
      },
    },
  },

  /* 8 ──────────────────────────── AVANT-PREMIÈRE OFF-MARKET ─────────── */
  festival: {
    title: 'Diffusion off-market', emoji: '💎', persona: 'Campagne · clients opt-in',
    blurb: 'Avant-première off-market à 20 000 clients — chaque réponse traitée à l\'instant.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'campaign', data:{ title:'Avant-première off-market ✨', body:"Nouvelle sélection confidentielle : penthouse-terrasse près de la Madeleine, maison de ville à Neuilly, villa vue mer au Cap d'Antibes. Accès prioritaire réservé à nos clients avant toute mise sur le marché.", cta:"Découvrir la sélection" } },
          { t:'system', text:'Diffusion : 20 000 clients opt-in · 92 % délivrés · 41 % ouverts dans la première heure (illustratif)' },
          { t:'text', text:"👆 Voilà ce qui arrive sur le WhatsApp de chaque client concerné. Et quand des centaines répondent en même temps — je réponds à *tous*, à la fois. Essayez :" },
        ],
        choices: [
          { label:'Quels biens exactement ?', goto:'price' },
          { label:'Je veux l\'accès prioritaire', goto:'lead' },
        ],
      },
      price: {
        user: 'Quels biens dans cette sélection ?',
        bot: [
          { t:'cards', ids:['PA-PH-06','CA-VL-11'], note:'Sélection off-market — prix communiqué sur rendez-vous privé' },
          { t:'text', text:"Ces biens ne seront pas diffusés publiquement. L'accès se fait par ordre d'inscription — je vous place sur la liste d'avant-première ?" },
        ],
        choices: [ { label:'Oui — liste prioritaire', goto:'lead' } ],
      },
      lead: {
        user: 'Placez-moi sur la liste prioritaire',
        bot: [
          { t:'appt', kind:'bridal', store:'Paris', when:'Avant-première privée · sam. 26 juil., 10h30' },
          { t:'lead', data:{ nom:'Client avant-première', bien:'Prestige off-market', secteur:'Paris / Neuilly / Riviera', budget:'à définir', horizon:'≤ 3 mois', prochaine_étape:'RDV avant-première' }, score:'TIÈDE' },
          { t:'system', text:'Inscription confirmée · dossier confidentiel préparé · rappel J-1 programmé' },
        ],
        choices: [],
      },
    },
  },

  /* 9 ──────────────────────────── MÉMOIRE CLIENT ────────────────────── */
  concierge: {
    title: 'Mémoire du client', emoji: '🧠', persona: 'Nathalie · visite en mai',
    blurb: 'Se souvient de sa visite, sa sélection et son financement — reprend en cours de route.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Bonjour, j\'ai visité en mai — du nouveau sur ce 3 pièces à Passy ?',
        bot: [
          { t:'text', text:"Ravie de vous retrouver, Nathalie ! 👋 Bien sûr que je me souviens — voici où nous en étions :" },
          { t:'profile', data:{ visite:'Agence Victor Hugo · 18 mai', sélection:'3 pièces · Passy · étage élevé', budget:'1,6–1,7 M€', financement:'Pré-accord BNP 1,2 M€ (valable jusqu\'à sept.)', préférence:'Au calme · double séjour' } },
          { t:'text', text:"Nouveauté depuis votre visite : *deux 3 pièces au calme* se sont libérés à Passy la semaine dernière, et votre pré-accord est toujours valable. L'un coche toutes vos cases. 🎯" },
        ],
        choices: [
          { label:'Montrez-moi ce bien', goto:'unit' },
          { label:'Revisiter ce week-end', goto:'visit' },
        ],
      },
      unit: {
        user: 'Montrez-moi le bien',
        bot: [
          { t:'cards', ids:['PA-3P-03'], note:'*Lot 4ᵉ étage* · au calme sur cour · correspond à votre sélection de mai' },
          { t:'text', text:"À 1,65 M€, il entre dans votre pré-accord avec de la marge. Les 3 pièces au calme partent vite dans ce secteur — je le bloque pendant que vous organisez la revisite ?" },
        ],
        choices: [ { label:'Bloquez-le + revisite sam.', goto:'hold' } ],
      },
      visit: {
        user: 'Je passe ce week-end',
        bot: [
          { t:'appt', kind:'visit', store:'Paris', when:'Sam. 19 juil., 16h00' },
          { t:'text', text:"Réservé — et j'ai demandé à Laurent de garder les clés des *deux* 3 pièces pour que vous soyez dans les vraies pièces, pas seulement sur plan." },
        ],
        choices: [ { label:'Bloquez aussi le lot', goto:'hold' } ],
      },
      hold: {
        user: 'Bloquez ce lot pour moi',
        bot: [
          { t:'appt', kind:'reserve', product:'PA-3P-03' },
          { t:'lead', data:{ nom:'Nathalie', bien:'3 pièces · Passy', secteur:'Paris 16ᵉ', budget:'1,65 M€', horizon:'≤ 1 mois', prochaine_étape:'Lot bloqué · revisite sam. 16h' }, score:'CHAUD' },
          { t:'system', text:'Continuité : 54 jours depuis la première visite · zéro contexte perdu · conseiller notifié' },
        ],
        choices: [],
      },
    },
  },

  /* 10 ─────────────────────────── QUALIFICATION DE LEAD ─────────────── */
  lead: {
    title: 'Qualification de lead', emoji: '🎯', persona: 'Lead portail · 23h40',
    blurb: 'Lead de portail à minuit → qualifié, scoré et RDV pris avant le petit-déjeuner.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'system', text:'23h42 · Nouveau lead depuis un portail immobilier → opt-in WhatsApp · réponse en 4 secondes' },
          { t:'text', text:"Bonsoir ! Je suis *Juliette* de Breteuil — vous venez de vous renseigner sur un *3 pièces à Nice*. Je suis une assistante IA ; je réponds tout de suite pour ne pas vous faire attendre demain matin. 🙂 Rapidement : résidence secondaire, investissement, ou résidence principale ?" },
        ],
        choices: [
          { label:'Résidence secondaire', goto:'q2' },
          { label:'Investissement', goto:'q2inv' },
        ],
      },
      q2: {
        user: 'Plutôt résidence secondaire',
        bot: [ { t:'text', text:"Parfait — le Carré d'Or de Nice est idéal pour ça. Quelle taille vous conviendrait : *2 pièces*, *3 pièces*, ou *plus grand* ?" } ],
        choices: [ { label:'3 pièces', goto:'q3' }, { label:'Plus grand', goto:'q3' } ],
      },
      q2inv: {
        user: 'Surtout un investissement',
        bot: [ { t:'text', text:"Nice est un bon choix — la Promenade loue très bien en saison. Vous visez du *neuf* (TVA récupérable en résidence gérée) ou de l'*ancien* Belle Époque ?" } ],
        choices: [ { label:'Neuf, résidence gérée', goto:'q3' }, { label:'Ancien Belle Époque', goto:'q3' } ],
      },
      q3: {
        user: '3 pièces',
        bot: [ { t:'text', text:"Noté. Et la fourchette de budget — plutôt *1–1,3 M€*, *1,3–1,6 M€*, ou encore à définir ? (Aucun jugement 😄)" } ],
        choices: [ { label:'1,3–1,6 M€', goto:'q4' }, { label:'Encore à définir', goto:'q4' } ],
      },
      q4: {
        user: 'Autour de 1,3–1,6 M€',
        bot: [ { t:'text', text:"Parfait — notre 3 pièces vue mer du Carré d'Or est pile dans cette fourchette. Dernière question : vous souhaitez avancer *sous 3 mois*, *3–6 mois*, ou vous explorez ?" } ],
        choices: [ { label:'3–6 mois', goto:'close' }, { label:'J\'explore', goto:'closeExplore' } ],
      },
      close: {
        user: 'Dans les 3 à 6 mois',
        bot: [
          { t:'cards', ids:['CA-3P-10'], note:'Votre correspondance — gardée pour votre visite' },
          { t:'text', text:"Vous êtes un acquéreur sérieux, faisons les choses bien : visite privée ce week-end ? Samedi *11h* ou dimanche *16h* — j'aurai le dossier et le point fiscalité prêts et imprimés." },
        ],
        choices: [ { label:'Samedi 11h', goto:'done' }, { label:'Dimanche 16h', goto:'done' } ],
      },
      closeExplore: {
        user: 'J\'explore pour l\'instant',
        bot: [
          { t:'text', text:"Très bien — un achat de cette nature ne doit jamais être précipité. Je vous envoie la sélection niçoise et vous ajoute à la liste des avant-premières. Quand vous serez prêt, je suis à un message. 🙏" },
          { t:'lead', data:{ nom:'Lead portail', bien:'3 pièces', secteur:'Nice', budget:'1,3–1,6 M€', horizon:'exploration', prochaine_étape:'Nurturing · sélection envoyée' }, score:'À SUIVRE' },
        ],
        choices: [],
      },
      done: {
        user:  'Samedi 11h',
        bot: [
          { t:'appt', kind:'visit', store:"Côte d'Azur", when:'Sam. 19 juil., 11h00' },
          { t:'lead', data:{ nom:'Lead portail', bien:'3 pièces', secteur:'Nice', budget:'1,3–1,6 M€', horizon:'3–6 mois', prochaine_étape:'Visite sam. 11h' }, score:'CHAUD' },
          { t:'system', text:'Qualifié en 94 secondes à 23h44 · le conseiller découvre un brief complet à 9h · zéro minute humaine dépensée' },
        ],
        choices: [],
      },
    },
  },
};

window.SCENARIO_ORDER = ['discovery','sitevisit','payment','emi','status','docs','nri','festival','concierge','lead'];

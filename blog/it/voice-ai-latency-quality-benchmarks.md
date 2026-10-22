---
title: "Voice AI: latenza, interruzioni e trasferimenti da valutare"
description: "La fiducia in una voice AI dipende da tempo di risposta, interruzioni e trasferimenti. Cifre con fonte, sette domande e soglie di partenza per un collaudo."
noBrandSuffix: "true"
date: "2026-10-22"
category: "Voice AI"
readingTime: "9"
keywords: "latenza voice AI, benchmark qualità voice AI, latenza bocca-orecchio, tempo di risposta IA conversazionale, gestione delle interruzioni voice AI, trasferimento voice AI, accuratezza riconoscimento vocale, criteri di valutazione voice AI"
---

# Come Suona una «Buona» Voice AI: Latenza, Interruzioni e Trasferimenti

Tre misure decidono se i chiamanti si fidano di un agente vocale: l'intervallo tra l'ultima parola del chiamante e il primo suono dell'agente, la frequenza con cui l'agente si ferma a sproposito o parla sopra il chiamante, e la capacità di un trasferimento di arrivare a una persona con un riepilogo utilizzabile. Le indicazioni pubblicate da Twilio per un agente standard (riconoscimento vocale, modello linguistico, sintesi vocale) prevedono circa 1,1 secondi tra l'ultima parola del chiamante e l'arrivo della risposta al suo orecchio. Un fornitore che dichiara molto meno vi deve quindi le condizioni di misura.

Questa guida vi dà le cifre con fonte che esistono, dice chiaramente dove non ce ne sono e si chiude con domande e soglie di partenza per un collaudo, da inserire in un capitolato.

## Il Divario tra Demo e Realtà

La demo di ogni fornitore è curata. Tre mesi dopo il rilascio, le operations ricevono lamentele: il sistema suona «robotico», interrompe i clienti a metà frase o resta in silenzio proprio quando dovrebbe passare la chiamata a una persona. La causa raramente è il modello. È la distanza tra le condizioni della demo e quelle reali: accenti, rumore di fondo, voci sovrapposte, picchi di carico e variabilità di rete.

## Dimensione 1: La Latenza

Nella voice AI la latenza è il tempo che passa da quando il chiamante finisce la frase a quando il primo suono dell'agente arriva al suo orecchio. Gli ingegneri la chiamano turn gap, l'intervallo tra i turni di parola. È il segnale di qualità più netto, perché decide se la chiamata somiglia a una conversazione o a una linea disturbata.

### Come appare una conversazione tra persone

Stivers e colleghi hanno misurato i tempi di risposta in dieci lingue e li hanno pubblicati su [PNAS nel 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2705608/). Lo scarto medio di risposta sull'intero insieme di dati è di +208 ms, con le medie per lingua entro circa 250 ms da una parte e dall'altra. Le persone si aspettano che una risposta inizi entro una frazione di secondo.

Gli standard delle telecomunicazioni offrono un secondo riferimento. La raccomandazione [ITU-T G.114](https://www.itu.int/dms_pubrec/itu-t/rec/g/T-REC-G.114-200305-I!!SUM-HTM-E.htm) considera accettabile per la maggior parte delle applicazioni un ritardo di rete unidirezionale fino a 150 ms e raccomanda di non superare i 400 ms nella pianificazione generale delle reti. Osserva inoltre che le attività molto interattive, tra cui le chiamate vocali, possono risentire di ritardi molto inferiori. La G.114 riguarda il tempo di trasmissione sulla rete, non il tempo di elaborazione di un agente.

Nessuna delle due fonti dice quanto a lungo un chiamante aspetti un agente IA, e non abbiamo trovato alcuno studio pubblicato che lo faccia. Questi numeri descrivono ciò a cui i chiamanti sono abituati, non una soglia dimostrata oltre la quale riagganciano. Qualunque tabella di un fornitore che associa fasce di latenza a tassi di abbandono («oltre i due secondi il chiamante pensa che la linea sia caduta») è l'opinione di quel fornitore, a meno che citi dati.

### Dove va il tempo

A novembre 2025 Twilio ha pubblicato intervalli di budget per un agente a cascata, cioè un agente che fa passare l'audio in sequenza dal riconoscimento vocale, da un modello linguistico e dalla sintesi vocale:

| Misura | Obiettivo (ms) | Limite massimo (ms) |
|---|---|---|
| Riconoscimento vocale | 350 | 500 |
| Modello linguistico, tempo al primo token | 375 | 750 |
| Sintesi vocale, tempo al primo byte | 100 | 250 |
| Intervallo di turno lato piattaforma | 885 | 1.100 |
| Intervallo di turno bocca-orecchio | 1.115 | 1.400 |

Fonte: Twilio, [Core Latency in AI Voice Agents](https://www.twilio.com/en-us/blog/developers/best-practices/guide-core-latency-ai-voice-agents), 17 novembre 2025. Sono indicazioni di ingegneria pubblicate da un fornitore. Twilio le presenta come riferimenti mediani per il lancio iniziale di un agente a cascata semplice e come punti di partenza, non come la migliore prestazione possibile. L'intervallo lato piattaforma esclude il percorso dell'audio su Internet o sulla rete telefonica. L'intervallo bocca-orecchio lo include.

Dalla tabella emergono due conseguenze. I tre modelli rappresentano 825 ms sui 1.115 ms dell'obiettivo. Il resto è trasporto dell'audio, buffering e passaggi tra i servizi, quindi un modello più veloce da solo non recupera tutto il divario.

La seconda riguarda la coda della distribuzione. Twilio avverte che il rilevamento intelligente della fine del parlato, che fa attendere il sistema quando ritiene che il chiamante stia ancora parlando, può abbassare la mediana provocando però improvvisi picchi di latenza quando la previsione è sbagliata. La sola mediana può far apparire buono un sistema che fa attendere un chiamante su venti.

### Come leggere un dato di latenza

Prima di confrontare due numeri, ponete quattro domande:

- **Punti di inizio e di fine.** Intervallo lato piattaforma o bocca-orecchio? Il secondo è ciò che vive il chiamante.
- **Mediana o 95° percentile.** Chiedete entrambi e la causa delle chiamate peggiori.
- **Traffico.** Chiamate telefoniche reali al vostro picco di concorrenza o una linea demo tranquilla?
- **Chiamate a strumenti esterni.** Le cifre di Twilio sono latenza di base ed escludono i picchi dovuti alle chiamate a strumenti. Se l'agente consulta un ordine nel vostro ERP a metà turno, quella consultazione si somma all'intervallo.

Chiedete anche se lo stack funziona in streaming. Quello che passa risultati parziali dal riconoscimento al modello alla sintesi inizia a parlare prima che la risposta completa esista. Quello che attende l'intera trascrizione o l'intera risposta aggiunge quell'attesa a ogni turno.

## Dimensione 2: La Gestione delle Interruzioni

La gestione delle interruzioni, o barge-in, decide che cosa fa il sistema quando il chiamante parla mentre l'agente sta ancora parlando. È la funzione più spesso all'origine delle lamentele «robotico» che arrivano dopo il lancio.

### I due modi di fallire

**Falsi positivi, l'agente è troppo sensibile.** Si ferma appena sente un suono: rumore di fondo, un colpo di tosse, il chiamante che dice «mm-hmm». L'agente si interrompe di continuo e sembra malfunzionante. Ne soffrono di più i chiamanti in officina, in auto o in un open space.

**Falsi negativi, l'agente è poco sensibile.** Continua a parlare sopra un vero tentativo di interruzione. Il chiamante dice «aspetti, non è così» o chiede una persona, e l'agente prosegue. È il guasto che danneggia più in fretta la fiducia, perché il chiamante capisce di non essere stato ascoltato.

### Che cosa chiedere

I sistemi di interruzione in genere combinano il volume rispetto a una soglia di rumore, il contenuto audio simile al parlato e una durata minima di parlato prima che l'agente si fermi. I fornitori si differenziano per come questi parametri vengono impostati e per la possibilità di modificarli in base ai vostri chiamanti. Non indichiamo soglie numeriche perché nessuna è standard tra gli stack.

Chiedete i tassi di falsi positivi e falsi negativi in tre condizioni: un ufficio silenzioso, un centro di contatto con rumore ambientale e un chiamante mobile in auto. Un fornitore che non li ricava da installazioni reali non ha testato nelle vostre condizioni.

Il recupero conta quanto il rilevamento. Dopo un'interruzione l'agente deve prenderne atto e tornare al punto della conversazione, senza che il chiamante debba ricominciare. Questo richiede che il livello del modello mantenga lo stato della conversazione, non solo l'ultimo enunciato.

## Dimensione 3: La Qualità dei Trasferimenti

Il trasferimento è il momento in cui l'agente passa un chiamante a una persona, ed è l'evento più delicato di un'installazione. Fatto bene, è quasi invisibile. Fatto male, annulla l'efficienza che il resto del sistema produce.

### Un tetto per il tempo di trasferimento

Usiamo tre secondi, dal «la metto in contatto» dell'agente alla presenza di una persona in linea, come tetto di collaudo. È una nostra regola empirica, non uno standard pubblicato. Oltre pochi secondi di silenzio, chi chiama al telefono non distingue un trasferimento da una caduta di linea: riaggancia, e i vostri report contano un trasferimento fallito.

### Il riepilogo di contesto

Quando l'agente trasferisce, che cosa riceve la persona? Il minimo che accetteremmo:

- Nome del chiamante e ID account, se autenticato
- Motivo della chiamata in una frase
- Passaggi già svolti dall'agente, per esempio «numero d'ordine confermato, account verificato, rimborso richiesto per l'articolo 4821»
- Un indicatore di sentiment: neutro, frustrato o in escalation

Una persona che parte con il riepilogo non deve chiedere al chiamante di ripetere il motivo della chiamata. Chiedete al fornitore un trasferimento dal vivo e guardate lo schermo di ricezione nel momento del passaggio. Se è vuoto, o mostra solo il numero di telefono, l'implementazione è incompleta.

### Trasferimenti a caldo e a freddo

- **Trasferimento a freddo:** l'agente collega il chiamante alla prima persona disponibile e si disconnette. La persona riceve un riepilogo tramite CRM o schermata di contesto, e il chiamante attende durante l'instradamento.
- **Trasferimento a caldo:** l'agente resta in linea, presenta il chiamante, consegna il riepilogo e poi esce. Non c'è attesa, al prezzo di un'integrazione più impegnativa.

Se un fornitore offre solo il trasferimento a freddo, chiedete quale tempo di attesa comporta per la vostra coda prima di firmare.

## Sette Domande Prima del Rilascio

| # | Domanda | Perché conta |
|---|---|---|
| 1 | Quali sono le vostre latenze bocca-orecchio mediana e al 95° percentile al picco di carico? | La mediana nasconde la coda. Il 95° percentile è ciò che vivono i chiamanti peggiori. |
| 2 | Queste misure provengono da chiamate telefoniche reali, comprese le chiamate a strumenti? | Le linee demo non hanno carico concorrente né consultazioni di sistema. |
| 3 | Quali sono i vostri tassi di falsi positivi e falsi negativi di barge-in per i chiamanti mobili? | Chiedete la misura, non un'affermazione. |
| 4 | Che cosa sente un chiamante se interrompe a metà risposta? | Percorrete lo scenario durante la demo. |
| 5 | Che cosa arriva alla persona al trasferimento, e con che rapidità? | Guardate un trasferimento dal vivo con lo schermo di ricezione visibile. |
| 6 | Offrite il trasferimento a caldo? Se no, qual è il tempo di attesa? | Determina l'esperienza del chiamante a ogni escalation. |
| 7 | Qual è il vostro tasso di errore sulle parole con i miei accenti e il mio lessico? | Un benchmark su audio da studio pulito dice poco delle chiamate telefoniche. |

## Soglie di Partenza per un Collaudo

Non abbiamo trovato alcuno standard pubblicato di qualità accettabile per gli agenti telefonici IA. Questi sono punti di partenza che inseriremmo in un accordo di pilota, da adattare al vostro traffico. Sono un nostro giudizio, non norme di settore.

- **Intervallo di turno.** Misurate mediana e 95° percentile, bocca-orecchio, su chiamate reali al picco. Confrontate la mediana con le cifre di lancio pubblicate da Twilio: obiettivo di 1.115 ms e limite massimo di 1.400 ms. Un fornitore che dichiara molto meglio deve mostrare le condizioni.
- **Barge-in.** Annotate un campione delle vostre chiamate, contate i due tipi di errore e concordate il tasso tollerato prima dell'inizio del pilota.
- **Riconoscimento vocale.** Fate trascrivere da persone un insieme delle vostre registrazioni, calcolate il tasso di errore sulle parole rispetto a quella trascrizione e concordate in anticipo la soglia di superamento.
- **Trasferimento.** Tre secondi o meno fino a una persona collegata, con motivo, stato di autenticazione, passaggi svolti e sentiment sullo schermo quando risponde.

Lo stesso orologio vale per uno strumento di coaching che un commerciale legge a metà frase, ed è per questo che [Rocket Sales Agent](/rocket-sales-agent.html) si misura in secondi fino allo schermo anziché in risposte per chiamata. Per la scelta del canale e per come funziona la tecnologia, vedere [Voice AI vs Chatbot](/blog/it/voice-ai-vs-chatbots-channel-strategy.html) e [Come Funziona Davvero la Voice AI](/blog/it/voice-ai-technology-explained-executives.html).

Se state impostando un progetto vocale attorno ai vostri flussi di chiamata, la nostra pagina sullo [sviluppo di agenti vocali IA](/ai-voice-agents.html) descrive il nostro metodo. Ogni dato di latenza che vi forniamo deve essere accompagnato dalle quattro condizioni sopra, e dovete pretenderlo da noi.

## FAQ

### Quali sono le cause di un'elevata latenza nei sistemi di voice AI?
Il riconoscimento vocale, il tempo del modello al primo token e la sintesi vocale, più il trasporto dell'audio e i passaggi tra i servizi. Un rilevamento della fine del parlato troppo paziente, l'elaborazione a blocchi invece dello streaming, le chiamate a sistemi interni e un'infrastruttura sottodimensionata al picco peggiorano il ritardo.

### Un secondo di latenza è accettabile per un agente telefonico voice AI?
L'obiettivo di lancio di Twilio per un agente standard è di circa 1,1 secondi bocca-orecchio alla mediana, quindi oggi un secondo è nella norma. Le persone si rispondono in circa 200 ms, perciò una semplice conferma sembrerà lenta. Provate con i vostri chiamanti e osservate ripetizioni e abbandoni.

### Come si verifica la qualità di una voice AI prima di firmare un contratto?
Chiedete un pilota su traffico telefonico reale, non una demo in ambiente di prova. Come regola empirica, attendete diverse centinaia di chiamate reali prima di leggere i percentili, così il 95° non dipende da una manciata di chiamate. Chiedete una dashboard con percentili di latenza, eventi di barge-in ed esiti dei trasferimenti.

### Che cos'è il tasso di errore sulle parole e quale obiettivo porsi?
Il tasso di errore sulle parole (WER) è la quota di parole che un sistema di riconoscimento vocale trascrive in modo errato rispetto a una trascrizione umana. Non esiste un obiettivo valido per tutti, perché dipende da qualità audio, accenti e lessico. Concordate in anticipo la soglia di superamento, misuratela sulle vostre registrazioni e scartate qualunque cifra ottenuta su parlato da studio pulito.

### La voice AI gestisce le interruzioni bene quanto una persona?
Non in ogni condizione. Un agente che lavora dall'audio può essere ingannato dal rumore di fondo e dai brevi segnali di ascolto come «mm-hmm». Non abbiamo trovato alcun benchmark indipendente che confronti agenti e persone: provate con i vostri chiamanti e tenete una via semplice verso un operatore umano.

Fonti consultate il 22 ottobre 2026: Stivers et al., PNAS 2009 (tramite PubMed Central); sintesi ITU-T G.114 (2003); Twilio, Core Latency in AI Voice Agents (17 novembre 2025).

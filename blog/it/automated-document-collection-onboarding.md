---
title: "Raccolta Documenti: Automatizzare i Solleciti"
description: "Il cliente versa la caparra, poi la pratica si ferma. Come un agente IA sollecita documenti KYC e bancari su WhatsApp e aggiorna la checklist nel CRM."
date: "2026-10-03"
category: "Automazione dei Processi Aziendali"
readingTime: "8"
keywords: "raccolta documenti automatizzata, automazione raccolta documenti, sollecito documenti clienti, raccolta documenti WhatsApp, raccolta KYC immobiliare, agente IA aggiornamento CRM"
noBrandSuffix: "true"
---

# Raccolta Documenti: Automatizzare i Solleciti

## Il Giorno della Prenotazione Non È il Traguardo

Un responsabile relazioni clienti di un costruttore residenziale di Pune chiude una prenotazione il sabato. L'acquirente versa la caparra, stringe la mano e se ne va soddisfatto. Il mercoledì la pratica è ferma.

La banca chiede buste paga e tre mesi di estratti conto. Il team compliance del costruttore vuole documento d'identità e prova di residenza per ogni co-intestatario. L'atto di assegnazione deve tornare firmato. L'acquirente, che ha un lavoro a tempo pieno, alle 23 manda una foto sfocata di una sola carta PAN sul WhatsApp personale del responsabile e considera la cosa chiusa.

Nessuno qui è trascurato. Il compito è costruito per fallire a mano: una sola persona gestisce quaranta pratiche aperte, ciascuna con due o tre documenti mancanti diversi, e i solleciti partono quando restano dieci minuti liberi.

Questo articolo riguarda proprio quel compito: raccogliere i documenti che l'acquirente deve consegnare dopo la prenotazione e tenere corretta la checklist del CRM mentre accade. L'esempio è un costruttore residenziale indiano; lo schema vale ovunque l'onboarding si blocchi su carte che deve fornire il cliente.

## Che Cos'è Davvero il Compito

«Raccolta documenti» sembra un lavoro solo. Sono quattro.

1. **Sapere che cosa è dovuto.** L'elenco cambia con il profilo dell'acquirente. Un lavoratore dipendente residente, un autonomo, un non residente (NRI) e una domanda con più co-intestatari attivano ciascuno un insieme diverso, e la banca che finanzia l'acquisto può aggiungere requisiti propri a quelli del costruttore.
2. **Chiedere, e chiedere ancora.** Ogni documento mancante richiede una richiesta, poi un sollecito, poi un sollecito diverso quando il primo viene ignorato.
3. **Controllare ciò che arriva.** Un file che è il documento sbagliato, appartiene a un'altra persona, è tagliato o scaduto è peggio di nessun file, perché la checklist ora segna «ricevuto».
4. **Registrarlo.** Il CRM deve mostrare, per acquirente e per documento, che cosa è stato chiesto, che cosa è tornato e chi l'ha accettato.

La maggior parte dei team gestisce tutti e quattro con un foglio di calcolo e la memoria. La prima automazione copre di solito solo il secondo, una raffica di promemoria programmati, e fallisce.

## Perché le Raffiche di Promemoria Non Funzionano

Un promemoria generico («Vi preghiamo di inviare i documenti in sospeso») costringe l'acquirente a indovinare quali. Una richiesta dallo sforzo poco chiaro si rimanda facilmente, e una richiesta rimandata in un giorno feriale intenso spesso resta rimandata.

Una richiesta utile è precisa e piccola: «Ci manca ancora la sua ultima busta paga. Basta una foto; si assicuri che i quattro angoli siano visibili.» Un documento, un'istruzione, una risposta.

Il modello a raffica ha un secondo difetto: ignora ciò che è già arrivato. Se un documento è arrivato alle 14 e il promemoria parte alle 17, l'acquirente viene sollecitato per qualcosa che ha già inviato. Il suo messaggio successivo a una persona sarà irritato.

Il promemoria deve leggere la checklist prima di parlare. È il punto in cui lo strumento smette di essere un pianificatore e diventa un dipendente IA con un compito definito.

## Che Cosa Fa il Dipendente IA, Passo per Passo

L'agente lavora su [WhatsApp](/whatsapp-donna-agents.html), dove gli acquirenti indiani si trovano già, e scrive nel CRM che il team di sales operations usa già. Il confronto con il processo manuale:

| Passo | Manuale | Dipendente IA |
|---|---|---|
| Costruire la checklist | Il responsabile la ricorda o copia dalla pratica precedente | La genera da profilo acquirente, modalità di finanziamento e co-intestatari registrati nel CRM |
| Richiedere | Messaggio estemporaneo dal telefono del responsabile | Invia una richiesta per documento, nella lingua dell'acquirente, dal numero aziendale |
| Ricevere | La foto finisce in una chat personale | Immagine o PDF arrivano nell'archivio documentale aziendale, collegati alla scheda acquirente |
| Controllare | Accettato se sembra più o meno corretto | Verifica tipo, leggibilità, corrispondenza del nome con l'acquirente e validità delle date |
| Correggere | Notato dopo, spesso alla fase del mutuo | Risponde subito: «Sembra solo la pagina 2; può inviare la pagina 1?» |
| Registrare | Foglio di calcolo, se aggiornato | Lo stato della checklist cambia per documento, con data di ricezione e riferimento del file |
| Escalare | Il responsabile se ne ricorda prima o poi | Dopo un numero definito di tentativi, segnala la pratica con il motivo e si ferma |

Contano due limiti. Primo, l'agente verifica che un documento sia utilizzabile. Stabilire se un documento d'identità sia autentico e se l'acquirente rispetti le regole KYC del costruttore resta a una persona designata del team compliance. Il compito dell'agente è farle arrivare una pratica completa e leggibile, non prendere la decisione di conformità. Secondo, non improvvisa mai la checklist. Se il profilo dell'acquirente non corrisponde a nessun elenco definito, lo chiede al responsabile invece di tirare a indovinare.

Per il passaggio a monte, cioè come la richiesta è diventata un acquirente qualificato, vedi [che cosa chiede davvero un qualificatore di lead IA](/blog/it/ai-lead-qualification-what-it-asks.html). La raccolta documenti inizia dove finisce la qualificazione.

## Quattro Fatti di Canale che Condizionano il Progetto

Sono proprietà di WhatsApp e della normativa indiana sui dati che cambiano il modo di costruire il flusso. Ciascuna è verificata sulla fonte della piattaforma o delle autorità.

Il primo fatto è la finestra di 24 ore. Quando un acquirente scrive al vostro numero aziendale, si apre una finestra di assistenza clienti di 24 ore, e potete rispondere liberamente al suo interno. Fuori dalla finestra, Meta richiede un messaggio modello (template) preapprovato ([Meta for Developers, documentazione della WhatsApp Business Platform](https://developers.facebook.com/documentation/business-messaging/whatsapp/messages/send-messages/)). Per la raccolta documenti, la prima richiesta dopo una settimana di silenzio deve quindi partire come template approvato; deve chiedere il documento più utile, perché la risposta dell'acquirente riapre la finestra.

Il secondo è la dimensione dei file. La Cloud API accetta immagini fino a 5 MB e PDF fino a 100 MB ([riferimento media di Meta](https://developers.facebook.com/docs/whatsapp/cloud-api/reference/media/)). Un documento di una pagina fotografato con il telefono può superare i 5 MB, e un estratto conto di più pagine è meglio richiederlo in PDF. L'agente deve indicare il formato che vuole.

Il terzo è che i media non restano su WhatsApp. Meta dichiara che i file media inviati tramite API vengono conservati per 30 giorni, salvo cancellazione anticipata. Un costruttore che usa WhatsApp come archivio perderà documenti. L'agente deve scaricare ogni file alla ricezione e scriverlo nell'archivio documentale aziendale, con il CRM che conserva il riferimento.

Il quarto è consenso e finalità. L'India ha notificato le DPDP Rules 2025 (Digital Personal Data Protection Rules), che rendono operativa la legge DPDP del 2023, con un calendario di conformità graduale di 18 mesi. Le norme richiedono informative di consenso autonome e chiare, che spieghino la finalità specifica della raccolta ([comunicato del Press Information Bureau](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2190014)). Per la raccolta documenti ne consegue che il primo messaggio deve dire che cosa si raccoglie e perché, che l'agente deve chiedere solo ciò che la checklist richiede, e che la regola di conservazione va definita prima dell'arrivo del primo file. Un consulente legale deve confermare come le norme si applichino al vostro trattamento.

## Progettare il Calendario dei Solleciti

Un progetto di partenza ragionevole, da tarare sui vostri tempi di chiusura delle pratiche:

- **Richiesta.** Inviata entro un giorno dalla prenotazione, con uno o due documenti più urgenti e il motivo («la banca ne ha bisogno per avviare la delibera»).
- **Primo sollecito.** Due giorni dopo, solo per i documenti ancora mancanti, indicando quello preciso.
- **Aiuto sul formato.** Se un documento viene respinto all'arrivo, la correzione parte subito, con un esempio di ciò che serve.
- **Secondo sollecito, da un'altra angolazione.** Offre aiuto: «Sarebbe più comoda una telefonata? Posso organizzarla con il suo responsabile.»
- **Stop e passaggio di mano.** Dopo il numero di tentativi concordato, l'agente smette di scrivere e segnala al responsabile pratica, documento e cronologia. Non continua.

La regola di stop conta quanto i promemoria. Un acquirente che ha versato una caparra e riceve ogni giorno un messaggio automatico si sente sorvegliato, non servito. Lo stesso criterio vale per altri compiti di follow-up: l'articolo sul [coordinamento degli appuntamenti quando l'agenda cambia](/blog/it/appointment-coordination-when-slots-move.html) descrive un altro compito di sollecito ripetitivo, oggi in capo a un coordinatore umano, che un agente WhatsApp può assumere.

## Che Cosa Deve Contenere la Scheda CRM

Il CRM trasforma una pila di chat in uno stato che il direttore commerciale legge a colpo d'occhio. Ogni scheda acquirente deve riportare, per documento:

| Campo | Esempio |
|---|---|
| Tipo di documento | Busta paga, mese 1 |
| Necessario per | Delibera bancaria |
| Stato | Richiesto / Ricevuto / Da correggere / Accettato |
| Ricevuto il | Marca temporale dalla chat |
| Riferimento file | Link all'archivio documentale aziendale |
| Accettato da | Agente (leggibilità) o responsabile compliance nominato (verifica) |
| Codice motivo | Tagliato, persona sbagliata, scaduto, tipo sbagliato |

Distinguere «ricevuto» da «accettato», e separare il controllo di leggibilità dalla verifica di conformità, permette al responsabile sales operations di fidarsi della dashboard. Una pratica segnata come completa significa che una persona del team compliance l'ha esaminata.

Se l'agente non riesce a scrivere in modo pulito nel CRM, tutto si riduce a un altro strumento di chat. La pagina [chatbot IA per l'immobiliare](/industries/real-estate-ai-chatbot.html) mostra come si imposta la parte a monte di questo flusso: qualificazione su WhatsApp, con la scheda dell'acquirente scritta nel CRM. La raccolta documenti estende la stessa integrazione alle settimane successive alla prenotazione.

## Che Cosa Misurare

Misurate il completamento del compito, non il volume di messaggi.

- **Giorni dalla prenotazione a una pratica completa.** Il numero principale. Rilevate il valore di partenza prima dell'avvio dell'agente.
- **Pratiche complete senza intervento del responsabile.** La quota che l'agente chiude da solo.
- **Seconde richieste per documento.** Un valore alto indica una prima richiesta poco chiara o una checklist sbagliata.
- **Respinti all'arrivo contro respinti dalla banca.** Il secondo numero deve tendere a zero.
- **Passaggi di mano e relativi motivi.** Gli schemi mostrano dove è difettoso il processo, non l'agente.

Fissate metodo di misura e periodo prima del lancio; un confronto prima/dopo senza valore di partenza non è una prova.

## Dove Va Storto

Un acquirente invia la foto di una foto, scattata da un altro schermo, e il controllo lascia passare un file che la banca respingerà più tardi. Rimedio: un controllo di leggibilità più severo e un'immagine di esempio nella richiesta.

Il documento di un co-intestatario arriva nella chat dell'acquirente principale; l'agente chiede allora a chi appartiene prima di archiviarlo.

Un acquirente risponde in hindi o in marathi a una richiesta in inglese. L'agente deve rispondere nella lingua dell'acquirente, e i nomi della checklist devono esistere in ogni lingua. È qui che il [supporto multilingue](/blog/it/multilingual-support-specialty-brands.html) ripaga su un mercato non anglofono.

Un acquirente ignora il testo e preferisce parlare. Un follow-up vocale, passato attraverso la stessa scheda CRM, riprende da dove la chat si era fermata. Il canale è una proprietà dell'acquirente, non del sistema.

## FAQ

### L'agente verifica i documenti KYC?

No. Controlla che il documento sia del tipo atteso, leggibile, aggiornato e intestato all'acquirente, poi lo inoltra a un responsabile compliance designato che decide. La verifica è una responsabilità della compliance, e il CRM deve registrare chi l'ha eseguita.

### Quali documenti sollecita?

Quelli della checklist definita per quel profilo di acquirente e quella modalità di finanziamento, e nient'altro. La checklist si configura con i vostri team sales operations e compliance, non si deduce. Raccogliere meno fa parte del progetto.

### Che cosa succede quando un acquirente smette di rispondere?

Dopo il numero di tentativi concordato, l'agente si ferma e segnala la pratica al responsabile con la cronologia. Il responsabile decide se telefonare, andare di persona o mettere la pratica in attesa.

### Sostituisce il responsabile relazioni clienti?

Elimina i solleciti, la parte del lavoro che nessuno apprezza. Il responsabile mantiene la relazione, la trattativa e ogni eccezione che l'agente gli passa.

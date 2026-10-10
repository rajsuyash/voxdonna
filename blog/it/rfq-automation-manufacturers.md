---
title: "Automazione delle RFQ: Quotare Prima della Concorrenza"
description: "Come un agente IA trasforma le RFQ ricevute via e-mail in preventivi preparati nel vostro ERP e CRM, cosa può inviare da solo e cosa resta alle vendite."
date: "2026-10-10"
category: "Automazione dei Processi Aziendali"
readingTime: "8"
keywords: "automazione rfq, automazione richieste di offerta, automazione rfq industria manifatturiera, preventivo automatico da e-mail, agente ia rfq, dalla rfq al preventivo erp"
noBrandSuffix: "true"
---

# Automazione delle RFQ: Quotare Prima della Concorrenza

## La Risposta in Breve

Automatizzare le RFQ (richieste di offerta) significa affidare a un agente IA la lettura di ogni richiesta ricevuta via e-mail, l'abbinamento di ogni riga al vostro catalogo, il recupero di prezzo e disponibilità dal vostro ERP e la preparazione del preventivo. Per una classe ristretta di richieste, l'agente invia il preventivo da solo. Per tutte le altre consegna al vostro ufficio vendite interno una bozza pronta, con le righe dubbie segnalate. Il lavoro approda in due posti: un preventivo nell'ERP e un'opportunità nel CRM.

L'agente elimina la ricerca e la ribattitura dei dati tra «la richiesta arriva» e «il preventivo è pronto». Non elimina le decisioni che comportano un rischio sul margine. Quelle restano a una persona, finché i vostri stessi dati non mostrano che si possono delegare in sicurezza.

Questo articolo descrive uno schema di progettazione, non un risultato misurato. L'agente di acquisizione ordini pubblicato da VoxDonna gestisce ordini di acquisto, e i suoi casi di accettazione sono sintetici. Non abbiamo pubblicato risultati sulle RFQ, e nessun numero qui sotto è un risultato VoxDonna.

## Perché la Prima Risposta Conta, e Cosa Si Sa Davvero

Gran parte dei consigli sulle RFQ ripete un'idea: vince il fornitore che risponde per primo. Le prove a sostegno sono più sottili della ripetizione.

La fonte più nota è l'articolo del marzo 2011 della *Harvard Business Review*, «The Short Life of Online Sales Leads», di Oldroyd, McElheran ed Elkington. In un audit su 2.241 aziende statunitensi a cui era stato inviato un contatto di prova generato dal web, il 37% ha risposto entro un'ora, il 24% ha impiegato più di 24 ore e il 23% non ha mai risposto. In uno studio separato su 1,25 milioni di contatti presso 29 aziende B2C e 13 B2B, le aziende che contattavano un lead entro un'ora avevano quasi sette volte più probabilità di qualificarlo rispetto a quelle che aspettavano anche solo un'ora in più.

Prima di applicarlo ai preventivi servono due avvertenze. Si trattava di richieste web, non di RFQ, e i dati provenivano dalla piattaforma InsideSales, il cui CEO è coautore. Il testo integrale è leggibile nella [copia dell'Internet Archive](https://web.archive.org/web/2020/https://hbr.org/2011/03/the-short-life-of-online-sales-leads).

Non abbiamo trovato alcun indicatore indipendente e pubblicato sul tempo che intercorre tra RFQ e preventivo. Le pagine dei fornitori citano multipli di velocità e aumenti dei tassi di vittoria, ma è marketing dei fornitori: non costruite un business case su quei numeri.

Costruitelo sui vostri dati. Estraete gli ultimi 90 giorni della casella condivisa dei preventivi e calcolate due numeri: il tempo mediano tra l'arrivo della richiesta e la prima risposta, e la quota di richieste che non hanno mai ricevuto un preventivo. Sono la base di partenza con cui misurare qualsiasi pilota.

## In Cosa una RFQ Differisce da un Ordine di Acquisto

Un agente per gli ordini e un agente per i preventivi condividono gran parte dei meccanismi, ma il modo in cui sbagliano è diverso. Un ordine errato viene registrato e intercettato alla conferma d'ordine. Un preventivo errato è un prezzo o una data che avete promesso per iscritto.

| Dimensione | Ordine di acquisto | RFQ |
|---|---|---|
| Impegno dell'acquirente | Decisione presa; attende una conferma | Confronta fornitori; nessun impegno |
| Documento prodotto | Ordine cliente e conferma d'ordine | Preventivo con prezzo, tempi di consegna e data di validità |
| Qualità dell'input | Di solito i vostri codici o un riferimento contrattuale | Spesso una descrizione, un disegno o il codice di un concorrente |
| Prezzo | Verificato rispetto a un prezzo concordato | Da determinare: listino, contratto, sconto per volume, soglia di margine |
| Costo di un errore | Un ordine sbagliato registrato | Una promessa di prezzo da onorare o ritirare |
| Azione predefinita sensata | Registrare quando tutti i controlli passano | Preparare una bozza per approvazione, salvo regole esplicite di invio |

La lettura, l'abbinamento, i controlli deterministici e la traccia di audit dell'[acquisizione degli ordini di acquisto](/blog/it/purchase-order-intake-automation.html) si trasferiscono. Cambia solo l'ultimo passaggio: invece di registrare un ordine, l'agente sceglie tra inviare, preparare una bozza o sospendere.

## La Pipeline, Fase per Fase

Un agente RFQ di cui un responsabile vendite interne può fidarsi segue lo stesso percorso per ogni e-mail.

1. **Ricezione.** Monitora la casella condivisa dei preventivi, accetta i domini degli acquirenti noti e invia i mittenti sconosciuti a una coda di revisione. Un registro durevole prenota ogni messaggio prima che inizi il lavoro, così un riavvio a metà esecuzione non può produrre due risposte.
2. **Estrazione.** Legge il corpo del messaggio e gli allegati PDF o foglio di calcolo secondo uno schema fisso: acquirente, righe richieste (descrizione, codice dell'acquirente, quantità, unità), data richiesta, indirizzo di consegna e termine di risposta. Un'e-mail che non è una RFQ viene registrata e lasciata stare.
3. **Abbinamento.** Ogni riga viene confrontata con il vostro catalogo e con la tabella di corrispondenza del cliente. Il risultato per riga è: corrispondenza esatta, corrispondenza probabile o nessuna corrispondenza. Una corrispondenza probabile non viene mai quotata come se fosse esatta.
4. **Prezzo e disponibilità.** Legge dall'ERP il prezzo specifico del cliente, gli sconti per volume, la giacenza e il tempo di consegna standard. Questa fase è in sola lettura, e nessun modello genera un prezzo.
5. **Regole.** Codice ordinario verifica la soglia di margine, lo stato di credito o di blocco del cliente, la quantità minima, la validità del preventivo e ogni articolo che richiede una revisione tecnica. Ogni risultato viene registrato.
6. **Esito.** L'agente sceglie se inviare, preparare una bozza o sospendere, come descritto nella sezione successiva.
7. **Registrazione.** Il preventivo viene scritto nell'ERP, un'opportunità o un'attività viene registrata nel CRM con il thread allegato, e la risposta parte nel thread e-mail originale.

## Tre Esiti: Inviare, Preparare una Bozza, Sospendere

| Esito | Quando si applica | Cosa riceve l'acquirente | Cosa vedono le vendite interne |
|---|---|---|---|
| Invio | Ogni riga è una corrispondenza esatta, il prezzo deriva direttamente da contratto o listino, la giacenza copre la quantità, il margine supera la soglia, il cliente è in regola e il totale è sotto un tetto che stabilite voi | Un preventivo nel thread originale in pochi minuti | Una voce di registro |
| Bozza | Una corrispondenza probabile, uno sconto fuori regola o un tempo di consegna oltre la data richiesta | Un avviso che indica cosa si sta confermando e quando attendere il preventivo | Un preventivo preparato, con le righe da verificare evidenziate |
| Sospeso | Cliente bloccato, nessuna corrispondenza, disegno necessario, quantità contraddittorie, allegato illeggibile o consultazione dell'ERP fallita | Un avviso che indica cosa manca | Un'escalation con il motivo allegato |

Iniziate con l'invio disattivato. Trattate ogni RFQ come bozza per diverse settimane e confrontate ogni bozza con il preventivo che il vostro team avrebbe scritto. Abilitate l'invio solo per il gruppo di clienti e il tetto di valore in cui le bozze coincidevano, poi ampliate gradualmente.

## Un Esempio Concreto (Illustrativo)

È uno scenario costruito, non un dato cliente. Un produttore statunitense di viteria e raccordi industriali riceve alle 20:40 di un venerdì un'e-mail dall'acquirente di un distributore. Un PDF allegato elenca cinque righe.

| Riga | Cosa ha chiesto l'acquirente | Cosa fa l'agente | Esito |
|---|---|---|---|
| 1 | 5.000 pezzi con il codice dell'acquirente | La tabella di corrispondenza dà un solo articolo esatto; vale il prezzo contrattuale; la giacenza copre | Quotata |
| 2 | 2.000 pezzi, «zincati», mentre il catalogo ha due finiture zincate | Solo corrispondenza probabile; non sceglie la finitura | Segnalata alle vendite interne |
| 3 | 500 pezzi di un articolo con minimo di 1.000 | Non modifica la quantità di propria iniziativa | Segnalata alle vendite interne |
| 4 | 3.000 pezzi senza giacenza | Indica il tempo di consegna standard dell'ERP, che supera la data richiesta | Segnalata alle vendite interne |
| 5 | «Staffa su misura come da disegno allegato» | Nessuna corrispondenza a catalogo; serve l'ufficio tecnico | Sospesa |

Quattro righe su cinque richiedono una persona, quindi l'intera richiesta diventa una bozza. L'acquirente riceve comunque una risposta quella sera stessa: cinque righe ricevute, riga 1 quotata, righe da 2 a 5 in conferma, e l'ora entro cui l'azienda si è impegnata a rispondere. Inviare un preventivo parziale o attendere uno completo è una politica commerciale, e l'agente applica quella che scegliete.

Il lunedì le vendite interne aprono un'unica bozza preparata, con le domande aperte elencate, invece di un PDF da ribattere. Il vantaggio sta nelle prime ore e nella ribattitura. La fase di revisione resta.

## Cosa Arriva nell'ERP e nel CRM

L'agente scrive nell'ERP un preventivo con gli articoli abbinati, il prezzo e la sua origine, il tempo di consegna e la data di validità. Nel CRM crea o aggiorna un'opportunità o un'attività, collega il thread e-mail e assegna un responsabile.

Poiché scrive nei sistemi del cliente, i permessi sono ristretti: crea preventivi e registra attività, e non modifica mai listini, anagrafiche clienti o dati anagrafici degli articoli. La stessa e-mail ricevuta due volte produce un solo preventivo. Un controllo fallito non crea nulla.

Per il lato ordini della stessa casella, vedete come funziona l'[acquisizione degli ordini di vendita e di acquisto](/sap-email-agent.html) nel pilota pubblicato.

## Come Testare Prima che Scriva Qualcosa

Eseguite questi casi su una copia della casella dei preventivi e su un ERP di prova, e leggete il registro di esecuzione invece della risposta. Sono criteri di accettazione da eseguire, non risultati che abbiamo misurato.

1. **RFQ pulita da un acquirente noto, ogni riga con corrispondenza esatta.** Atteso: una bozza, oppure un invio se le vostre regole lo consentono.
2. **Un codice acquirente assente dalla tabella di corrispondenza.** Atteso: la riga viene sospesa e nulla viene inventato.
3. **La stessa RFQ consegnata due volte, con un riavvio a metà esecuzione.** Atteso: una sola risposta in totale.
4. **Una quantità nel corpo dell'e-mail che contraddice il PDF.** Atteso: sospesa, con entrambe le letture allegate.
5. **Un cliente con blocco di credito.** Atteso: nessun preventivo e un'escalation.
6. **Una consultazione prezzi dell'ERP che va in timeout.** Atteso: nessun prezzo ipotizzato e la richiesta viene sospesa.

L'agente che quota il caso pulito è facile da costruire. Contano i cinque casi in cui deve rifiutarsi di tirare a indovinare.

## Da Dove Cominciare

1. **Misurare la base di partenza.** Rilevate il tempo mediano di prima risposta e la quota di richieste senza preventivo negli ultimi 90 giorni.
2. **Trovare il vostro tetto di corrispondenze esatte.** Stimate la quota di RFQ che arrivano da acquirenti ricorrenti per articoli a catalogo. Quella quota limita quanto potrebbe mai partire senza revisione.
3. **Sistemare prima la tabella di corrispondenza.** I codici degli acquirenti associati ai vostri articoli sono di solito il vero collo di bottiglia, non il modello.
4. **Avviare il pilota in modalità bozza.** Misurate quanto spesso la bozza coincide con ciò che il vostro team avrebbe inviato.

Se state valutando l'alternativa dell'automazione a script, [Dipendente IA vs. RPA](/blog/it/ai-employee-vs-rpa.html) spiega dove si adatta ciascuna. L'insieme dei flussi di lavoro per l'industria è sulla nostra pagina dedicata agli [agenti IA per i produttori](/ai-for-manufacturers.html).

## FAQ

### Un agente IA può inviare preventivi senza approvazione umana?
Per una classe ristretta, sì. Righe con corrispondenza esatta, a prezzo di contratto o listino, con giacenza disponibile, margine sopra la soglia e un cliente in regola, possono partire in automatico sotto un tetto di valore che stabilite voi. Tutto ciò che esce da quella classe va a una persona come bozza.

### In cosa è diverso da un software CPQ?
Un CPQ configura e quota prodotti a partire da dati strutturati, all'interno del vostro sistema. Un agente RFQ lavora a monte: legge la richiesta ricevuta via e-mail, con i suoi formati misti e i codici dell'acquirente, e la trasforma nei dati strutturati che un motore di prezzi o un ERP possono usare. Molti team vorranno entrambi.

### Con quali ERP funziona?
La pagina di VoxDonna sull'acquisizione degli ordini è scritta per SAP, Oracle e Dynamics, ma i suoi casi di accettazione pubblicati girano su un backend pilota con input sintetici, non sull'ERP di produzione di un cliente. Un progetto RFQ viene definito in base alle interfacce di preventivazione e di consultazione prezzi del vostro ERP, e non pubblichiamo un elenco di connettori supportati per la quotazione.

### VoxDonna ha pubblicato risultati sulle RFQ?
No. Questo articolo è uno schema di progettazione costruito sulla nostra pipeline di acquisizione ordini pubblicata. Ogni risultato misurato verrà da un progetto definito, con base di partenza, periodo e metodo dichiarati.

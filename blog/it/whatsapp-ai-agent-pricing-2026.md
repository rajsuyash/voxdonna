---
title: "Prezzi Agente IA WhatsApp 2026: Meta vs. Agente"
description: "I messaggi di servizio hanno smesso di essere gratuiti dal 1° ottobre 2026. Ecco il tariffario attuale di Meta rispetto a ciò che fattura il vostro agente IA."
date: "2026-10-06"
category: "Prezzi"
readingTime: "8"
keywords: "prezzi agente ia whatsapp, costo whatsapp business api, tariffe meta whatsapp 2026, costo automazione whatsapp, prezzo chatbot vs agente ia whatsapp"
noBrandSuffix: "true"
---

# Prezzi Agente IA WhatsApp 2026: Meta vs. Agente

## Due Fatture, Due Fornitori, Una Fattura Confusa

Un responsabile operativo che valuta un agente IA per WhatsApp riceve di solito un numero dalla chiamata commerciale e uno diverso dalla documentazione ufficiale di Meta, e i due non si somma facilmente. Questo perché sono due fatture separate emesse da due parti separate. Meta fattura i messaggi che viaggiano su WhatsApp. Il fornitore dell'agente, o il Business Solution Provider (BSP) che rivende l'accesso a WhatsApp, fattura separatamente il software che decide cosa dicono quei messaggi.

Gran parte della confusione pubblica risale a un cambiamento preciso: il 1° luglio 2025 Meta ha eliminato il prezzo basato sulla conversazione — dove una sola tariffa copriva un intero scambio di 24 ore — passando alla fatturazione per messaggio, per categoria di modello ([documentazione ufficiale sui prezzi della piattaforma WhatsApp di Meta](https://developers.facebook.com/docs/whatsapp/pricing/)). Buona parte dei contenuti su "prezzi WhatsApp" ancora online descrive il vecchio modello — e, come vedremo, una parte descrive anche un modello già superato da cinque giorni. Questo articolo separa ciò che Meta fattura davvero oggi da ciò che si paga in più per l'agente stesso.

## Cosa Fattura Meta, Direttamente

Secondo la documentazione ufficiale di Meta, i messaggi modello di WhatsApp si dividono in quattro categorie:

| Categoria | A cosa serve | Quando Meta fattura |
|---|---|---|
| Marketing | Promozioni, offerte, re-engagement | Sempre — ogni messaggio modello marketing consegnato |
| Utility | Aggiornamenti ordine, avvisi di consegna, alert account | Ogni messaggio consegnato — la gratuità in finestra è finita il 1° ottobre 2026 |
| Autenticazione | Codici OTP, codici di accesso | Solo fuori da una finestra di servizio clienti aperta |
| Servizio | Risposte in testo libero a un cliente che ha scritto prima | Ogni messaggio consegnato — la gratuità è finita il 1° ottobre 2026 |

Questa colonna "quando Meta fattura" è cambiata sotto i nostri piedi cinque giorni prima della stesura di questo articolo. I messaggi di servizio erano gratuiti per tutte le aziende dal 1° novembre 2024. I modelli utility inviati in una finestra di servizio clienti aperta erano gratuiti dal 1° luglio 2025. Entrambe queste gratuità sono terminate il 1° ottobre 2026: la documentazione ufficiale di Meta afferma che da quella data "Meta fatturerà i messaggi di servizio su base per messaggio, in modo coerente con come Meta fattura i messaggi modello", e separatamente "i messaggi utility inviati in risposta agli utenti all'interno di una finestra di servizio clienti aperta di 24 ore" ([Meta, prezzi dei messaggi non-modello di WhatsApp](https://developers.facebook.com/documentation/business-messaging/whatsapp/pricing/non-template-messages)). Se una guida ai prezzi — incluse, ormai, la maggior parte di quelle ancora online — descrive le risposte in finestra di servizio come gratuite, è precedente al 1° ottobre 2026 e non è aggiornata. L'autenticazione in finestra resta l'unica categoria per cui Meta non ha annunciato una tariffa a oggi.

Le tariffe variano anche in base al paese del destinatario e, per i modelli utility e di autenticazione, in base alla fascia di volume. Meta ha nuovamente aggiornato alcune tariffe per mercato specifico il 1° luglio 2026, spostando diversi paesi — tra cui Regno Unito, Italia, Spagna e Singapore — da gruppi tariffari regionali condivisi a tariffe proprie per mercato (secondo la [documentazione sui prezzi della piattaforma WhatsApp di Meta](https://developers.facebook.com/docs/whatsapp/pricing/)). Non esiste un numero globale unico; i "prezzi WhatsApp" sono in realtà un tariffario, rivisto due volte in tre mesi.

Per dare un'idea concreta prima del cambiamento del 1° ottobre, l'analisi prezzi 2026 di Blueticks — un dato di terze parti, non di Meta — indica tariffe USA di circa 0,025 $ per messaggio modello marketing, e 0,004 $ per modello utility o autenticazione inviato fuori dalla finestra di servizio ([Blueticks, "WhatsApp Business Per-Message Pricing in 2026"](https://blueticks.co/blog/whatsapp-business-pricing-change-2026-per-message)). La stessa fonte ha calcolato un mese da 35.000 messaggi per un'azienda e-commerce statunitense — 10.000 invii marketing, 12.000 invii utility a freddo, 8.000 invii utility in finestra (gratuiti secondo le vecchie regole) e 5.000 invii di autenticazione — arrivando a una fattura Meta di 318 $. Ripetendo lo stesso mese secondo le regole del 1° ottobre, gli 8.000 invii utility in finestra e qualsiasi risposta di servizio inviata non sono più gratuiti; i 318 $ diventano un pavimento, non un totale. Cominciate a monitorare il vostro volume di messaggi di servizio da subito.

## L'Altra Nuova Voce: Meta Business Agent

Un cambiamento distinto, facile da confondere con quello sopra: Meta vende ora un proprio agente IA integrato in WhatsApp, chiamato Meta Business Agent, con una propria unità tariffaria — i token, non i messaggi. A partire dal 1° agosto 2026, Meta fattura 2,00 $ per milione di token per i messaggi generati da Meta Business Agent, pari a circa 4-5 centesimi per messaggio per un'interazione tipica, secondo la documentazione di Meta ([Meta, prezzi dei messaggi non-modello di WhatsApp](https://developers.facebook.com/documentation/business-messaging/whatsapp/pricing/non-template-messages)). Meta Business Agent è anche l'unica categoria fatturata anche all'interno della finestra gratuita di 72 ore che le pubblicità click-to-WhatsApp normalmente aprono — la consegna lì resta gratuita, ma non il costo in token dell'IA di Meta.

Questo conta per inquadrare una conversazione con un fornitore, perché è un prodotto diverso da un dipendente IA di terze parti costruito da un fornitore come VoxDonna sopra l'API Business WhatsApp standard. I messaggi di un agente IA su misura sono fatturati secondo la tabella delle categorie sopra — marketing, utility, autenticazione, servizio — non per token. Se la spiegazione tariffaria di un fornitore mescola un linguaggio "per token" in un preventivo per un agente su misura, chiarite quale prodotto viene effettivamente fatturato.

## Cosa Si Paga all'Agente, Separatamente

Il tariffario di Meta è solo una riga della fattura. La seconda è ciò che il vostro fornitore di agenti IA o il vostro BSP fattura per:

- **Costi di piattaforma o per postazione** — un abbonamento mensile per il software dell'agente stesso, indipendente dal volume di messaggi.
- **Costi basati sull'utilizzo** — alcuni fornitori fatturano per conversazione gestita, per risoluzione, o per messaggio elaborato dall'IA, in aggiunta al costo per messaggio di Meta.
- **Margine del BSP** — la commissione tecnica che un Business Solution Provider aggiunge alla tariffa di Meta per l'accesso API e la consegna. Questo varia per fornitore; YCloud, ad esempio, pubblicizza l'assenza di margine aggiunto come elemento competitivo, cosa che ha senso come argomento di vendita solo se applicare un margine è la norma tra gli altri BSP ([YCloud, "WhatsApp API Pricing Update"](https://www.ycloud.com/blog/whatsapp-api-pricing-update)).

Questa è la fattura che varia più per fornitore, ed è quella su cui vale la pena negoziare — il tariffario di Meta è fisso indipendentemente da chi media l'acquisto.

## Perché le Due Fatture Si Confondono nelle Conversazioni Commerciali

Un fornitore che nel 2026 propone un prezzo "per conversazione" sta usando terminologia superata, oppure incorpora il costo per messaggio di Meta in una tariffa mista, oppure descrive il proprio costo a utilizzo con il vecchio vocabolario. La domanda utile per qualsiasi preventivo di agente IA WhatsApp è semplice: questo numero include il costo per messaggio di Meta, o è la commissione del fornitore sopra a una fattura Meta che vedrete anche direttamente sul vostro account WhatsApp Business? Se un fornitore non riesce a rispondere con chiarezza, chiedete la fattura WhatsApp del mese scorso di un cliente comparabile.

## Cosa Determina Davvero il Totale

Tre variabili contano più di qualsiasi tariffa in vetrina:

1. **Il volume totale di messaggi, punto.** Dal 1° ottobre 2026 non c'è più una fascia gratuita in cui nascondersi — le risposte di servizio e i messaggi utility in finestra sono fatturati come tutto il resto. Un deployment orientato al supporto non sfugge più al costo semplicemente aspettando che il cliente scriva prima.
2. **Il mix di categoria.** Il marketing resta la tariffa fissa più alta senza sconto di volume; utility e autenticazione restano più economici per messaggio ad alto volume; i messaggi di servizio sono fatturati "in modo coerente con i messaggi modello" secondo la documentazione di Meta, senza uno sconto di volume proprio annunciato.
3. **Il mix di paesi.** Le tariffe differiscono per mercato del destinatario, e Meta ha dimostrato che continuerà ad aggiustare tariffari per paese — già due volte nel 2026.

Nessuno di questi fattori è deciso dal listino prezzi di un fornitore — sono proprietà di come l'agente è progettato per usare il canale e il traffico per cui è stato costruito.

## La Fascia di Volume Che la Maggior Parte degli Acquirenti Trascura

La documentazione ufficiale di Meta afferma che le tariffe dipendono da "categoria del modello, fascia di volume e tariffa per paese/regione" — tre variabili, non una. La fascia di volume si applica ai modelli utility e di autenticazione: inviarne di più in un determinato mercato fa scendere la tariffa per messaggio. Non si applica ai modelli marketing, che restano a tariffa fissa indipendentemente dal volume.

Cosa significa in pratica: un fornitore che propone un uso intensivo di broadcast marketing per "spingere" i clienti propone proprio la categoria senza sconto di volume e con la tariffa fissa più alta in quasi ogni mercato. Un agente costruito attorno ad aggiornamenti di categoria utility ad alto volume conserva uno sconto che il marketing non avrà mai — questo vantaggio sopravvive intatto al cambiamento di ottobre 2026, anche se il vantaggio "la finestra di servizio è gratuita" non sopravvive.

## Una Checklist Prima di Firmare

Prima di accettare un preventivo, chiedete al fornitore di esaminare questi punti rispetto al vostro traffico effettivo:

- **Quali categorie invierà davvero l'agente**, e in che proporzione — marketing, utility, autenticazione, servizio?
- **Il prezzo quotato include il costo per messaggio di Meta**, o si aggiunge a una fattura Meta separata?
- **Qual è il margine del BSP**, espresso come numero, non come elenco di funzionalità.
- **Esiste un costo di piattaforma o per postazione** indipendente dal volume di messaggi?
- **Il preventivo del fornitore è aggiornato al 1° ottobre 2026** — assume ancora che le risposte di servizio e i messaggi utility in finestra siano gratuiti? Se sì, sta quotando un tariffario che non esiste più.
- **L'agente usa Meta Business Agent, o è una costruzione su misura sull'API standard?** I due sono fatturati in modo completamente diverso — per token contro per messaggio.

Un fornitore che risponde con precisione a questi punti, usando i vostri numeri, vi sta quotando un prezzo reale. Per cosa fa davvero un dipendente IA WhatsApp con quel traffico una volta chiarito il modello tariffario, vedi [gli agenti IA WhatsApp di VoxDonna](/whatsapp-donna-agents.html).

## FAQ

### WhatsApp è ancora fatturato "per conversazione"?
No. Meta è passata alla fatturazione per messaggio il 1° luglio 2025. Il modello basato sulla conversazione non esiste più.

### Le risposte generate dall'IA sono fatturate diversamente dai messaggi modello?
Meta fattura in base al tipo e alla categoria del messaggio, non in base a chi ha scritto il contenuto — con un'eccezione. Il Meta Business Agent di Meta stesso è fatturato per token, separatamente dalla tabella delle categorie. Le risposte in testo libero di un agente IA su misura sono, dal 1° ottobre 2026, fatturate come qualsiasi messaggio di servizio: non più gratuite.

### VoxDonna pubblica un prezzo fisso per l'agente WhatsApp?
No — il tariffario di Meta cambia per paese e categoria, e cambia esso stesso più volte l'anno. [Parlateci del vostro traffico WhatsApp](/index.html#contact) e definiremo le due fatture in base al vostro volume reale.

### Perché alcuni siti di fornitori descrivono ancora prezzi per conversazione, o risposte di servizio gratuite?
Molto probabilmente perché il contenuto è precedente a luglio 2025, o al 1° ottobre 2026, e non è mai stato aggiornato. Verificate qualsiasi cifra con la [documentazione ufficiale sui prezzi WhatsApp di Meta](https://developers.facebook.com/docs/whatsapp/pricing/), che è la fonte autorevole.

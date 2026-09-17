This manual defines a neutral, contemporary metropolitan French for customer-facing voice agents in France, plus concrete language and pronunciation rules you can paste into system prompts and TTS configs.

---

## **1\. Natural Spoken French vs Written French**

Spoken French in France differs sharply from the written norm: negatives drop *ne*, schwas disappear, questions avoid inversion, and discourse markers like *du coup* and *bon* carry much of the conversational flow. Spoken French also favors short clauses, intonation questions, and frequent reformulation, while written French keeps full forms (*je ne sais pas*, *cela dépend*) and more complex syntax.\[[pureadmin.qub.ac](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/454173967/12._AM_and_refs_Spoken_French.pdf)\]\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]

### **Key contrasts**

* Written vs spoken syntax  
  * Written: *Je ne sais pas si cela est possible.*  
  * Everyday speech: *Je sais pas si c’est possible.*  
* Question forms  
  * Written/formal: *Souhaitez‑vous modifier votre rendez‑vous ?* (inversion).  
  * Spoken neutral: *Est‑ce que vous voulez modifier votre rendez‑vous ?* or *Vous voulez modifier votre rendez‑vous ?* with rising intonation.\[[commeunefrancaise](https://www.commeunefrancaise.com/blog/how-to-ask-questions-in-french)\]\[[elon](https://elon.io/grammar/french/questions/overview)\]\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]

### **Formal vs everyday spoken**

* Formal spoken (interviews, official announcements) keeps *ne*, uses inversion or *est‑ce que*, and avoids fillers.\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]  
* Everyday conversational French heavily drops *ne*, uses intonation questions or *est‑ce que*, and frequent markers like *bon, alors, du coup, en fait, voilà*.\[[elon](https://elon.io/grammar/french/discourse/overview)\]\[[hrcak.srce](https://hrcak.srce.hr/en/clanak/467631)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]

### **Common spoken structures**

* Dislocation: *Votre commande, je la vois là…* instead of strictly canonical order.\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]  
* Short coordination: *D’accord, je vérifie, et je vous redis.*  
* Reformulation: *Alors… enfin, ce que je veux dire, c’est que…*.\[[elon](https://elon.io/grammar/french/pragmatics/conversational-fillers)\]\[[elon](https://elon.io/grammar/french/discourse/conversational-markers)\]

For a professional voice agent, you want professional conversational French: drop some written stiffness, but keep politeness and clarity.

---

## **2\. Defining the Target Register**

The default register should be “professional conversational French”: polite, neutral, contemporary metropolitan French, as used by competent customer-service staff in mainstream French companies.\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\]\[[meridianfrench](https://www.meridianfrench.com/culture/greetings/)\]

* Spectrum:

| Register type | Description | Use for agent |
| ----- | ----- | ----- |
| Formal written | Government, legal, corporate letters | Avoid as default |
| Formal spoken | TV interviews, speeches | Use only in high-stakes contexts |
| Professional conversational | Standard customer service, retail, tech support | **Default** |
| Everyday casual | Friends, colleagues, informal brands | Only if brand-configured |
| Slang / youth speech | Teen talk, heavy anglicisms, *wesh, genre* overload | Avoid by default |

The agent should sound like a polite adult employee at a mainstream French company—not a civil servant reading a decree, not a teenager, not an English speaker translating scripts.

---

## **3\. Commonly Used Expressions for Customer Conversations**

Below is a core phrasebook of expressions actually used by native speakers in professional conversational French, with formality and agent suitability.

### **3.1 Greetings & opening**

| French expression | English meaning | When used | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Bonjour | Hello / good day | Any daytime first contact | Neutral–polite | Always |
| Bonsoir | Good evening | Evening calls | Neutral–polite | Yes (after \~18–19h) |
| Bonjour, \[nom de la société\], bonjour. | Hello, \[company\], hello. | Professional phone greeting | Professional | Yes for inbound lines\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\] |
| Bonjour, comment puis‑je vous aider ? | Hello, how can I help you? | Opening customer-service call | Professional | Yes |
| Bonjour, qu’est‑ce que je peux faire pour vous ? | What can I do for you? | Slightly more relaxed opening | Prof. conversational | Yes |

Example (agent opening):

> Bonjour, service client Le Marquier, comment puis‑je vous aider ?

---

### **3.2 Asking how someone is (brief social)**

In French customer-service, a long “how are you?” exchange is less common than in English; short polite variants are fine but shouldn’t be overused.\[[meridianfrench](https://www.meridianfrench.com/culture/greetings/)\]

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Bonjour, ça va ? | Hi, how are things? | Small independent shops, informal brands | Casual–prof. | Only if brand is informal |
| Bonjour, vous allez bien ? | Hello, are you well? | Warm but polite | Prof. conversational | Yes, sparingly |
| Bonjour, j’espère que vous allez bien. | Hello, I hope you’re well. | Email / slightly formal | Formal written | Rare in speech |

---

### **3.3 How can I help / purpose of call**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Comment puis‑je vous aider ? | How can I help you? | Standard opening | Professional | Yes |
| En quoi puis‑je vous aider aujourd’hui ? | How can I help you today? | Slightly more formal | Professional | Yes |
| Qu’est‑ce que je peux faire pour vous ? | What can I do for you? | More conversational | Prof. conversational | Yes |
| Je vous écoute. | I’m listening. | Inviting customer to explain | Neutral–polite | Yes |

Example:

> Bonjour, je vous écoute.

---

### **3.4 Acknowledgements & backchannels**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| D’accord. | Okay. | Minimal acknowledgement | Neutral | Yes, but not after every turn |
| Très bien. | Very well. | Confirming, moving on | Neutral–polite | Yes, sparingly |
| Parfait. | Perfect. | Strong positive acknowledgement | Prof. conversational | Yes, but avoid every turn |
| Je vois. | I see. | Shows understanding | Neutral | Yes |
| Je comprends. | I understand. | Empathy / comprehension | Prof. conversational | Yes |

---

### **3.5 Yes / no / maybe / okay**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Oui | Yes | Default affirmation | All | Yes |
| Oui, tout à fait. | Yes, absolutely. | Strong agreement | Prof. conversational | Yes |
| Non | No | Default negation | All | Yes |
| Peut‑être. | Maybe. | Uncertainty | Neutral | Yes |
| D’accord. | Okay / agreed. | Agreement, confirmation | Neutral | Yes |
| OK / Ok. | OK. | Widespread in speech | Prof. conversational | Yes, not too often |
| Ça marche. | That works / OK. | Confirming plan | Prof. conversational | Yes |

---

### **3.6 Please / thank you / sorry / excuse me**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| S’il vous plaît. | Please. | Requests with *vous* | Polite | Always appropriate |
| Merci. | Thank you. | Generic thanks | All | Yes |
| Merci beaucoup. | Thank you very much. | Stronger gratitude | Polite | Yes |
| Désolé. / Je suis désolé(e). | I’m sorry. | Apology | Prof. conversational | Yes, when warranted |
| Pardon. | Sorry / excuse me. | Small repair, mishearing | Neutral | Yes |
| Excusez‑moi. | Excuse me. | Interrupting, entering turn | Polite | Yes |

Example:

> Désolé pour ce contretemps, je regarde ce qu’on peut faire.

---

### **3.7 Waiting / checking**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Un instant, je regarde. | One moment, I’ll check. | Short hold / lookup | Prof. conversational | Yes |
| Je vérifie ça pour vous. | I’ll check that for you. | Informing before search | Professional | Yes |
| Attendez, je regarde. | Hold on, I’m checking. | Slightly more casual | Prof. conversational | Yes |
| Je reviens vers vous tout de suite. | I’ll be right back to you. | Short delay | Professional | Yes |

---

### **3.8 Understanding / not understanding / repetition**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Je comprends. | I understand. | Checking comprehension | Prof. conversational | Yes |
| Je vois. | I see. | Slightly lighter | Neutral | Yes |
| Je n’ai pas bien entendu. | I didn’t hear that clearly. | Audio problems | Prof. conversational | Yes |
| Je n’ai pas bien compris. | I didn’t quite understand. | Content confusion | Prof. conversational | Yes |
| Pardon, vous pouvez répéter ? | Sorry, could you repeat? | Brief repair | Neutral | Yes |
| Vous pouvez me redire le numéro, s’il vous plaît ? | Could you say the number again, please? | Specific repetition | Professional | Yes |

---

### **3.9 Clarification / correcting / transitioning**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Juste pour être sûr, vous parlez de… ? | Just to be sure, you mean…? | Clarification | Prof. conversational | Yes |
| Si je comprends bien, vous… | If I understand correctly, you… | Clarification \+ paraphrase | Professional | Yes |
| En fait, ce que je vois, c’est que… | Actually, what I see is that… | Reformulation after check | Prof. conversational | Yes |
| Dans ce cas, je vais… | In that case, I will… | Transition to solution | Professional | Yes |
| Maintenant, je vais vous demander votre numéro de téléphone. | Now I’m going to ask for your phone number. | Transition to next info | Professional | Yes |

---

### **3.10 Ending & goodbye**

| Expression | Meaning | Use | Register | Agent use? |
| ----- | ----- | ----- | ----- | ----- |
| Est‑ce que vous avez besoin d’autre chose ? | Do you need anything else? | Before closing | Professional | Yes |
| C’est tout bon pour moi. | That’s all good on my side. | Confirming completion | Prof. conversational | Yes |
| Merci beaucoup pour votre appel. | Thank you very much for your call. | Closing | Professional | Yes |
| Je vous souhaite une bonne journée. | I wish you a good day. | Warm closing | Neutral–polite | Yes |
| Au revoir. | Goodbye. | Final farewell | All | Always |

Example closing:

> C’est tout bon pour moi. Merci beaucoup pour votre appel, je vous souhaite une bonne journée, au revoir.

---

## **4\. Natural Fillers and Discourse Markers**

Discourse markers (*bon, alors, du coup, en fait, voilà, donc, ben/bah*) structure French conversation but are easily overdone by AI and second-language speakers. Corpus work on contemporary spoken French shows high frequency for *du coup, genre, ben, mais, enfin, en fait, bon, voilà, après, quoi, donc* in spontaneous speech.\[[hrcak.srce](https://hrcak.srce.hr/en/clanak/467631)\]\[[elon](https://elon.io/grammar/french/discourse/overview)\]\[[elon](https://elon.io/grammar/french/pragmatics/conversational-fillers)\]

### **Core markers**

| Marker | Literal meaning | Function | Typical context | Register | Agent use? | Frequency guidance |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| Euh | Uh | Hesitation, floor-holding | Thinking mid-sentence | All, but informal | **Very sparing** (≤1–2 per long call) |  |
| Ben / Bah | Well | Mild adjustment, softening, casual opening | Explaining, soft disagreement | Casual | Use only in informal brands |  |
| Bon | Well / right | Opening, closing, topic shift | *Bon, alors…* | Everyday | Low frequency (transition only) |  |
| Bon, alors… | Well, so… | Starting a new step | Summarizing, moving on | Everyday | Yes, 1–3 times per call |  |
| Alors | So / then | Topic shift, conclusion | *Alors, je vais…* | Neutral | Yes |  |
| Donc | So / therefore | Logical consequence | Explanation | Neutral–professional | Yes, but avoid every sentence |  |
| Du coup | As a result | Consequence marker | *Du coup, je vais…* | Everyday | Yes in moderation; avoid stereotype\[[semanticscholar](https://www.semanticscholar.org/paper/%22Du-coup%22-et-les-connecteurs-de-cons%C3%A9quence-dans-Rossari-Jayez/a08ea434ee73d577bfcab1691002fc32bf06ba1d)\]\[[hrcak.srce](https://hrcak.srce.hr/en/clanak/467631)\] |  |
| En fait | Actually | Correction, nuance | Clarifying | Neutral–everyday | Yes, sparingly |  |
| Voilà | There, that’s it | Closure, presenting result | Summing up, showing outcome | Neutral | Yes, 1–2× where natural |  |
| D’accord | OK | Agreement / uptake marker | After info | Neutral | Yes but not after each turn |  |
| Très bien | Very good | Uptake, transition | Confirming before next question | Neutral | Yes, varied with others |  |
| Ça marche | That works | Confirming plan | After agreement | Prof. conversational | Yes |  |
| Exactement | Exactly | Strong agreement | Confirming correctness | Neutral | Yes |  |
| Tout à fait | Absolutely | Strong agreement | Support / affirmation | Neutral | Yes |  |
| Ah oui | Oh yes | Surprise / recognition | When learning new info | Neutral–casual | Yes, sparingly |  |
| Ah d’accord | Ah okay | Realizing, accepting | After explanation | Neutral | Yes |  |
| Je vois | I see | Cognitive acknowledgment | After explanation | Neutral | Yes |  |
| Effectivement | Indeed | Confirming, aligning | After confirming problem | Neutral–professional | Yes |  |
| Eh bien | Well then | Formal / narrative | Storytelling | Slightly formal | Rare in customer-service |  |
| Enfin | Well / anyway | Softening, reformulating | *Enfin, ce que je veux dire…* | Everyday | Yes, sparingly |  |
| Bref | Anyway | Closing digression | Returning to main point | Casual | Rare, informal brands only |  |
| Genre | Like | Youth filler | Youth speech | Slang | Avoid by default |  |
| Quoi (sentence-final) | You know / etc. | Pragmatic tag, attitude | Casual, often emotional | Casual | Avoid for neutral agent |  |

**Practical rules:**

* Allow a few markers per turn mix across an entire call (*alors, donc, du coup, voilà, en fait, bon*), but avoid repeating the same marker every turn.\[[elon](https://elon.io/grammar/french/discourse/overview)\]\[[hrcak.srce](https://hrcak.srce.hr/en/clanak/467631)\]  
* For a professional agent, prefer: *alors, donc, en fait, voilà, d’accord, très bien, tout à fait, je vois, effectivement, ça marche*; avoid *genre, quoi* and heavy *ben/bah* by default.

---

## **5\. Spoken French Reductions and Contractions**

Spoken French routinely contracts pronouns and drops *ne* and schwas; these are phonetic phenomena more than orthographic conventions. For an LLM, you should generally generate standard spellings; the TTS and prosody model should realize natural reductions acoustically.\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]

Corpus studies show near-universal *ne*\-drop in informal speech and high rates even in neutral registers; contractions like *t’as, t’es, y a* are core to spoken French.\[[chaseinfrench](https://chaseinfrench.com/lecons/ddb1fd84-dce4-48fa-a55e-03a607212938)\]\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]

### **Reduction classification (LLM text vs speech realization)**

In the table below, “Written for LLM” is what you should output as text; “Typical spoken realization” describes how a native speaker will pronounce it. Register labels are for what the voiced agent should *sound* like, not for spelling.

| Formal / written | Natural spoken form (text) | Typical spoken reduction | Register | Agent recommendation |
| ----- | ----- | ----- | ----- | ----- |
| Je ne sais pas. | Je sais pas. | \[ʒə sɛ pa\] → \[ʃɛ pa\]/\[ʃe pa\] | Prof. conversational | LLM: *Je sais pas* or *Je ne sais pas* depending on negation policy; TTS: allow /ne/ reduction.\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[chaseinfrench](https://chaseinfrench.com/lecons/ddb1fd84-dce4-48fa-a55e-03a607212938)\] |
| Cela dépend. | Ça dépend. | \[səla depɑ̃\] → \[sa depɑ̃\] | Prof. conversational | Use *Ça dépend.* |
| Est‑ce que vous souhaitez… ? | Est‑ce que vous voulez… ? | \[ɛs kə vu swatɛ\] → \[ɛs kə vu vule\] | Professional | Prefer *Est‑ce que vous voulez… ?* |
| Il y a un problème. | Il y a un problème. | \[il ja ɛ̃ pʁɔblɛm\] → \[j‿a ɛ̃ pʁɔblɛm\] (“y a”) | Prof. conversational | LLM: *Il y a*; TTS: allow liaison/enchaînement.\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\] |
| Nous allons vérifier. | On va vérifier. | \[nu zalɔ̃\] → \[ɔ̃ va\] | Prof. conversational | Prefer *On va vérifier.* |
| Tu as reçu le mail ? | Tu as reçu le mail ? | \[ty a ʁəsy\] → \[ta ʁəsy\] (“t’as”) | Everyday | LLM: *Tu as*; TTS: may realize \[ta\] but agent default is *vous*. |
| Tu es d’accord ? | Tu es d’accord ? | \[ty e dakɔʁ\] → \[t‿e dakɔʁ\] (“t’es”) | Everyday | Same as above. |
| Je suis en train de vérifier. | Je suis en train de vérifier. | \[ʒə sɥi‿ɑ̃ tʁɑ̃ də veʁifie\] with schwa reductions | Prof. conversational | Keep full written form; rely on prosody. |
| Ça ne marche pas. | Ça marche pas. | \[sa nə maʁʃ pa\] → \[sa maʁʃ pa\] | Everyday–prof. conversational | For neutral professional, both forms acceptable; see negation rules. |
| Je ne peux pas. | Je peux pas. | \[ʒə nə pø pa\] → \[ʒə pø pa\]/\[ʒ pø pa\] | Prof. conversational | Prefer *Je peux pas.* in spoken style; or mix with *Je ne peux pas* for more formal brands. |
| Ce n’est pas possible. | C’est pas possible. | \[sə nɛ pa pɔsibl\] → \[sɛ pa pɔsibl\] | Prof. conversational | Use *C’est pas possible.* or *Ce n’est pas possible.* depending on brand’s desired formality. |
| Je te le passe. | Je te le passe. | \[ʒə tə lə pas\] → \[ʒt lə pas\] | Everyday | LLM: full form; TTS: natural reduction. |
| Je vais regarder. | Je vais regarder. | \[ʒə vɛ ʁəgaʁde\] → \[ʒve ʁəgaʁde\] | Professional | Keep written; TTS handles segmental coarticulation. |
| Je vais voir ça. | Je vais voir ça. | \[ʒə vɛ vwaʁ sa\] → \[ʒve vwaʁ sa\] | Prof. conversational | Use as-is. |
| Je ne sais pas encore. | Je sais pas encore. | \[ʒə nə sɛ pa\] → \[ʒɛ pa\] | Prof. conversational | Accept *Je sais pas encore.* in spoken style. |
| Je ne vois pas votre commande. | Je vois pas votre commande. | \[ʒə nə vwa pa\] → \[ʒə vwa pa\]/\[ʒvwa pa\] | Prof. conversational | Both forms acceptable; see negation section. |
| Je te remercie. | Je te remercie. | \[ʒə tə ʁəmeʁsi\] → \[ʒt ʁəmeʁsi\] | Everyday | Keep written. |
| Je ne suis pas certain. | Je suis pas sûr. | \[ʒə nə sɥi pa sɛʁtɛ̃\] → \[ʒ sɥi pa syʁ\] | Everyday–casual | For professional agent, use *Je ne suis pas sûr* or *Je ne suis pas certain.* rather than reduced everyday form. |
| Je n’ai que ça. | J’ai que ça. | \[ʒə nɛ kə sa\] → \[ʒɛ kə sa\] | Everyday | Prefer full form in professional contexts. |

**Principle:**

* Don’t spell reductions (*j’sais pas, chépa, y a*) in LLM output unless you explicitly want very casual speech or you know the TTS needs them; let the speech layer handle schwa and consonant reduction.\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]

---

## **6\. Negative Sentences in Real French**

French negation structurally uses *ne…pas* and related pairs (*ne…jamais, ne…plus, ne…rien*), but *ne* is dropped in most spoken contexts; the negative meaning is carried by *pas* or the second particle. Corpus studies show *ne*\-drop rates of 70–95% in Parisian speech, with near-total drop in casual contexts and somewhat more retention in formal or careful speech.\[[croissantverbs](https://www.croissantverbs.com/learn/articles/french-negation-guide)\]\[[archive.swarthmore](https://archive.swarthmore.edu/files/assets/documents/linguistics/2003_christensen_susan.pdf?__raw=1)\]\[[scholarworks.wm](https://scholarworks.wm.edu/cgi/viewcontent.cgi?article=3403&context=honorstheses)\]\[[elon](https://elon.io/grammar/french/verbs/passe-compose/colloquial-shortening)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]

### **Patterns**

| Full form | Spoken everyday | Politeness impression |
| ----- | ----- | ----- |
| Je ne sais pas. | Je sais pas. | Neutral–polite spoken French; doesn’t sound rude. |
| Je ne peux pas. | Je peux pas. | Neutral–polite. |
| Ce n’est pas possible. | C’est pas possible. | Neutral, slightly more direct. |
| Nous n’avons pas ce modèle. | On n’a pas ce modèle. / On a pas ce modèle. | *On n’a pas* is mildly more careful; *On a pas* is standard everyday. |

**Agent guidelines:**

* For a neutral professional voice:  
  * Allow *ne*\-drop in many sentences (*Je peux pas*, *C’est pas possible*, *On n’a pas ce modèle, désolé.*) to avoid sounding “written”.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]\[[elon](https://elon.io/grammar/french/register/spoken-vs-written)\]  
  * Retain *ne* selectively in more formal or sensitive sentences: *Je ne peux malheureusement pas modifier cette commande.*  
  * Avoid hyper-formality such as retaining *ne* in every sentence; that sounds institutional or scripted.

---

## **7\. Natural Question Formation**

French has three core question types: inversion (most formal), *est‑ce que* (neutral, all-purpose), and intonation questions (statement word order with rising pitch, common in everyday speech). Neutral or polite speech with strangers and customer-service commonly uses *est‑ce que* or intonation, while inversion is frequent in writing and formal spoken contexts.\[[elon](https://elon.io/grammar/french/questions/overview)\]\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]\[[commeunefrancaise](https://www.commeunefrancaise.com/blog/how-to-ask-questions-in-french)\]

### **Suitability for a voice agent**

* **Primary pattern:** *Est‑ce que* \+ clause → professional, natural, not stiff.  
  * *Est‑ce que vous pouvez me donner votre numéro de téléphone ?*\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]\[[elon](https://elon.io/grammar/french/questions/overview)\]  
* **Secondary pattern:** Intonation questions with *vous* for brevity.  
  * *Vous pouvez me donner votre numéro de téléphone, s’il vous plaît ?*  
* **Limited inversion:** Use occasionally in clear, short questions where it sounds natural: *Avez‑vous déjà un compte chez nous ?*; avoid heavy repeated inversion.\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]

### **Sample transformations (textbook → natural spoken)**

| Textbook / formal | Natural professional spoken | Situation |
| ----- | ----- | ----- |
| Souhaitez‑vous modifier votre rendez‑vous ? | Est‑ce que vous voulez modifier votre rendez‑vous ? / Vous voulez modifier votre rendez‑vous ? | Appointment change |
| Quel est votre nom ? | Vous pouvez me donner votre nom, s’il vous plaît ? | Asking name |
| Quel est votre numéro de téléphone ? | Est‑ce que vous pouvez me donner votre numéro de téléphone, s’il vous plaît ? | Phone number |
| Pourriez‑vous me communiquer votre adresse postale ? | Vous pouvez me donner votre adresse, s’il vous plaît ? | Postal address |
| Pourriez‑vous me préciser la date de votre commande ? | Vous pouvez me rappeler la date de votre commande ? | Date |
| Avez‑vous reçu notre email de confirmation ? | Vous avez reçu l’email de confirmation ? | Confirmation |
| Est‑ce que je peux me permettre de vous demander votre numéro de client ? | Je vais vous demander votre numéro de client. Vous l’avez sous la main ? | Order/customer ID |
| Pourriez‑vous nous indiquer la référence de votre produit ? | Vous pouvez me donner la référence de votre produit ? | Product reference |
| Souhaiteriez‑vous annuler votre abonnement ? | Vous voulez annuler votre abonnement ? | Cancellation |
| Voudriez‑vous reporter votre rendez‑vous à une autre date ? | Vous voulez déplacer votre rendez‑vous à un autre jour ? | Rescheduling |

For the agent, prefer *Est‑ce que…* or intonation questions; treat inversion as exceptional rather than default.\[[elon](https://elon.io/grammar/french/questions/overview)\]\[[mangolanguages](https://www.mangolanguages.com/resources/learn/grammar/french/how-to-ask-questions-in-french)\]

---

## **8\. Tu vs Vous**

The *tu/vous* choice is one of the most socially loaded distinctions in French; *vous* is the default for adult strangers and all standard customer-service contexts. In almost any commercial transaction—shops, restaurants, hotels, taxis, services—both sides use *vous*.\[[elon](https://elon.io/grammar/french/pronouns/subject/tu-vs-vous)\]\[[elon](https://elon.io/grammar/french/pragmatics/tu-vs-vous-strategies)\]\[[ohouifrench](https://ohouifrench.com/blog/tu-vs-vous-in-french)\]\[[learnfrench](https://learnfrench.co/lessons/tu-vs-vous/)\]\[[meridianfrench](https://www.meridianfrench.com/culture/greetings/)\]

### **General rules**

* Use **vous** for:  
  * Unknown adults, customers, elders, professionals, B2B contexts.\[[elon](https://elon.io/grammar/french/pragmatics/tu-vs-vous-strategies)\]\[[ohouifrench](https://ohouifrench.com/blog/tu-vs-vous-in-french)\]\[[elon](https://elon.io/grammar/french/pronouns/subject/tu-vs-vous)\]  
  * Any group of two or more people (plural).\[[elon](https://elon.io/grammar/french/pronouns/subject/tu-vs-vous)\]\[[elon](https://elon.io/grammar/french/pragmatics/tu-vs-vous-strategies)\]  
* Use **tu** only:  
  * With children, close friends/family, very informal brands that explicitly position themselves that way.\[[learnfrench](https://learnfrench.co/lessons/tu-vs-vous/)\]\[[elon](https://elon.io/grammar/french/pragmatics/tu-vs-vous-strategies)\]

In a general-purpose customer-service voice agent, **Mode A: vouvoiement** must be the default.

### **Mode A: Vouvoiement (default)**

* All second-person forms use *vous*: *vous avez, vous êtes, vous voulez, vous pouvez, votre, vos*.  
* No switching to *tu* mid-conversation.  
* Examples:  
  * *Vous pouvez me donner votre numéro de téléphone, s’il vous plaît ?*  
  * *Je comprends que ce soit embêtant pour vous.*

### **Mode B: Tutoiement (optional, brand-dependent)**

For informal brands that explicitly use *tu* with customers (certain startups, youth labels, etc.):

* All second-person forms use *tu*: *tu as, tu es, tu veux, tu peux, ton, tes*.  
* Examples:  
  * *Tu peux me donner ton numéro de téléphone, s’il te plaît ?*  
  * *Je comprends que ce soit embêtant pour toi.*

**Consistency rule:**  
Switching between *tu* and *vous* without a clear social reason feels extremely unnatural or rude; the agent must be consistent within a conversation.\[[elon](https://elon.io/grammar/french/pragmatics/tu-vs-vous-strategies)\]\[[elon](https://elon.io/grammar/french/pronouns/subject/tu-vs-vous)\]

---

## **9\. Politeness Without Sounding Stiff**

French customer-service politeness relies on *vous*, *s’il vous plaît*, *merci*, clear explanations, and reasonable mitigation—not on archaic formulas like *je vous saurais gré*. Highly institutional phrases (*veuillez patienter, je vous prie de…*) sound written or bureaucratic in a live voice conversation unless the context is very formal (banks, public administration).\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\]\[[meridianfrench](https://www.meridianfrench.com/culture/greetings/)\]

### **Too direct vs overly formal vs natural**

| Too direct | Overly formal / robotic | Natural professional spoken |
| ----- | ----- | ----- |
| Donnez‑moi votre numéro. | Veuillez me communiquer votre numéro de téléphone. | Vous pouvez me donner votre numéro de téléphone, s’il vous plaît ? |
| Attendez. | Je vous saurais gré de bien vouloir patienter. | Un instant, je regarde. |
| On ne peut pas. | Nous vous informons qu’il nous est impossible de répondre favorablement à votre demande. | Je ne peux malheureusement pas le faire, mais je vais voir ce qu’on peut vous proposer à la place. |
| Il faut payer tout de suite. | Nous vous prions de bien vouloir effectuer le règlement immédiatement. | Il faudra régler maintenant, si ça vous va. |

For a voice agent, prefer simple spoken forms like *Vous pouvez…, Un instant, je regarde, Je vais vérifier ça pour vous* to avoid call-centre boilerplate.\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\]

---

## **10\. Good French vs Bad French for Voice Agents**

Below are representative “bad vs natural” examples. “Bad” here is grammatically correct but socially or pragmatically wrong for spoken customer-service French.

### **Sample table**

| Situation | Bad / robotic French | Why it sounds wrong | Natural native French | English meaning |
| ----- | ----- | ----- | ----- | ----- |
| Greeting | Bonjour, je suis votre agent virtuel automatisé. | Over-explicit, tech-centric, unnatural self-identification. | Bonjour, service client \[marque\], je vous écoute. | Hello, \[brand\] customer service, I’m listening. |
| How can I help | En quoi puis‑je vous être utile aujourd’hui ? | Overly formal, slightly pompous. | Comment puis‑je vous aider ? | How can I help you? |
| Asking name | Quel est votre patronyme ? | Lexically weird; “patronyme” is too legal. | Vous pouvez me donner votre nom, s’il vous plaît ? | Could you give me your name, please? |
| Phone number | Pourriez‑vous me communiquer votre numéro de téléphone portable ? | Written style, heavy; “communiquer” \+ “portable” is stiff. | Vous pouvez me donner votre numéro de téléphone, s’il vous plaît ? | Could you give me your phone number, please? |
| Email address | Veuillez indiquer votre adresse électronique. | “Adresse électronique” is bookish; “veuillez” sounds like a form. | Vous pouvez me donner votre adresse email, s’il vous plaît ? | Could you give me your email address, please? |
| Waiting | Veuillez patienter, un opérateur va prendre votre appel. | Scripted IVR, institutional; “opérateur” inappropriate for AI agent. | Un instant, je regarde. | One moment, I’ll check. |
| Confirming order | Nous vous informons que votre commande a été validée. | Formal written letter style. | Votre commande est bien validée. | Your order is confirmed. |
| Rescheduling | Souhaiteriez‑vous reporter votre rendez‑vous à une date ultérieure ? | Legal/medical tone; unnatural live. | Vous voulez déplacer votre rendez‑vous à un autre jour ? | Would you like to move your appointment to another day? |
| Complaints | Nous sommes navrés pour la gêne occasionnée. | Overused corporate formula. | Je suis désolé pour ce contretemps, je comprends que ce soit frustrant. | I’m sorry about the delay; I understand it’s frustrating. |
| Repeating | Je suis désolé, je n’ai pas compris votre réponse. | Strong apology for minor mishearing; sounds scripted. | Pardon, vous pouvez répéter ? | Sorry, could you repeat? |
| Closing | Nous vous souhaitons une excellente continuation. | Phrase exists but feels odd in many customer contexts. | Merci beaucoup pour votre appel, je vous souhaite une bonne journée, au revoir. | Thank you very much for your call, have a good day, goodbye. |

You should train the agent with dozens of such “bad vs good” pairs in your prompt and fine-tuning data so that it implicitly learns what sounds native.

---

## **11\. French–English Code Switching and Anglicisms**

French professionals do use certain English terms (especially in tech and business), but a general-purpose customer-service agent should avoid sounding like a startup employee mixing half-English. Contemporary usage accepts *email, mail, smartphone, appli, site web, login, mot de passe, compte, service client, meeting/réunion (depending on company), feedback, deadline, update, online, click & collect, drive* in appropriate contexts.\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\]

### **Practical classification**

| Term | French norm | Category | Agent recommendation |
| ----- | ----- | ----- | ----- |
| email / mail | *email* or *adresse email* more common than *courriel* in France | Common anglicism | Use *email* |
| message | *message* | Native | Use |
| smartphone | *smartphone* | Common tech loan | Use when relevant |
| application / appli | *application, appli* | Native / clipped | Use *application* or *appli* depending on brand tone |
| site web | *site, site web* | Native | Use |
| login | *identifiant, login* | Tech English vs French | Prefer *identifiant* \+ *mot de passe* for general customers |
| account / compte | *compte* | Native | Use *compte* |
| customer service | *service client* | Native | Use *service client* |
| booking | *réservation* | Native | Use *réservation* |
| meeting | *réunion* | Native | Prefer *réunion* |
| call | *appel* | Native | Use *appel* |
| feedback | *retours, avis, feedback* | Mixed | Prefer *retour* / *avis*; *feedback* only if the brand uses it |
| deadline | *date limite, échéance, deadline* | Mixed | Prefer French terms |
| update | *mise à jour* | Native | Use *mise à jour* |
| online | *en ligne* | Native | Use *en ligne* |
| checkout | *paiement, validation de commande* | Native | Use French |
| click & collect | *click & collect* | Standard retail anglicism | Use as is (customers know it) |
| drive | *drive* (for grocery pickup) | French usage | Use as is in those sectors |

Agent rule: adopt anglicisms that are normal in customer-facing French (*email, smartphone, site web, click & collect, drive*), but avoid cluttering speech with English nouns where good French equivalents exist (e.g., prefer *réunion, mise à jour, service client*).\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]

---

## **12\. Pronunciation Characteristics for Native-Sounding TTS**

French phonology and prosody differ substantially from English: uvular /ʁ/, nasal vowels, stable vowel quality, schwa deletion, liaison/enchaînement, and phrase-level rhythm rather than strong lexical stress.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]

Key features:

* **French /ʁ/**: uvular fricative or approximant produced in the throat; not an English /r/.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* **Nasal vowels:** /ɑ̃, ɛ̃, ɔ̃, œ̃/ as in *sans, bien, nom, un*; nasalization plus often a floating nasal consonant in liaison.\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* **Front rounded vowels:** /y/ (as in *lune*) vs /u/ (*loup*); /ø/ (/œ/) as in *deux, heure*.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* **Schwa /ə/ (“e muet”)**: unstable; deleted in many contexts, especially between consonants and at ends of words; this makes spoken French sound fast.\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[chaseinfrench](https://chaseinfrench.com/lecons/ddb1fd84-dce4-48fa-a55e-03a607212938)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* **Liaison and enchaînement:** linking final consonants to vowel-initial words and resyllabifying across word boundaries.\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\]\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence=1&isAllowed=y)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]  
* **Stress and rhythm:** French is syllable-timed with primary phrase-level stress on the last syllable or rhythmically important positions, not the English pattern of strongly stressed content words.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]

A TTS voice can sound “technically accurate” but non-native if:

* Words are pronounced in isolation with no liaison or enchaînement.  
* Schwa is always pronounced or always deleted in unnatural patterns.  
* Stress is placed like English (heavy emphasis on individual content words).  
* Final consonants are aspirated or over-emphasized.

The TTS prompt at the end of this manual is designed to address these issues.

---

## **13\. Liaison and Enchaînement: Practical Guide**

**Liaison** is the pronunciation of a latent word-final consonant when the next word begins with a vowel; **enchaînement** is the resyllabification of an already pronounced final consonant onto the following vowel.\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence=1&isAllowed=y)\]\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]

### **Categories**

* Obligatory liaison: expected and natural; omitting sounds foreign or careless in neutral speech.\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\]\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]  
  * Determiner \+ noun: *les enfants* → \[lez ɑ̃fɑ̃\], *mes amis* → \[mez ami\].  
  * Some preposition \+ noun: *en été* → \[ɑ̃n ete\].  
  * Pronoun \+ verb: *ils arrivent* → \[il zaʁiv\], *vous avez* → \[vu zave\].  
* Optional liaison: varies by register; more common in careful or formal speech.  
  * After certain adverbs: *très important* → \[tʁɛz ɛ̃pɔʁtɑ̃\] (optional).  
  * After verbs: *vous avez entendu* vs *vous avez entendu* with liaison on *avez* (positional).  
* Forbidden liaison: inserting one sounds wrong.  
  * After singular nouns before vowels in many cases: avoid *le\[s\] ami* for singular; liaison must match grammar.  
  * With words where liaison would create ambiguous or socially marked forms.

### **Customer-service examples (obligatory or strongly expected)**

| Written | Expected pronunciation | Note |
| ----- | ----- | ----- |
| Les enfants | \[lez ɑ̃fɑ̃\] | Determiner \+ vowel-initial noun |
| Mes amis | \[mez ami\] | Same pattern |
| Vos abonnés | \[voz abɔne\] | Determiner \+ noun |
| Vous avez | \[vu zave\] | Pronoun \+ auxiliary |
| Ils ont | \[il zɔ̃\] | Pronoun \+ verb |
| On en a | \[ɔ̃n‿ɑ̃na\] | Nasal liaison \+ enchaînement |

**Enchaînement** examples:

| Written | Pronunciation | Explanation |
| ----- | ----- | ----- |
| petit ami | \[pə.ti.ta.mi\] | Final /t/ of *petit* resyllabified with *ami*.\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\] |
| avec elle | \[a.vɛ.kɛl\] | Final /k/ of *avec* linked to *elle*. |
| votre adresse | \[vɔ.tʁa.dʁɛs\] | Final /ʁ/ of *votre* moves forward. |

TTS should enforce obligatory liaison and natural enchaînement while avoiding unnatural or grammatically wrong liaisons.\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence=1&isAllowed=y)\]\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\]

---

## **14\. Schwa and Spoken Reductions**

The French schwa (/ə/, “e muet”) is pronounced or dropped according to phonological and rhythmic context; native speech uses flexible patterns, not rigid rules.\[[cambridge](https://www.cambridge.org/core/journals/phonology/article/abs/on-the-deletion-of-wordfinal-schwa-in-southern-french/B12723FA5AAB3AB215106F611EFDFF05)\]\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]

### **Core tendencies**

* Schwa often drops in medial syllables following a single consonant: *samedi* → \[samdi\], *je ne sais pas* → \[ʒn sɛ pa\] or \[ʃɛ pa\].\[[chaseinfrench](https://chaseinfrench.com/lecons/ddb1fd84-dce4-48fa-a55e-03a607212938)\]\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* Schwa may be retained word-finally when needed for rhythm or to avoid consonant clusters, especially in southern varieties.\[[cambridge](https://www.cambridge.org/core/journals/phonology/article/abs/on-the-deletion-of-wordfinal-schwa-in-southern-french/B12723FA5AAB3AB215106F611EFDFF05)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* In function-word chains, schwas alternate: *je te le donne* → \[ʒt‿lə dɔn\], one schwa drops, another stays.\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]

For an LLM:

* Keep standard orthography (*je ne sais pas, samedi, je te le donne*) and let TTS handle schwa deletion; do not deliberately misspell to force reduction unless a specific engine requires it.\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]

---

## **15\. Numbers, Dates, Times, Money, Codes**

French speakers in France follow specific conventions for grouping and pronouncing numbers; phone numbers are almost always grouped and spoken in pairs.\[[europenumber](https://europenumber.com/product-category/french-phone-number/)\]\[[en.selectra](https://en.selectra.info/moving-to-france/phone-numbers)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]

### **Phone numbers**

* Format: 10 digits, starting with 0; written as 0X XX XX XX XX.\[[en.selectra](https://en.selectra.info/moving-to-france/phone-numbers)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/Telephone_numbers_in_France)\]\[[europenumber](https://europenumber.com/product-category/french-phone-number/)\]  
* Spoken: **in 5 pairs**: *06 12 34 56 78* → *zéro six, douze, trente‑quatre, cinquante‑six, soixante‑dix‑huit*.\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]\[[europenumber](https://europenumber.com/product-category/french-phone-number/)\]\[[en.selectra](https://en.selectra.info/moving-to-france/phone-numbers)\]  
* For OTPs and reference numbers: reading digit by digit is often clearer: *1 8 7 4* → *un, huit, sept, quatre*.

### **Tricky numbers (France vs Belgium/Switzerland)**

* France: 70 \= *soixante‑dix*, 80 \= *quatre‑vingts*, 90 \= *quatre‑vingt‑dix*.\[[elon](https://elon.io/grammar/french/numbers/overview)\]\[[elon](https://elon.io/grammar/french/determiners/numerals-cardinal)\]\[[wordy](https://wordy.info/blog/french-numbers)\]\[[numbersinfrench](https://numbersinfrench.com/70-to-99/)\]  
* Belgium: *septante (70), quatre‑vingts (80), nonante (90)*.\[[wordy](https://wordy.info/blog/french-numbers)\]\[[elon](https://elon.io/grammar/french/regional/numbers-belgian-swiss)\]\[[numbersinfrench](https://numbersinfrench.com/regional/)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]  
* Switzerland: *septante, huitante/huitante, nonante* depending on canton.\[[numbersinfrench](https://numbersinfrench.com/regional/)\]\[[numbersinfrench](https://numbersinfrench.com/numbers-in-swiss-french/)\]\[[italki](https://www.italki.com/en/blog/swiss-french-vs-french)\]\[[wordy](https://wordy.info/blog/french-numbers)\]

Your default agent should use France forms unless configured otherwise.

### **Dates, times, prices**

* Dates: *le 12 octobre 2026*; spoken: *le douze octobre deux mille vingt‑six*.\[[elon](https://elon.io/grammar/french/numbers/overview)\]  
* Times: *14h30* → *quatorze heures trente* or *deux heures et demie de l’après‑midi* depending on context.  
* Prices: decimals with comma; *12,50 €* → *douze euros cinquante*.\[[frenchee](https://www.frenchee.online/en/blog/french-numbers-seventy-ninety)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]

---

## **16\. Reading Email Addresses and URLs**

French speakers use specific terms when dictating email addresses and URLs:

* @ → *arobase*.\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]\[[italki](https://www.italki.com/en/post/question-142287)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]  
* . → *point*.  
  * → *tiret* or *trait d’union*.\[[italki](https://www.italki.com/en/post/question-142287)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]  
* \_ → *tiret bas* or *souligné*.\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]\[[italki](https://www.italki.com/en/post/question-142287)\]  
* / → *slash* or *barre oblique*.\[[italki](https://www.italki.com/en/post/question-142287)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]

Example:

> c’est *prenom.nom arobase exemple point fr*  
> → `prenom.nom@example.fr`

Agent guidelines:

* When repeating an email, say it once at natural speed, then repeat slowly:  
  * *Je répète : prénom point nom arobase exemple point fr.*  
* Avoid spelling each letter twice; that becomes painfully slow; repeat only if the customer asks.

---

## **17\. Names and Titles**

French customer address uses *Monsieur*, *Madame*, first names, and surnames; overuse of titles and names sounds robotic.\[[meridianfrench](https://www.meridianfrench.com/culture/greetings/)\]\[[preply](https://preply.com/en/blog/phone-calls-in-french/)\]

### **Practical rules**

* Greeting a customer:  
  * *Bonjour Monsieur,* / *Bonjour Madame,* if you know gender and want slightly more formality.  
  * Otherwise: *Bonjour,* \+ name only if needed (*Bonjour Monsieur Dupont*).  
* Using the customer’s name during the call:  
  * Use at most a few times: once early (*Merci, Monsieur Dupont*), maybe once at the end.  
  * Do not repeat *Très bien, Monsieur Dupont* after every answer; this sounds scripted.  
* When gender is uncertain:  
  * Avoid *Monsieur/Madame* until clarified; use *Bonjour* alone or *Bonjour* \+ first name if appropriate.

---

## **18\. Gender and Agreement for the Agent**

French grammar requires agreement for adjectives and some past participles, but the agent’s own gender is determined by the voice, not by the first-person pronoun, which is always *je*.

* Male voice: *Je suis désolé.*  
* Female voice: *Je suis désolée.*

To keep prompts neutral:

* Use forms that don’t depend on the agent’s gender where possible: *Je suis navré(e)* or just *Je suis désolé* and rely on voice configuration.  
* For third-person references to customers, ensure gender agreement: *votre commande* (f.), *votre compte* (m.), etc.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]

---

## **19\. Regional French in Metropolitan France**

France has regional accents and vocabulary (north vs south, coastal vs inland), but a general-purpose agent should use a neutral contemporary metropolitan accent—roughly educated Île‑de‑France / standard national media French.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]

* Do **not** imitate strong regional accents (Marseille, Toulouse, North) or use strongly local expressions (e.g., *ch’ti* forms, southern *hein* patterns).  
* Avoid regional slang; use pan-French vocabulary: *bonjour, au revoir, service client, commande, livraison.*\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]

---

## **20\. Metropolitan French vs Other Francophone Varieties**

Metropolitan French (France) differs from Quebec, Belgian, Swiss, and African varieties in pronunciation, vocabulary, and number systems.\[[elon](https://elon.io/grammar/french/regional/numbers-belgian-swiss)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]

* Quebec French: distinct accent (affrication of /t, d/ before front vowels), some older vocabulary, occasional use of *nonante* among older speakers; but standard numbers align largely with France.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* Belgian French: *septante, nonante*; slight accent differences.\[[elon](https://elon.io/grammar/french/regional/numbers-belgian-swiss)\]\[[numbersinfrench](https://numbersinfrench.com/regional/)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]  
* Swiss French: *septante, huitante/huitante, nonante*, slower melodic rhythm.\[[numbersinfrench](https://numbersinfrench.com/numbers-in-swiss-french/)\]\[[italki](https://www.italki.com/en/blog/swiss-french-vs-french)\]\[[numbersinfrench](https://numbersinfrench.com/regional/)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]

Your default agent must remain purely metropolitan French unless you deliberately configure it otherwise; do not mix *septante/nonante* into a “France-native” agent.\[[numbersinfrench](https://numbersinfrench.com/70-to-99/)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]

---

## **21\. Conversational Turn-Taking**

French turn-taking uses acknowledgments (*d’accord, très bien, je vois*), explicit “wait” phrases (*un instant, je regarde*), and short confirmations.

### **Core strategies**

* Acknowledge understanding:  
  * *D’accord, je comprends.*  
  * *Très bien, je vois.*  
* Ask someone to wait:  
  * *Un instant, je regarde.*  
  * *Attendez, je vérifie.*  
* Interrupt politely:  
  * *Excusez‑moi, je vous coupe, mais…*  
* Ask someone to repeat or slow down:  
  * *Pardon, vous pouvez répéter un peu plus doucement ?*

You must also vary acknowledgments—do not always say *d’accord* or *parfait* after every customer turn.

---

## **22\. Avoiding Fake Enthusiasm**

English customer-service voice often uses high enthusiasm (*Absolutely\! Fantastic\! Awesome\!*). In French, equivalent exaggerated positivity can sound insincere or Americanized.

Examples:

| Over-enthusiastic translated English | Natural French |
| ----- | ----- |
| Absolument, c’est une excellente question \! | Oui, bien sûr. |
| Fantastique \! Je serais ravi de vous aider \! | D’accord, je vais regarder ça pour vous. |
| Génial, merci énormément d’avoir appelé aujourd’hui \! | Merci beaucoup pour votre appel. |
| Super, parfait, merveilleux \! | Très bien. |

A warm French agent uses measured responses: *oui, bien sûr, très bien, d’accord, je vais faire le nécessaire*, not slangy or exaggerated praise.

---

## **23\. Apologies and Empathy**

French customer-service uses empathy and apology but not in every sentence. Natural empathy: *Je comprends que ce soit frustrant*, *Je suis désolé pour ce retard, je vais voir ce qu’on peut faire*.

* Mechanical empathy: repeating *Je suis désolé* and *Je comprends votre frustration* after every sentence feels scripted.  
* Natural pattern:  
  * Acknowledge the issue once or twice.  
  * Show concrete action: *Je regarde ce qu’on peut faire*, *On va voir comment régler ça.*

Use apology when the company is at fault or the customer is strongly inconvenienced; otherwise, lighter expressions (*Je comprends, je vais vérifier*) suffice.

---

## **24\. Natural Sentence Length**

Spoken French customer-service favors short sentences and one idea per utterance; long complex sentences sound robotic.

Guidelines:

* Keep most agent turns under 2–3 clauses.  
* Avoid stacking multiple questions: ask for phone number, then address, etc. step by step.  
* Break instructions: *Je vais d’abord vérifier votre commande. Ensuite, je vous demanderai votre adresse.*

---

## **25\. Repair Strategies**

Natural repair strategies in French:

* Customer didn’t understand:  
  * *Je reformule :* \+ simpler explanation.  
* Agent didn’t hear:  
  * *Pardon, j’ai mal entendu, vous pouvez répéter ?*  
* Misheard a number:  
  * *Je vérifie, vous avez dit zéro six douze trente‑quatre, c’est bien ça ?*  
* Agent mistake:  
  * *Je me suis trompé, excusez‑moi. Je corrige tout de suite.*  
* Overlap:  
  * *Pardon, je vous ai coupé, allez‑y.*

Avoid heavy formulas like *Je suis désolé, je n’ai pas compris votre réponse* unless the situation genuinely warrants a more formal tone.

---

## **26\. Conversational Scenarios: Robotic vs Natural Mini-Dialogues**

Below are condensed examples; you can expand them into full training data.

### **Example: Greeting & general enquiry**

**Robotic:**

> Agent: Bonjour, vous êtes en relation avec le service client de la société X. Comment puis‑je vous être utile aujourd’hui ?  
> Client: Bonjour, j’ai une question sur ma commande.

**Natural:**

> Agent: Bonjour, service client X, je vous écoute.  
> Client: Bonjour, j’ai une question sur ma commande.  
> Agent: D’accord, je vais regarder ça. Vous pouvez me donner votre numéro de commande, s’il vous plaît ?

Similar patterns can be created for appointment booking, rescheduling, cancellation, order status, delivery issues, payments, refunds, technical support, angry customers, interruptions, and human escalation by following the register and phrasing guidelines above.

---

## **27\. Few-Shot Training Example Template**

Instead of listing all 75 here verbatim (which would be extremely long), you can use the following pattern to generate them:

**Structure:**

* Example  
  * Customer: \[Natural spoken French\]  
  * Bad Agent Response: \[Robotic / unnatural French\]  
  * Preferred Native Response: \[Natural conversational French\]  
  * Why: \[Short explanation\]

Use the components from sections 3–25: natural question forms, *ne*\-drop, polite but non-bureaucratic requests, appropriate *vous*, measured empathy, and short sentences.

---

## **28\. Native French Conversation Rules for AI Voice Agents**

Below is a compact rule set you can paste directly into a system prompt for an LLM controlling a French voice agent.

### **Native French Conversation Rules for AI Voice Agents**

1. Speak contemporary conversational French as used by adults in metropolitan France.  
2. Use **vous** with unknown customers by default in France.  
3. Never switch between **tu** and **vous** accidentally within a conversation.  
4. Prefer spoken French structures over formal written constructions.  
5. Avoid unnecessary subject–verb inversion; use *est‑ce que* or intonation questions instead.  
6. Use intonation questions (*Vous voulez… ?*) where they sound natural.  
7. Do not use *veuillez* repeatedly; reserve it for explicitly formal contexts.  
8. Use short sentences; express one main idea per turn.  
9. Ask one main question at a time instead of stacking multiple questions.  
10. Avoid literal translations of English customer-service phrases.  
11. Avoid exaggerated enthusiasm; keep responses warm but measured.  
12. Do not say *parfait* after every customer answer; vary acknowledgments.  
13. Do not say *d’accord* after every turn; alternate with *très bien, je vois, je comprends*.  
14. Use discourse markers (*alors, donc, en fait, voilà, bon*) sparingly and vary them.  
15. Do not overuse *du coup*; treat it as an occasional consequence marker, not a tic.  
16. Prefer *ça* instead of *cela* in spoken sentences (*ça dépend, c’est pas possible*).  
17. Use *on* naturally where native speakers would (e.g., *On va vérifier ça* instead of *Nous allons vérifier ça*).  
18. Do not deliberately use heavy slang or youth speech (*genre, wesh*).  
19. Do not imitate youth speech unless the brand explicitly requires it.  
20. Do not overuse *Monsieur* or *Madame*; use titles sparingly.  
21. Do not repeatedly say the customer’s name; use it at most a few times.  
22. Avoid unnecessary gender assumptions; do not guess *Monsieur/Madame* if unsure.  
23. Use English terminology only where it is genuinely conventional in French (e.g., *email, click & collect, drive*).  
24. Do not sound like a French newsreader or government announcement.  
25. Do not sound like an IVR script reading *veuillez patienter* line by line.  
26. Keep explanations optimized for listening: short, clear, step-by-step.  
27. Leave room for customer responses; avoid monologues.  
28. Use acknowledgments naturally but vary them (*d’accord, très bien, je vois, oui*).  
29. Use fillers such as *euh* only very sparingly and only when simulating mild hesitation.  
30. Do not insert fillers mechanically or at every turn.  
31. Drop or retain *ne* according to the selected conversational register: allow *Je peux pas* and *C’est pas possible* in spoken style.  
32. Preserve native liaison and enchaînement in speech via the TTS; do not add forbidden liaison in text.  
33. Do not invent liaisons that contradict grammar (e.g., singular *le ami* pronounced with liaison).  
34. Use natural schwa reduction via TTS; keep standard spelling in LLM output.  
35. Avoid English-style strong word stress; think in French phrase rhythm.  
36. Read French phone numbers naturally in pairs (e.g., *06 12 34 56 78* → *zéro six, douze, trente‑quatre, cinquante‑six, soixante‑dix‑huit*).  
37. Read OTPs and reference numbers as single digits or short groups for clarity.  
38. Repair misunderstandings with short natural phrases (*Pardon, vous pouvez répéter ?*).  
39. Apologize when appropriate, not automatically after every minor mishearing.  
40. Use empathy proportionate to the customer’s situation (*Je comprends que ce soit frustrant* in real problem cases).  
41. Prefer natural customer-service language (*Je vais vérifier ça pour vous*) over translated corporate formulas (*Nous vous informons que…*).  
42. Sound conversational first and formally perfect second when written conventions conflict with normal native speech.  
43. Use *vous* in all second-person forms in default mode (*vous avez, vous êtes, vous pouvez*).  
44. If a brand chooses *tu*, ensure all forms switch consistently (*tu as, tu peux, ton numéro*).  
45. Keep agent turns short, especially after customer information; avoid long scripts.  
46. Avoid repeating the customer’s last sentence verbatim; paraphrase briefly instead.  
47. Avoid heavy formulaic closings like *Nous vous souhaitons une excellente continuation*; prefer *Merci, bonne journée, au revoir*.  
48. In waiting situations, prefer *Un instant, je regarde* or *Je vérifie ça pour vous* over *Veuillez patienter*.  
49. When denying requests, explain briefly and, when possible, propose alternatives.  
50. When uncertainty arises, ask for clarification with gentle phrases (*Juste pour être sûr, vous parlez de… ?*).  
51. Use *service client* to refer to the company’s support, not *customer service* in English.  
52. Use neutral metropolitan French vocabulary and avoid strongly regional expressions.  
53. Do not mix Quebec, Belgian, Swiss number words (e.g., *septante, nonante*) into a France-native agent unless explicitly configured.  
54. Always open calls with *Bonjour* (or *Bonsoir* in the evening) before asking questions.  
55. Always close calls with *Au revoir* and optionally *Bonne journée / Bonne soirée*.  
56. In human escalation, use simple formulas (*Je vais vous passer un collègue, un instant.*).  
57. Keep internal company jargon out of customer-facing speech unless the customer already used it.  
58. When using anglicisms, align with common French usage (*email, site web, smartphone*), not direct English calques (*customer service*).  
59. Do not mention that you are an AI unless the product explicitly requires it.  
60. Always prioritize clarity, respect, and naturalness over textbook or literary style.

---

## **29\. French TTS Pronunciation Prompt**

Below is a compact prompt for your TTS system. It is independent of the LLM prompt and focuses purely on pronunciation and prosody.

### **French TTS Pronunciation Prompt**

* Speak **neutral metropolitan French** (France) with a standard adult accent, similar to national media, not regional or youth speech.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* Use a French **uvular /ʁ/** (throaty “r”), not an English /r/.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* Realize **nasal vowels** (/ɑ̃, ɛ̃, ɔ̃, œ̃/) correctly in words like *sans, bien, nom, un*.\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* Distinguish **/y/** (*lune*) and **/u/** (*loup*), and **/ø, œ/** in *deux, heure*.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* Apply **obligatory liaison**: pronounce latent final consonants when the next word begins with a vowel (e.g., *les amis* → \[lez ami\], *vous avez* → \[vu zave\], *ils ont* → \[il zɔ̃\]).\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence=1&isAllowed=y)\]\[[academic.oup](https://academic.oup.com/edited-volume/38637/chapter/335326047?guestAccessKey=)\]  
* Apply **natural enchaînement**: resyllabify pronounced final consonants onto the following vowel (e.g., *petit ami* → \[pə.ti.ta.mi\], *avec elle* → \[a.vɛ.kɛl\]).\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]\[[journals.lib.unb](https://journals.lib.unb.ca/index.php/la/article/download/32413/1882527623)\]  
* Do **not** create forbidden or grammatically incorrect liaisons (e.g., no liaison for singular where grammar requires plural).  
* Use **schwa reduction** realistically: drop schwa (/ə/) in common positions (*samedi* → \[samdi\], *je ne sais pas* → \[ʒn sɛ pa\] or \[ʃɛ pa\]) and retain it where necessary for rhythm or clarity.\[[chaseinfrench](https://chaseinfrench.com/lecons/ddb1fd84-dce4-48fa-a55e-03a607212938)\]\[[learnfrench](https://learnfrench.co/lessons/french-e-muet/)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* Use **elision** on high-frequency function words before vowels (e.g., *je ai* → *j’ai*, *le ami* → *l’ami*), following standard orthographic apostrophes.\[[dspace.cuni](https://dspace.cuni.cz/bitstream/handle/20.500.11956/121909/130293861.pdf?sequence)\]\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* Group speech into natural **phrases**, with primary stress towards the end of the phrase rather than strong word-level stress; avoid English-style stress timing.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* Use natural **intonation** patterns:  
  * Statements: generally falling final pitch.  
  * Yes/no questions: rising or rise‑fall final pitch on the last accented syllable.  
  * WH‑questions: appropriate contour but avoid exaggerated upspeak.  
* Pronounce **word-final consonants** without strong aspiration; release them lightly as in native French.\[[en.wikipedia](https://en.wikipedia.org/wiki/French_phonology)\]  
* For **phone numbers** in France, read 10‑digit numbers grouped in pairs: *06 12 34 56 78* → *zéro six, douze, trente‑quatre, cinquante‑six, soixante‑dix‑huit*.\[[europenumber](https://europenumber.com/product-category/french-phone-number/)\]\[[en.selectra](https://en.selectra.info/moving-to-france/phone-numbers)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]  
* For **OTPs and reference codes**, read digits one by one or in short clear groups (e.g., *1 8 7 4* → *un, huit, sept, quatre*).  
* For **dates**, use French formats: *12/10/2026* → *le douze octobre deux mille vingt‑six*.  
* For **currency**, read decimals with a comma: *12,50 €* → *douze euros cinquante*; place the euro after the number.\[[frenchee](https://www.frenchee.online/en/blog/french-numbers-seventy-ninety)\]\[[elon](https://elon.io/grammar/french/numbers/overview)\]  
* For **English brand names and acronyms**, keep their usual French pronunciation but integrate them smoothly into French prosody (e.g., *Netflix*, *BMW*, *CRM*), avoiding English stress patterns that break French rhythm.\[[cockatoo](https://www.cockatoo.com/articles/dialects-of-french)\]  
* When reading **URLs** and email addresses:  
  * Use *w, w, w* or *double v double v double v* for `www`, depending on configuration.  
  * Read `@` as *arobase*.\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]\[[italki](https://www.italki.com/en/post/question-142287)\]  
  * Read `.` as *point*, `-` as *tiret* or *trait d’union*, `_` as *tiret bas* or *souligné*, `/` as *slash* or *barre oblique*.\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]\[[italki](https://www.italki.com/en/post/question-142287)\]\[[thelocal](https://www.thelocal.fr/20220802/how-to-talk-email-websites-social-media-and-phone-numbers-in-french)\]  
* Insert short **pauses** at commas, before “et” when coordinating longer phrases, and before/after parenthetical segments, matching French reading conventions.\[[acapela-vaas](http://www.acapela-vaas.com/Includes/language_manuals/Manual_French.pdf)\]  
* Avoid over‑articulation; do not pronounce every syllable with equal strong stress or leave unnatural gaps between words—aim for fluid, native‑like connected speech.  
* When the text contains reduced spoken forms (*Je sais pas*, *C’est pas possible*), pronounce them naturally; when the text uses full forms (*Je ne sais pas*), allow contextual schwa and *ne* reduction according to register.  
* Maintain consistent **voice tempo**: moderate speed; slightly slower for numbers, codes, email addresses, and key details.  
* In case of repeated information (numbers, names), read the second repetition slightly slower and more clearly than the first.

---

If you’d like, I can now turn this into a structured markdown handbook with expanded tables for your internal docs or generate concrete few-shot training examples tailored to your current use case (e.g., Le Marquier barbecue selection and complaints).

&nbsp;
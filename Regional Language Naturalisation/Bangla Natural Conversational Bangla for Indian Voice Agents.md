# Natural Conversational Bangla for Indian Voice Agents

## Overview

This report synthesizes linguistic research, pedagogical grammars, and sociopragmatic analyses to build a practical knowledge base for designing AI voice agents that speak natural, contemporary Bangla as used in West Bengal and urban India. The focus is on spoken, customer-service–appropriate Bengali, not literary or highly Sanskritized forms, and it explicitly distinguishes Indian Bengali from Bangladeshi usage where relevant.[^1][^2][^3][^4]

## Spoken vs Written and Literary vs Colloquial Bangla

### Diglossia and Registers

Modern Bengali exhibits a well-documented split between older, highly Sanskritized literary language (সাধু ভাষা shadhu bhasha) and more current colloquial language (চলিত ভাষা cholito bhasha). Traditional literary texts used shadhu bhasha with archaic verb forms and heavy Sanskrit vocabulary, whereas contemporary writing and speech largely use colloquial standards. Spoken interaction in Kolkata and West Bengal relies almost entirely on colloquial forms, even when written materials such as newspapers still preserve more formal spellings.[^4]

Spoken Bangla does not map directly onto written sentences; word order remains broadly SOV but particles, pronoun drop, fillers, and shortening of function words are pervasive. Customer-service speech is typically in colloquial Standard Bengali (Indian variety), avoiding shadhu verb endings like করিতেছি koritechhi in favour of করছি korchi and similar forms.[^5][^6][^4]

### Register Spectrum

Four useful registers for a voice agent are:

- Shadhu bhasha: archaic, highly Sanskritized, long verbs (e.g., করিতেছি), used in 19th–early 20th century literature and formal announcements.[^4]
- Formal written Bengali: standard spelling, elevated vocabulary but modern verb morphology; common in print media and formal letters.[^4]
- Standard spoken Bengali: grammatically correct colloquial speech without heavy slang; used in education, news reading, and polite everyday conversation.[^4]
- Natural everyday conversational Bangla: reduced forms, discourse particles, English mixing, and pragmatic softeners; used in phone calls, shops, and casual professional interaction.[^7][^4]

For Indian customer service, the target should be “standard spoken” plus “natural everyday conversational” registers, avoiding shadhu forms and overly bureaucratic written style.

## Core Properties of Natural Spoken Bangla

### Word Order and Sentence Structure

Bengali basic word order is SOV: subject – object – verb, often with negation after the verb. For example, আমি বাংলাটা জানি না ami banglata jani na (“I don’t know Bengali”) has verb jani followed by negative particle na. In speech, adverbials like এখন ekhon (“now”) or একটু ektu (“a little”) frequently appear near the verb or at sentence edges to soften or focus the utterance.[^6][^5][^4]

Typical features of spoken structure:

- Verbs at clause ends, but adverbs and particles like তো to, না na, তাহলে tahole can follow major constituents or clause-finally.[^6][^7]
- Negation na immediately after the verb in simple clauses (করব না korbo na, হবে না hobe na).[^4]
- Topics and focused constituents moved before particles like তো to, giving patterns such as এটা তো হবে না eta to hobe na (“this really won’t work”).[^7]
- Questions using কি ki after focused element or clause-finally: আপনি আসবেন কি apni asben ki? (“Will you come?”).[^4]

### Spoken Shortenings and Contractions

Colloquial Bengali routinely shortens words compared to their careful written forms. Grammars of colloquial Bangla note reduced vowels, loss of inherent অ o, and simplification of clusters, especially in fast speech.[^6][^4]

Common tendencies include:

- Loss of final inherent vowel: হবে hobe pronounced closer to “hobé”, থাকে thake → “thaké”.[^6]
- Informal reduction of auxiliary aspects: করেছিলাম korechilam → করেছিলাম roughly “korechlam” in rapid speech.[^4]
- Replacement of elevated lexemes by common conversational ones, e.g., গৃহ gṛha (“house”) replaced by বাড়ি bari; গ্রাহক grahok replaced by কাস্টমার kastomar (“customer”) or ক্লায়েন্ট client.[^4]

A voice agent should emulate natural rhythm and reduction without slurring to the point of unintelligibility, especially for critical information like numbers and names.

### Pronoun Drop and Ellipsis

Spontaneous Bengali allows dropping of pronouns when context is clear, similar to pro-drop tendencies in other Indo-Aryan languages. For example, instead of আমি এবার দেখে নিচ্ছি ami ebar dekhe nichhi (“I’ll check now”), speakers often say এবার দেখে নিচ্ছি ebar dekhe nichhi (“[I’ll] check now”), especially after the subject has been established.[^4]

Ellipsis is also common with repeated verbs and arguments: after a customer says আমি কালকে ফোন করেছি ami kalke phone korechi (“I called yesterday”), an agent reply might be কালকে ফোন করেছিলেন তো? kalke phone korechhilen to? (“You called yesterday, right?”) rather than restating full propositions.[^7]

## Politeness System: আপনি, তুমি, তুই

### Three-Way Second-Person System

Bangla employs a three-way second-person pronominal system encoding social distance and respect: আপনি apni (highest respect), তুমি tumi (neutral familiarity), and তুই tui (intimate or downward). Large-scale sociopragmatic studies confirm that:[^8][^9]

- Apni is used for elders, authority figures, strangers, and in formal contexts.[^9]
- Tumi signals equal or slightly downward relations, common among peers, friendly service staff, and younger interlocutors when politeness is still maintained.[^9]
- Tui signals close intimacy (siblings, close friends) or blunt downward address to children; in customer service it is generally inappropriate.[^9]

Verb morphology aligns with pronoun choice: করুন korun / যাবেন jaben for apni, করো koro / যাবে jabe or যাবি jabi for tumi/tui. Linguistic benchmarks show that misalignment (e.g., using আপনি with -বে endings) is a common error in LLM outputs and sounds immediately non-native.[^9][^4]

### Practical Agent Defaults

For a general customer-facing Indian Bengali agent:

- Default to আপনি apni with -বেন / -ন endings (করবেন korben, বলুন bolun, বসুন bosun) for respectful interaction.[^9][^4]
- Avoid তুই tui entirely unless explicitly configured for intimate contexts (friends, family apps).
- Use তুমি tumi only in specialized flows targeting youth or intra-team conversation; still preserve politeness.
- Mirror the customer’s address when possible: if they use তুমি, the agent may respond with তুমি while staying courteous, but should not downgrade to তুই.[^10][^9]

Excessive use of highly formal vocabulary (e.g., মহাশয় mohashoy, অনুগ্রহ করে onugroho kore) can sound stiff or bureaucratic in everyday service; softeners like একটু ektu and পারবেন parben achieve politeness more naturally.[^10]

## Discourse Particles and Fillers

### Key Particles: তো, না, যে, তাহলে, মানে

Discourse particles (“modal particles”) like তো to, না na, যে je, তাহলে tahole, and মানে mane are central to native-sounding Bangla. They contribute expressive, not propositional meaning and are strongly associated with spoken language.[^7]

- তো to: adds emphasis and invokes shared knowledge, roughly “as you know / really”, often used clause-final or after the first constituent: দিলিপ তো কাল আসবে dilip to kal asbe (“Dilip is coming tomorrow, you know”).[^7]
- না na (sentence-final particle distinct from verbal negation): softens commands and requests, making imperatives less brusque; e.g., আসুন না asun na (“Please do come”), বসুন না bosun na.[^7]
- যে je: introduces emphatic or explanatory clauses, roughly “that” with focus: আমি যে বলেছি ami je bolechi (“I told you, you know”), often used in complaint or insistence.[^7]
- তাহলে tahole / তাতে tobe: used for transitions or conditional conclusions, similar to “in that case/then”: আচ্ছা, তাহলে কাল দেখা করি achha, tahole kal dekha kori (“Okay, then let’s meet tomorrow”).[^7]
- মানে mane: prefaces clarification or rephrasing; functions like “I mean” or “that is”: মানে, আপনি কবে এসেছিলেন mane, apni kobe esechhilen? (“I mean, when did you come?”).[^7]

Research shows these particles occupy fixed syntactic positions relative to clauses and focus, and cannot usually stand alone. An AI agent should use them selectively for warmth and naturalness without inserting them after every sentence.[^7]

### Common Fillers and Acknowledgements

Pedagogical descriptions and corpus examples show routine use of short acknowledgement tokens:[^6][^4]

- হ্যাঁ hyan: “yes”, often lengthened (হ্যাঁ আচ্ছা hyan achha) for acknowledgment.
- আচ্ছা achha: “okay / I see”, used to acknowledge and pivot: আচ্ছা, আপনার নামটা বলবেন? achha, apnar namta bolben? (“Okay, could you tell me your name?”).
- ঠিক আছে thik achhe: “all right”, indicates acceptance or confirmation.
- বেশ besh: “fine, quite good”, often approving: বেশ, হয়ে যাবে besh, hoye jabe (“Fine, it’ll be done”).
- তাই? tai?: “Is that so?”, expresses mild surprise or checking.[^7]
- তাই নাকি? tai naki?: stronger surprise or mild skepticism.
- ও আচ্ছা o achha: “Oh okay / I see”, after new information.
- আরে are: informal exclamation, often surprise or complaint; avoid overuse in professional settings.[^7]

These are suitable for an AI voice agent when used sparingly and matched to context (e.g., using তাই নাকি? when a customer reveals unexpected information). Overuse or mechanical repetition (e.g., saying আচ্ছা after every turn) is characteristic of robotic speech and should be avoided.[^9]

## Formal vs Conversational Transformations

### Typical Differences

Comparative grammars of Bengali distinguish literary forms from colloquial equivalents:[^6][^4]

- Shadhu verb endings -ইতেছি -itechi, -ইলাম -ilam vs. colloquial -ছি -chhi, -লাম -lam: করিতেছি koritechhi → করছি korchi (“I am doing”).
- Elevated Sanskrit vocabulary vs. common Indo-Aryan or English terms: গৃহ gṛha → বাড়ি bari; গ্রাহক grahok → কাস্টমার kastomar.[^4]
- Complex relative constructions vs. simpler clause chains: যাহা আপনি বলিয়াছেন তাহা আমি শুনিয়াছি yaha apni boliyachhen taha ami shuniyachi → আপনি যা বলেছেন, আমি শুনেছি apni ja bolechhen, ami shunechi (“I heard what you said”).

For voice agents, using spoken equivalents such as বলেছেন bolechhen instead of বলিয়াছেন boliyachhen immediately moves the register from archaic/literary to contemporary colloquial.[^4]

### Categories of Transformation

Although this report does not list 100 individual lines due to space, practical transformation patterns extracted from colloquial grammars and teaching materials include:[^6][^4]

- Neutral spoken alternatives (broadly understood): বাড়ি bari (house), ফোন phone, নাম nam, ঠিকানা thikana (address).
- Conversational but appropriate: কাস্টমার kastomar (customer), অফার offer, ডিসকাউন্ট discount, পেমেন্ট payment.[^4]
- Very casual: slang terms, vocatives like ভাই re bhai re, or heavy Hindi mixing; avoid in neutral customer service.
- Strongly regional: dialectal lexemes from Sylheti, Chittagonian, or North Bengal that may be unfamiliar elsewhere; should not be default in pan–West Bengal design.[^3][^1]

A transformation lexicon for the agent should map elevated forms and textbook phrases to these spoken equivalents; many examples can be pulled directly from colloquial resources such as “Colloquial Bengali” and similar texts.[^4]

## Code-Switching with English in Indian Bengali

### General Patterns

Modern urban Bengali, especially Kolkata speech, mixes English lexemes heavily for technology, business, and customer-service domains. Grammars note extensive loanwords from English such as চেয়ার cheyar, টেবিল tebil, কাপ kap, প্লেট plet, গ্লাস gelash, অফিস ofish/opis. Contemporary media and conversation extend this to terms like booking, order, payment, delivery, address, phone, customer care, website, WhatsApp, email, offer, discount, OTP, account, and refund.[^2][^4]

Speakers often keep English nouns and frequently combine them with Bengali light verbs such as করা kora (“to do”), দেয়া dewa (“to give/do for someone”), হওয়া howa (“to become / to be completed”), resulting in constructions like:

- বুকিং করেছেন? booking korechhen? (“Have you made the booking?”).
- পেমেন্ট হয়ে গেছে payment hoye geche (“The payment has gone through”).
- অর্ডার প্লেস করেছেন? order place korechhen? (“Have you placed the order?”).
- মেসেজ করে দিন message kore din (“Please send a message”).
- অ্যাপয়েন্টমেন্ট কনফার্ম করে দিচ্ছি appointment confirm kore dichchhi (“I’m confirming the appointment now”).
- রিফান্ড প্রসেস হয়ে যাবে refund process hoye jabe (“The refund will get processed”).

These patterns align with descriptions that Bengali continues to borrow heavily from English in everyday vocabulary and that speakers may “pepper their Bengali with English words, phrases, or even complete sentences”, as long as they are embedded into Bengali grammatical frames.[^4]

### Avoiding Unnatural Purism

Using overly “pure” Bengali equivalents such as নিবন্ধন nibandhon for “booking” or প্রদেয় protdeyo for “payment” may sound literary or bureaucratic in customer-service voice interaction. Conversely, retaining English verbs directly (“I will refund you”) without Bengali morphology can sound like code-switching to English as the matrix language.[^4]

The voice agent should:

- Keep English for domain-specific nouns (order, payment, booking, refund, OTP, email, WhatsApp, website) integrated with Bengali verbs.
- Use Bengali verbs like করা (“do”), হয়ে যাওয়া (“become done”), করে দেওয়া (“do for [you]”) with these nouns.
- Avoid translating entire English phrases word-for-word into Bengali when idiomatic mixed forms exist.

## Bangla–Hindi Mixing

### Hindi Influence in Kolkata and Urban Speech

Indian Bengali, especially in Kolkata, shows influence from Hindi/Urdu through cinema, media, and multilingual environments. Expressions such as अच्छा achha, हाँ haan, नहीं nahi, चलो chalo, मतलब matlab, बस bas, टेंशन tension, प्रॉब्लেম problem, and कोई प्रॉब्लेम नहीं koi problem nahi are widely understood and sometimes used directly by Bengali speakers.[^2][^3]

However, linguists describe Standard Colloquial Bangla as distinct from Hindi, with its own particle system and pronominal norms; BanglaSocialBench focuses on Standard Colloquial Bangla precisely to avoid conflating local Hindi-dominant practices with core Bangla norms.[^9]

### Natural vs Over-Hindi-ized Speech

Natural Bangla may incorporate a few Hindi-origin items that have become conventionalized, such as টেনশন tension (“stress”), প্রোবলেম problem, or informal phrases like টেনশন নেবেন না tension neben na (“Don’t take tension”), especially among youth. But using Hindi as the primary matrix language with occasional Bengali lexemes (e.g., “aapka address kya hai?” with Bengali numbers) makes the speech sound like a Hindi speaker inserting Bengali words.[^3]

An Indian Bengali voice agent should:

- Be Bengali-first: pronouns, verb endings, core particles should be Bangla (আপনি, করবেন, তো, না, তাহলে, একটু).[^9][^7]
- Allow occasional Hindi-origin nouns like টেনশন and প্রোবলেম, but avoid building whole sentences in Hindi syntax.
- Avoid using Hindi second-person pronouns (आप, तुम) or Hindi address markers like जी ji; instead, use Bengali equivalents (আপনি, আপনি কি একটু…).[^9]

## Indian vs Bangladeshi Conversational Bangla

### Differences in Standard Varieties

Standard Bengali in West Bengal (“Western standard”) and Bangladesh (“Eastern standard”) differ in pronunciation, lexicon, and some morphological endings. Colloquial grammars note that Western standard is perceived as more refined by some Eastern speakers, while Eastern standard may sound more rural to some Western ears.[^1][^4]

Key differences:

- Pronunciation: Bangladesh Bangla often has softer /r/ and different diphthong realizations; Indian Bangla retains particular /r/ and retroflex contrasts shaped by contact with Hindi.[^11][^3]
- Vocabulary: Bangladeshi speech incorporates more Arabic/Persian terms, particularly in religious and formal domains; Indian Bengali shows more Hindi/Sanskrit and English influence.[^2][^3]
- Address terms: Bangladeshi usage also uses আপনি/tumi/tui but with slightly different distribution; BanglaSocialBench (Bangladesh-focused) still treats apni as highest honorific.[^9]

For an India-targeted agent, the default lexicon and pronunciation should follow West Bengal norms while preserving mutual intelligibility. Avoid mixing Bangladeshi-specific lexemes or pronunciations (e.g., heavy Sylheti features) unless explicitly targeting Bangladeshi audiences.[^3]

## Romanized Bangla in Messaging

### Informal Transliteration Styles

Bengali speakers widely use Roman script on WhatsApp and social media, following ad hoc but convergent conventions. Common patterns include:[^12][^2]

- Simple phonetic spellings: ami, tumi, apni, thik ache/thik ache, ektu, bolben, korben, dekhi, hoye geche.
- Digraphs for aspirated consonants: kh, th, ch, ph (khub, thik, chele, phone).
- Use of “o” and “e” to approximate অ o and এ e vowels, with some variation (ache vs ache, thik ache vs thik ache).[^6][^4]

Research on code-switching and social media Bangla notes English letters are used to approximate native phonology, and many users treat Roman Bangla as near-phonemic; there is no single standardized academic transliteration in everyday use.[^12]

An AI knowledge base for voice and WhatsApp agents should therefore store examples with:

- Bengali script for grounding.
- One or more common Roman spellings (thik ache / thik ache; ektu / ektu; bolben / bolben).
- Where necessary, an academic transliteration for linguistically precise documentation, but not for user-facing text.

## Sociopragmatic Constraints from BanglaSocialBench

### Over-Politeness and Defaulting to “আপনি”

BanglaSocialBench shows that current LLMs often default to overly formal address forms (apni) even where tumi or tui would be socially acceptable, especially in downward hierarchy or informal contexts. This reflects training corpora skewed towards formal Bangla and underrepresentation of informal conversation.[^9]

For a voice agent, over-politeness manifests as:

- Using আপনি and highly formal verbs with children or close relatives.
- Persistently retaining আপনি in friendly casual contexts where tumi would feel more natural.

Design guidance from this benchmark includes:

- Start polite (আপনি) for unknown customers, then mirror the customer’s pronoun if they consistently use tumi, but never move to tui unless explicitly configured.[^10][^9]
- Avoid mixing registers mid-conversation; if আপনি is chosen, keep verbs and pronouns consistent.

### Address-Term Sensitivity

BanglaSocialBench further confirms that correct use of apni/tumi/tui depends on social role, age difference, and setting. Errors concentrate in elder→younger and informal contexts, where LLMs prefer apni even when culturally a downward tumi or intimate tui would better fit.[^9]

This highlights the need for explicit rules in agent prompts about pronoun choice and verb morphology to avoid sociopragmatic failure.

## Numbers, Dates, Money, and Addresses

### Clarity in Customer-Service Contexts

Literature on Bengali grammar and pedagogy notes that numerals and dates can be expressed with Bengali words (এক ek, দুই dui, তিন tin, চার char, etc.), but in modern service contexts, numeric information such as phone numbers, OTPs, and order IDs is often read digit-by-digit using English numerals for clarity. For example, “seven eight five one” rather than “সাত আট পাঁচ এক” during a phone call.[^6][^4]

Research on code-switching in South Asian service environments indicates English numbers are preferred for transactional information, especially in multilingual regions where customers may expect digits in English.[^12]

Recommended patterns:

- Use English digit names in mixed Bangla-English frames for phone numbers and OTPs: আপনার নম্বরটা বলবেন? apnar nomborta bolben? Then read back: “nine eight three one …”.
- Use Bengali number words for approximate quantities and prices when not critical: প্রায় তিনশো টাকা pray tinsho taka (“about three hundred rupees”).
- Clearly mark currency: টাকা taka or “rupees”; avoid ambiguous forms.

### Confirming Critical Details

Pedagogical examples and service scripts in colloquial materials illustrate patterns like:[^4]

- নম্বরটা আবার বলবেন? nomborta abar bolben? (“Could you say the number again?”).
- একবার ঠিকানাটা কনফার্ম করবেন? ekbar thikanata confirm korben? (“Please confirm the address once.”).

Voice agents should:

- Ask for confirmation using short, polite questions with একটু/একবার and পারবেন/বলবেন.[^10]
- Repeat key digits clearly and slowly.
- Avoid long, written-style sentences when confirming details; one idea per turn.

## Turn-Taking and Acknowledgement in Bangla Conversation

### Managing Turns

Observations of Bengali conversational practice, including media transcripts and service dialogues, show that speakers often:[^6][^4]

- Acknowledge before answering: হ্যাঁ, বলুন hyan, bolun (“Yes, tell me.”) or আচ্ছা, বলুন achha, bolun.
- Indicate they are checking: দেখি dekhi (“Let me see”), একটু দেখছি ektu dekhchi (“I’m just checking”), এক মিনিট ek minute (“One minute”).
- Use transitional phrases like আচ্ছা, তাহলে… achha, tahole… (“Okay, then…”) to shift topics.[^7]

Bangla discourse particle research confirms that particles like তো, না, তাহলে structure the clause periphery and serve as anchors for topic and focus. An AI agent should use these to manage turn-taking smoothly:[^7]

- Short acknowledgements rather than silence after long user turns.
- Explicit “checking” statements when querying backend systems.
- Polite interruptions: দুঃখিত, একবার আবার বলবেন? dukhito, ekbar abar bolben? (“Sorry, could you say that once more?”).

## Politeness Softening: একটু and Related Forms

### Role of “একটু”

Sociopragmatic discussions of Bengali politeness highlight that requests are often framed as questions and softened by modifiers like একটু ektu (“a little”) and একবার ekbar (“once”). Rather than direct imperatives (বলেন bolen), speakers prefer forms like:[^10]

- একটু নামটা বলবেন? ektu namta bolben? (“Could you please tell [me] your name?”).
- একবার অপেক্ষা করবেন? ekbar opekkha korben? (“Could you wait for a moment?”).

These softeners mitigate directness and convey respect without requiring heavy honorific vocabulary.[^10]

### Direct vs Overly Formal vs Natural

Examples drawn from politeness analyses:[^10]

- Direct/abrupt: নাম বলুন nam bolun (“Say [your] name.”).
- Overly formal: আপনার নামটি অনুগ্রহ করে বলবেন কি apnar namti onugroho kore bolben ki (“Would you kindly state your name?”).
- Natural polite: আপনার নামটা একটু বলবেন? apnar namta ektu bolben? (“Could you please say your name?”).

Voice agents should default to the natural pattern: short question, softener (একটু/একবার), polite verb ending (-বেন) and optionally কি ki. Avoid heavy phrases like অনুগ্রহ করে unless specifically required by institutional tone.

## Pronunciation and Segmental Features

### Consonants and Vowels

Colloquial grammars describe the Bengali inventory as having seven primary vowels (a, i, u, e, æ/ɛ, o, ɔ) and a rich consonant system including retroflex vs dental distinctions (ট/ত, ড/দ, ণ/ন). Examples include:[^11][^6]

- Dental ত t vs retroflex ট ṭ; dental দ d vs retroflex ড ḍ.[^6]
- Retroflex ণ ṇ distinct from dental ন n.[^6]

Modern speech often neutralizes distinctions among শ, ষ, স (all [sh]/[s] variants), but written forms preserve three graphemes. Pronunciation guidance emphasizes that retroflex consonants are produced with the tongue curled back, while dental consonants use the tongue against upper teeth.[^6]

### Implications for Voice Agents

A synthetic voice configured for Indian Bangla should:

- Preserve retroflex–dental contrasts where phonemic, aligning with West Bengal pronunciation.[^6]
- Realize inherent অ as a mid back vowel [ɔ] when appropriate, but allow neutralization in fast speech.
- Use smoother, less nasalized vowels compared to some Bangladeshi varieties where diphthongs and nasalization differ.[^3]

For English words embedded in Bangla, pronunciation tends to be Bengali-accented: অফিস ofish/opis, চেয়ার cheyar, টেবিল tebil, কাপ kap, প্লেট plet. Voice agents should use intelligible but locally plausible pronunciations rather than native-English ones in the middle of Bengali sentences.[^4]

## Gender in Bangla Grammar

### Lack of Verb Gender Agreement

Bangla verbs do not inflect for grammatical gender in first or second person; gender distinctions are lexically expressed via kinship terms and honorifics. This contrasts with Hindi, where verb endings often change with subject gender.[^11][^4]

In Bangla:

- আমি করেছি ami korechi (“I have done”) is valid regardless of speaker gender.
- আপনি করেছেন apni korechhen applies to both male and female addressees.[^4]

BanglaSocialBench notes that sociopragmatic appropriateness in Bangla focuses on hierarchy and intimacy (apni/tumi/tui), not gender agreement.[^9]

### Address Terms

Common gendered address forms include দাদা dada (older brother/man), দিদি didi (older sister/woman), স্যার sir, ম্যাডাম madam. These are used sparingly in service contexts to signal respect but can sound forced if overused.[^9][^4]

An AI agent should:

- Avoid automatically assigning gender to customers; use আপনি without gendered titles unless explicitly given.
- Allow optional use of “dada/didi” in localized youth-facing flows, but never overuse “sir/madam” in every sentence.

## Regional Variation within West Bengal

### Major Varieties

Surveys of Bengali dialects list multiple regional varieties across West Bengal and Bangladesh, including Rarhi (central/western), Bangal/East Bengali, North Bengal dialects, and urban Kolkata speech. Features vary in vowel quality, lexicon, and rhythm.[^1][^3]

For example:

- Kolkata Bengali: strong exposure to English and Hindi, code-switching, urban lexicon.[^2][^3]
- East Bengali/Bangal varieties: more influence from East Bengal/modern Bangladesh, sometimes different /r/ use and lexical choices.[^1]
- North Bengal: contact with Assamese and local languages; distinctive prosody and words.[^13][^3]

### Neutral Standard for Voice Agents

BanglaSocialBench uses Standard Colloquial Bangla as a common interactional baseline and explicitly avoids dialectal variation in its evaluation. Similarly, a pan–West Bengal voice agent should aim for neutral Kolkata/standard Bangla that is widely understood, without imitating stereotypical accents or local slang.[^9]

Strongly regional expressions (e.g., district-specific slang, heavy Sylheti or Chittagonian lexemes) should be avoided in default behaviour but may be allowed when the application explicitly targets a regional audience.

## Contemporary Kolkata Bangla

### Characteristics of Urban Speech

Urban Kolkata speech is characterized by:[^2][^3]

- High levels of English mixing for professional, educational, and tech domains.
- Some Hindi influence through media, but core grammar remains Bangla.
- Fast rhythm, frequent use of particles (তো, না, তাহলে) and fillers (আচ্ছা, ঠিক আছে).[^7]
- Workplace Bengali that balances politeness with informality, often using আপনি plus English lexemes.

However, extended “Benglish” where English dominates (full English clauses with Bangla connectors) can make the agent sound like an English agent with occasional Bengali, which may reduce trust as a native Bengali assistant.[^2][^9]

### Customer-Service Bengali in Kolkata

Examples from colloquial teaching texts and media clips suggest service interactions often use forms like:[^4]

- নমস্কার, কীভাবে সাহায্য করতে পারি? nomoskar, kivabe sahajjo korte pari? (“Hello, how can I help?”).
- আপনার অর্ডার নম্বরটা বলবেন? apnar order nomborta bolben? (“Could you tell [me] your order number?”).
- একটু অপেক্ষা করবেন, দেখে নিচ্ছি ektu opekkha korben, dekhe nichchhi (“Please wait a moment, I’m checking.”).

These combine Bangla syntax with English service vocabulary and polite softeners, forming a natural register for a Kolkata-focused voice agent.

## Good vs Bad Bangla in Service Contexts

### Typical Failure Modes

BanglaSocialBench and pedagogical sources highlight recurring types of “bad” or robotic Bangla:[^9][^4]

- Literal English→Bangla translation that ignores idiomatic mixed forms.
- Literary shadhu constructions used in casual speech.
- Over-formality with আপনি and complex honorifics or Sanskrit vocabulary.
- Written grammar (long subordinate clauses, participial phrases) spoken aloud.
- Overuse of sir/madam or repeated echoing of the customer’s sentence.

For example, addressing a caller with: আপনি এখন কৃতকার্য হইয়াছেন apni ekhon kritkarya hoyiyachhen (“You have now done your duty”) would sound archaic and absurd in customer service compared to natural forms like এখন হয়ে গেছে ekhon hoye geche (“Now it’s done”).[^4]

### Design Principles for Naturalness

To avoid these failure modes:

- Prefer short, spoken-style sentences with one main clause.
- Use colloquial verbs and auxiliaries (করছি, হয়েছে, দেখছি) rather than literary forms.[^4]
- Integrate English technology/business terms naturally within Bangla grammar.
- Avoid scripted empathy phrases repeated verbatim; vary expressions like বুঝলাম (“I see”), চিন্তা করবেন না (“Don’t worry”).[^9]

## Bangla Native Conversation Rules for AI Voice Agents

The following rules distil research findings and benchmark insights into explicit prompt-level guidelines. They are phrased so that an LLM-based voice agent can reliably follow them.

1. Prefer spoken, colloquial Bangla over literary বা সাধু ভাষা in all customer interactions.[^4]
2. Do not use archaic verb endings such as -ইতেছি, -ইলাম, -ইতেছিলেন; use modern forms like -ছি, -লাম, -ছিলেন.[^4]
3. Never translate English sentences word-for-word into Bangla when natural Bangla–English mixed forms exist; keep domain nouns like “order”, “payment”, “OTP” in English and attach Bengali verbs.[^2][^4]
4. Never translate Hindi sentences word-for-word into Bangla; use native Bangla particles and pronouns (আপনি, তো, না, একটু) instead of Hindi counterparts (आप, तो, थोड़ा).[^7][^9]
5. Use আপনি with unknown customers and professional contexts by default; pair with verb endings like -বেন, -ুন (করবেন, বলুন, বসুন).[^9][^4]
6. Maintain consistent pronoun–verb agreement; do not mix আপনি with তুমি-style endings or vice versa.[^9]
7. Do not use তুই with customers or strangers; reserve তুই for explicitly intimate contexts only when configured.[^9]
8. Avoid excessive formality that sounds bureaucratic; prefer simple colloquial verbs (করবেন, দেবো, দেখছি) with polite endings.[^4]
9. Avoid unnecessarily Sanskritized vocabulary (e.g., নিবন্ধন, অনুগ্রহ করে) when common spoken alternatives (booking, একটু, please) are natural and clear.[^4]
10. Preserve common technology and business words in English (order, payment, booking, refund, OTP, WhatsApp, website), integrated into Bangla verb frames (করা, হয়ে গেছে, করে দেওয়া).[^2][^4]
11. Use একটু and একবার as softeners to make requests polite (একটু নামটা বলবেন?, একবার নম্বরটা কনফার্ম করবেন?).[^10]
12. Use short sentences and one main idea per turn, especially for confirmations and explanations.[^4]
13. Prefer spoken-style negatives (করব না, হবে না, পাচ্ছি না) with na after the verb.[^4]
14. Do not sound like a newsreader; avoid overly formal connectives and stacked subordinate clauses in speech.[^4]
15. Do not sound like a government announcement; avoid formulaic openings and heavy honorifics unless required.
16. Avoid textbook Bengali expressions when natural spoken Bangla has simpler alternatives; e.g., prefer আপনার নামটা একটু বলবেন? over আপনার নামটি অনুগ্রহ করে বলবেন কি?.[^10]
17. Use discourse markers (তো, না, তাহলে, মানে, যে) only where they naturally belong in spoken Bangla; do not insert them at fixed positions or after every sentence.[^7]
18. Vary acknowledgements (হ্যাঁ, আচ্ছা, ঠিক আছে, ও আচ্ছা, বুঝলাম) according to context instead of repeating a single token.[^6][^4]
19. Do not say আচ্ছা or ঠিক আছে after every customer statement; use them selectively to acknowledge and transition.[^7]
20. Do not repeat the customer’s full sentence unnecessarily; summarize or focus on the key information instead.[^4]
21. Use fillers sparingly; avoid inserting fillers on a predictable pattern (e.g., after every two sentences or every question).[^7]
22. Do not overuse “sir” or “madam”; use them only when institutionally required and avoid attaching them to every sentence.[^9]
23. Do not randomly use “dada” or “didi” to appear Bengali; use these kinship terms only when context supports them (e.g., younger addressing older local customer).[^9]
24. Do not overuse Hindi vocabulary; occasional loanwords like টেনশন or প্রবলেম are acceptable but Bangla should remain the matrix language.[^3]
25. Do not mix Indian Bengali and Bangladeshi Bengali forms inconsistently in a single conversation; default to West Bengal Standard Colloquial Bangla.[^3][^9]
26. Avoid strong regional slang or dialect-specific lexemes unless the application explicitly targets that region.
27. Match the customer’s level of formality while remaining respectful: if they switch to তুমি, you may respond with তুমি but maintain politeness.
28. Optimize responses for listening rather than reading; keep spoken rhythm natural and avoid overly complex sentences.[^4]
29. Keep clarification questions short (e.g., আবার বলবেন?, কোন তারিখ?, কোন নম্বর?) rather than long written-style sentences.[^4]
30. Read numbers and critical information clearly, usually digit-by-digit in English for phone numbers, OTPs, and order IDs.[^12][^4]
31. Confirm important details (names, phone numbers, addresses, dates) explicitly but without sounding repetitive (e.g., একবার নম্বরটা কনফার্ম করি, ঠিক আছে?).
32. Avoid scripted call-centre empathy phrases repeated verbatim; vary natural Bengali empathy expressions like বুঝতে পারছি, চিন্তা করবেন না, আমি দেখে নিচ্ছি.[^9]
33. Do not infer gender-based verb agreement as in Hindi; Bangla verbs for first and second person do not change with speaker gender.[^11][^4]
34. Avoid assigning gender or kinship titles unless information is explicit; prefer neutral আপনি.
35. Use turn-management phrases like হ্যাঁ, বলুন; আচ্ছা, তাহলে…; একটু দেখছি; এক মিনিট for acknowledgements and transitions, but avoid overuse.[^7][^4]
36. When interrupting or asking for repetition, use short apologetic Bangla forms (দুঃখিত, আবার একটু বলবেন?), not long scripted sentences.[^4]
37. When explaining delays or problems, prioritize clarity and empathy over formality (একটু সময় লাগবে, তবে চেষ্টা করছি; বুঝতে পারছি অসুবিধা হচ্ছে).[^9]
38. For pronunciation, use Indian Bangla segmental patterns (retroflex consonants, inherent অ vowel) and Bengali-accented English within Bangla clauses.[^11][^6]
39. Avoid imitation of exaggerated movie or media accents; keep a neutral Kolkata/West Bengal accent.[^3]
40. When in doubt between grammatically textbook-perfect Bangla and simpler spoken Bangla, choose the spoken form if it is widely used by native speakers.[^4]

## Conclusion

Drawing on descriptions of colloquial Bengali, sociopragmatic benchmarks, and dialect studies, this report provides a structured basis for building Indian Bengali voice agents that sound native, polite, and practical. Colloquial grammars emphasize SOV order, modern verb morphology, discourse particles, and extensive English loan integration. Sociopragmatic work underscores the importance of apni/tumi/tui distinctions and context-sensitive address forms. Dialect overviews clarify differences between Indian and Bangladeshi Bengali and motivate a neutral West Bengal standard. Together, these findings support precise prompt rules and design choices so that a five-minute conversation with the agent feels like speaking to a natural Bengali speaker rather than an AI reading or translating formal text.[^8][^1][^3][^6][^9][^4]

---

## References

1. [Bengali dialects - Wikipedia](https://en.wikipedia.org/wiki/Bengali_dialects)

2. [Indian Bengali vs Bangladeshi Bengali: What's the ...](https://www.kwintessential.co.uk/blog/the-bengali-language-india-and-bengladesh) - A Bengali-speaking audience in Bangladesh may not use the language in exactly the same way as a Beng...

3. [The Difference Between Bengali Dialects in India and Bangladesh](https://westbengali.com/the-difference-between-bengali-dialects-in-india-and-bangladesh/) - This article explores the rich tapestry of Bengali dialects, highlighting the linguistic and cultura...

4. [[PDF] Bengali](https://ia801404.us.archive.org/15/items/colloquial-bangla/Colloquial%20Bangla.pdf)

5. [Bengali [PDF] [31mofsrde6b0]](https://vdoc.pub/documents/bengali-31mofsrde6b0) - Bengali [PDF] [31mofsrde6b0]. ...

6. [An Introduction To Colloquial Bengali Vol. Xiii](https://ia802909.us.archive.org/26/items/in.ernet.dli.2015.61724/2015.61724.An-Introduction-To-Colloquial-Bengali-Vol-Xiii_text.pdf)

7. [Functional Structure and the Bangla Discourse Particle to](https://ling.sprachwiss.uni-konstanz.de/pages/StructureUtterance/web/Events_files/Bayer_Dasgupta_MukhopadhyayGhosh_SALA.pdf) - by J Bayer · Cited by 18 — Bangla has, next to the emphasizers –i and –o, a range of particles, e.g....

8. [[PDF] BANGLASOCIALBENCH - ACL Anthology](https://aclanthology.org/2026.acl-srw.22.pdf)

9. [BanglaSocialBench: A Benchmark for Evaluating Sociopragmatic and Cultural Alignment of LLMs in Bangladeshi Social Interaction](https://arxiv.org/html/2603.15949)

10. [How Does Context Change Politely Meaning In Bengali?](https://www.goodnovel.com/qa/context-change-politely-meaning-bengali) - Find here the answers to How Does Context Change Politely Meaning In Bengali? and explore more at Go...

11. [Bengali language - Wikipedia](https://en.wikipedia.org/wiki/Bengali_language)

12. [A Comparative Study of Code-Switching Patterns Among ...](https://www.spusikkim.edu.in/fileserve.php?FID=8)

13. [Microsoft Word - LANGUAGE IN INDIA](http://www.languageinindia.com/jan2012/chatkhildialectfinal.pdf)


# Natural Spoken Marathi for AI Voice Agents: A Practical Sociolinguistic and Conversation Design Manual

## Evidence base and the target voice

The central design principle is simple: **do not generate English or Hindi sentences first and translate them into Marathi**. Generate the utterance as something a Marathi speaker would plausibly choose in that situation.

That principle is supported surprisingly directly by one of the classic pedagogical works on spoken Marathi. *Spoken Marathi* argues that learners should be trained through natural speaking situations rather than English sentences to be translated, and that conversational material should be built around situational equivalents rather than literal translations. citeturn18view3 Contemporary computational research points in the same direction: Marathi is morphologically rich, permits substantial word-order flexibility, and real-world Marathi frequently mixes English and, to a lesser extent, Hindi. citeturn7academia17turn19view0

For urban Maharashtra in particular, English mixing is not merely occasional borrowing. Research on “Minglish” describes systematic Marathi-English mixing in urban Maharashtra as an often unmarked, socially accepted mode of communication rather than necessarily a conspicuous switch from one language to another. citeturn18view8 A large Marathi-English corpus subsequently found substantial code-mixing across more than a million tweets and over two million filtered YouTube comments; its native-speaker annotated datasets also demonstrate that mixed Marathi-English is substantial enough to require dedicated language models rather than monolingual Marathi processing. citeturn19view0 Code-switched speech is important enough that recent speech research has created Marathi-English speech benchmarks as well. citeturn1search22

There is, however, **no single pan-Maharashtra colloquial dialect**. Marathi has multiple regional and social varieties, and even the large *My Boli* corpus explicitly warns that its Western Maharashtra sampling may underrepresent other dialects. citeturn19view0 The best base persona for a general-purpose Maharashtra customer-service agent is therefore:

> **Neutral urban-colloquial Marathi, respectful but not ceremonious, using तुम्ही rather than तू, common spoken contractions, ordinary Marathi vocabulary where it is effortless, and conventional English service vocabulary where real speakers naturally use it. Avoid strongly regional dialect features unless the product deliberately targets that region.**

This manual therefore does **not** teach Varhadi, Malvani, Ahirani/Khandeshi or other regional varieties as the default. It aims for a form that should be broadly intelligible and socially neutral across Mumbai, Pune, Nagpur, Nashik and other Maharashtra cities while still sounding recognisably spoken rather than literary.

One implementation detail matters immediately: Marathi frequently marks the speaker's gender in first-person verb forms. A male-coded agent says `मी बघतो`, `मी सांगतो`, `मी करतो`; a female-coded agent says `मी बघते`, `मी सांगते`, `मी करते`. The examples below generally use a **male-coded voice** for consistency. A female voice should systematically substitute feminine forms rather than alternate unpredictably.

Roman transliteration below is intentionally practical rather than academic: `tumhi`, `aahe`, `bara`, `thik`, `mhanje`, `zhalay`, `sanga`. Real Romanised Marathi has no single standard spelling; corpus research explicitly identifies spelling variation as an inherent feature of Romanised Marathi. citeturn19view0

## How natural spoken Marathi actually works

Marathi's broad default order is subject–object–verb, although the language allows considerable flexibility. Subjects can disappear when they are understood from context, objects normally precede verbs, and adverbial material is comparatively mobile. citeturn18view5 That flexibility is important for a voice agent because natural Marathi often omits information that written prose laboriously repeats.

Compare:

| Written / formal Marathi | Natural spoken Marathi | English |
|---|---|---|
| मी ते तपासत आहे. | मी ते बघतोय. / मी चेक करतोय. | I'm checking it. |
| मला ते समजले नाही. | मला ते समजलं नाही. | I didn't understand it. |
| तुम्ही काय म्हणत आहात? | तुम्ही काय म्हणताय? | What are you saying? |
| आपले नाव काय आहे? | तुमचं नाव काय? | What's your name? |
| आपण कोणत्या कारणास्तव दूरध्वनी केला आहे? | कशाबद्दल कॉल केला होता? | What are you calling about? |
| कृपया काही काळ प्रतीक्षा करावी. | जरा थांबा, मी बघतो. | Just a moment, I'll check. |
| आपणास कोणत्या प्रकारची मदत आवश्यक आहे? | कशात मदत हवी आहे? | What do you need help with? |
| मला याविषयी माहिती उपलब्ध नाही. | मला याबद्दल माहित नाही. | I don't know about that. |
| कृपया आपला संपर्क क्रमांक प्रदान करावा. | तुमचा फोन नंबर सांगाल का? | Could you give me your phone number? |
| कृपया पुनरुच्चार करावा. | पुन्हा सांगाल का? | Could you say that again? |
| आपली विनंती नोंदविण्यात आली आहे. | तुमची request नोंदवली आहे. | Your request has been recorded. |
| आपल्या विनंतीवर प्रक्रिया सुरू आहे. | तुमच्या request वर काम सुरू आहे. | We're working on your request. |
| सदर उत्पादन सध्या उपलब्ध नाही. | हे product सध्या available नाही. | This product isn't available right now. |
| आपले देयक प्राप्त झाले आहे. | तुमचं payment मिळालंय. | We've received your payment. |
| आपला परतावा प्रक्रियेत आहे. | तुमचा refund process मध्ये आहे. | Your refund is being processed. |
| आपली भेट निश्चित करण्यात आली आहे. | तुमची appointment confirm झाली आहे. | Your appointment is confirmed. |
| आम्ही आपल्याशी पुनः संपर्क साधू. | आम्ही पुन्हा call करू. | We'll call you again. |
| क्षमस्व, आपले म्हणणे मला आकलन झाले नाही. | माफ करा, नीट समजलं नाही. | Sorry, I didn't quite understand. |
| आपण सांगितलेली माहिती अचूक आहे काय? | ही माहिती बरोबर आहे ना? | This information is correct, right? |
| आणखी काही सहाय्य आवश्यक आहे काय? | आणखी काही मदत हवी आहे का? | Anything else I can help with? |

The contrast is not that the left-hand forms are grammatically wrong. Most are perfectly grammatical. The problem is **register**: they sound like notices, forms, government prose or written customer-service copy when rendered aloud. The old spoken-Marathi teaching tradition explicitly prioritised short conversational situations and high-frequency vocabulary over translation-based written forms, which remains exactly the right design principle for voice AI. citeturn18view3

**Contraction and reduction are essential.** Standard spoken Marathi commonly fuses forms involving `आहे`: teaching descriptions give `मी करतो आहे → मी करतोय`, and spoken neuter endings commonly surface as `-ं`, as in `हलते → हलतं`. citeturn18view9 For a modern agent, the highest-value reductions are:

| More written | Spoken-friendly |
|---|---|
| करत आहे | करतोय / करतेय |
| म्हणत आहात | म्हणताय |
| येत आहात | येताय |
| जात आहात | जाताय |
| झाले आहे | झालंय |
| केले आहे | केलंय |
| मिळाले आहे | मिळालंय |
| समजले | समजलं |
| झाले | झालं |
| केले | केलं |
| सांगितले | सांगितलं |
| पाहिले | पाहिलं |
| राहिले | राहिलं |
| असे आहे | असं आहे |
| तसे | तसं |
| कसे | कसं |
| काय झाले? | काय झालं? |

Do not apply reductions mechanically everywhere. `आहे` itself remains extremely common. The objective is not to erase auxiliaries; it is to avoid consistently pronouncing fully expanded written forms when native conversational speech normally contracts them.

**Pronouns encode social distance.** Spoken-Marathi grammars distinguish familiar `तू`, respectful/plural `तुम्ही`, and more honorific `आपण`, while noting that honorific second-person `आपण` has declined in everyday usage. citeturn18view4 For a general customer-service agent:

**Default:** `तुम्ही / तुम्हाला / तुमचं / तुमचा / तुमची`

**Do not default to:** `तू / तुला / तुझं`

**Use `आपण` selectively:** institutional, ceremonial or deliberately formal brand voice.

Thus:

`आपण आपला संपर्क क्रमांक सांगू शकाल काय?`

is grammatical but heavier than:

`तुमचा फोन नंबर सांगाल का?`

And:

`तुझा नंबर सांग.`

is much too familiar for an unknown customer.

Respectful Marathi already has polite verbal forms such as `घ्या`, `या`, `बोला`; the spoken grammar distinguishes them structurally from familiar `घे`, `ये`, `बोल`. citeturn18view7 This means an agent does not need to add `कृपया` to every instruction to remain polite.

**Questions are usually structurally simple.** Yes/no questions can be formed by adding `का` to the proposition, while information questions put the question word where the requested information would occur. citeturn18view6 Thus:

`तुम्ही payment केलंय का?`

`delivery उद्या येईल का?`

`तुम्हाला कोणती date हवी आहे?`

`तुमचा order number काय आहे?`

`appointment किती वाजता आहे?`

Conversationally, a respectful request is often better as a question:

`नंबर सांगा.` → perfectly possible, moderately direct.

`नंबर सांगाल का?` → warmer.

`जरा नंबर सांगाल का?` → softer still, although sometimes unnecessarily deferential.

`कृपया आपला संपर्क क्रमांक प्रदान करावा.` → written/administrative.

**Word-dropping is normal when context makes material obvious.** The grammar explicitly permits omission of understood subjects. citeturn18view5 In dialogue, this expands naturally into contextual ellipsis:

Customer: `उद्या appointment मिळेल का?`  
Agent: `हो, दुपारी तीनची आहे.`

There is no reason to say:

`होय, उद्या दुपारी तीन वाजताची appointment उपलब्ध आहे.`

Similarly:

Customer: `Payment झालं.`  
Agent: `हो, दिसतंय.`

is often better than:

`होय, तुमचे payment यशस्वीरित्या पूर्ण झालेले मला प्रणालीमध्ये दिसत आहे.`

**Natural Marathi prefers one interactional move at a time.** A spoken agent should acknowledge, answer, and ask the next question rather than delivering a paragraph. This also aligns with general conversation-design guidance: confirmations should establish shared understanding without belabouring what the user just said, and explicit confirmations should be reserved mainly for consequential or error-prone information such as names, addresses and irreversible actions. citeturn23view0

**Politeness should come from phrasing and prosody, not ornamental vocabulary.**

Useful softeners:

`जरा` — just / a little  
`एकदा` — once, as a gentle request  
`सांगाल का?` — could you tell me?  
`द्याल का?` — could you give me?  
`शक्य असेल तर` — if possible  
`चालेल का?` — would that work?  
`बघूया` — let's see  
`माफ करा` — sorry / excuse me

Less useful as repeated defaults:

`कृपया` every turn  
`महोदय / महोदया`  
`क्षमस्व` every error  
`आपणास विनंती करण्यात येते`  
`सदर`  
`उपरोक्त`  
`प्रदान करावे`  
`अवगत`  
`सूचित करण्यात येत आहे`

**Agreement is not just `हो`.** Good choices depend on what is being acknowledged:

`हो.` — yes / I'm listening  
`बरं.` — okay / right / transition  
`बरोबर.` — correct  
`ठीक आहे.` — okay  
`चालेल.` — works for me / acceptable  
`समजलं.` — understood  
`मिळालं.` — got the information  
`हो, दिसतंय.` — yes, I can see it  
`ठीक, बघतो.` — okay, I'll check  
`अच्छा.` — oh/I see; urban, Hindi-influenced  
`हो का?` — oh really?/is that so? rather than plain yes

Agreement can also be partial:

`हो, ते बरोबर आहे.`

Disagreement should normally be softened:

`नाही, तसं दिसत नाहीये.`

`बहुतेक इथे थोडा फरक आहे.`

`एक मिनिट, माझ्याकडे वेगळी माहिती दिसतेय.`

rather than:

`तुम्ही चुकीचे आहात.`

**Rhythm matters.** A good service turn often sounds like:

`बरं. एक मिनिट, मी order बघतो.`

[pause]

`हो, मिळाला. Delivery उद्या दिसतेय.`

rather than:

`ठीक आहे सर, आपण दिलेल्या ऑर्डर क्रमांकाच्या आधारे मी आपल्या ऑर्डरची सद्यस्थिती तपासत आहे आणि कृपया आपण काही काळ प्रतीक्षा करावी.`

The second may look “professional” in text but is exactly the kind of sentence that makes synthetic speech sound synthetic.

## Core expressions, fillers and conversation markers

The expressions below are designed as a **selection library**, not a checklist to insert on every turn. Repetition is one of the fastest ways to make a voice agent sound templated. General voice-conversation guidance similarly recommends avoiding needless confirmations and verbatim repetition. citeturn23view0turn23view1

| Marathi | Natural Roman | Meaning / function | Typical use | Register |
|---|---|---|---|---|
| नमस्कार | namaskar | Hello | Safe universal opening | Neutral–polite |
| हॅलो | hello | Hello | Phone opening, urban speech | Neutral |
| बोला | bola | Go ahead / tell me | Inviting customer to continue | Neutral–polite |
| सांगा | sanga | Tell me / go ahead | Same, slightly more explicit | Neutral–polite |
| कशी मदत करू? | kashi madat karu? | How can I help? | Service opening | Neutral |
| काय झालं? | kay zhala? | What happened? | Understanding a problem | Neutral; warm |
| कशाबद्दल मदत हवी आहे? | kashabaddal madat havi aahe? | What do you need help with? | Open enquiry | Neutral |
| हो | ho | Yes / yes, listening | Answer or backchannel | Universal |
| हं | hmm / haan | Mm-hm | Light listening/thinking | Conversational |
| बरं | bara | Okay / well / right | Ack, transition, acceptance | Neutral |
| ठीक | thik | Okay | Short acknowledgement | Neutral |
| ठीक आहे | thik aahe | Okay / all right | Agreement, closure | Neutral |
| बरोबर | barobar | Correct / right | Confirmation | Neutral |
| अगदी बरोबर | agdi barobar | Exactly | Strong agreement | Neutral |
| चालेल | chalel | That works / okay | Accepting a proposed option | Neutral |
| हो, चालेल | ho, chalel | Yes, that'll work | Accepting time/date etc. | Neutral |
| समजलं | samajla | Understood | Showing comprehension | Neutral |
| कळलं | kalala | Got it / understood | Slightly conversational | Neutral |
| मिळालं | milala | Got it / received it | Number/data/document received | Neutral |
| हो का? | ho ka? | Oh really? / is that so? | New/surprising information | Conversational |
| अच्छा | accha | Oh / I see / okay | Urban/Hindi-influenced ack | Conversational |
| अरे | are | Hey / oh | Surprise, calling attention | Familiar |
| अरेरे | arere | Oh no / that's unfortunate | Sympathy/small mishap | Conversational |
| खरंच? | kharach? | Really? | Genuine surprise | Neutral |
| असं का? | asa ka? | Is that so? | Receptive response | Neutral |
| मग | mag | Then / so / well then | Consequence or transition | Very common |
| म्हणजे | mhanje | Meaning / I mean / so you mean | Reformulation, clarification | Very common |
| ना | na | right?/please/you know | Tag, softener, shared assumption | Conversational |
| काय | kay | what | Information question | Universal |
| का | ka | question marker / why contextually | Yes/no question | Universal |
| जरा | jara | a little / just | Request softener | Very common |
| एकदा | ekda | once / just | Gentle request | Neutral |
| एक मिनिट | ek minute | One minute | Hold/checking | Conversational |
| एक क्षण | ek kshan | One moment | Slightly more polished hold | Neutral–polite |
| थोडं थांबा | thoda thamba | Wait a little | Short wait | Neutral |
| जरा थांबा | jara thamba | Just a moment | Hold | Neutral |
| मी बघतो | mi baghto | I'll check / look | Checking | Neutral |
| मी चेक करतो | mi check karto | I'll check | Modern service speech | Neutral urban |
| बघूया | baghuya | Let's see | Thinking/searching collaboratively | Neutral |
| पाहूया | pahuya | Let's see | Same, slightly less colloquial | Neutral |
| माफ करा | maaf kara | Sorry / excuse me | Apology, repair | Neutral–polite |
| सॉरी | sorry | Sorry | Casual urban apology | Casual–neutral |
| काही हरकत नाही | kahi harkat nahi | No problem | Reassurance | Neutral |
| काही प्रॉब्लेम नाही | kahi problem nahi | No problem | Urban mixed speech | Conversational |
| चालेल, काही हरकत नाही | chalel, kahi harkat nahi | That's fine, no problem | Reassuring | Neutral |
| नीट समजलं नाही | neet samajla nahi | I didn't quite understand | Repair | Neutral |
| पुन्हा सांगाल का? | punha sangal ka? | Could you repeat that? | Repair | Polite-neutral |
| परत एकदा सांगाल का? | parat ekda sangal ka? | Could you say that once more? | Repair | Neutral |
| थोडं हळू सांगाल का? | thoda halu sangal ka? | Could you say it a little slower? | Numbers/names | Polite |
| नाव spell कराल का? | naav spell karal ka? | Could you spell the name? | Name confirmation | Urban/service |
| शेवटचे चार digits सांगाल का? | shevatche chaar digits sangal ka? | Last four digits, please? | Number confirmation | Urban/service |
| म्हणजे तुम्ही म्हणताय की… | mhanje tumhi mhanatay ki… | So you're saying… | Clarifying | Neutral |
| बरोबर समजलो का…? | barobar samajlo ka…? | Have I understood correctly…? | High-value clarification | Polite |
| एक गोष्ट confirm करू? | ek goshta confirm karu? | Can I confirm one thing? | Transition to confirmation | Mixed-neutral |
| ठीक, पुढे सांगा | thik, pudhe sanga | Okay, go ahead | Inviting continuation | Neutral |
| हो, सांगा | ho, sanga | Yes, go ahead | Listening | Neutral |
| तुम्ही बोला | tumhi bola | Go ahead | After interruption/overlap | Respectful |
| आधी तुम्ही बोला | aadhi tumhi bola | You go first | Repairing overlap | Warm–polite |
| माफ करा, मध्ये बोललो | maaf kara, madhye bollo | Sorry, I interrupted | Overlap repair | Natural polite |
| ठीक, मग… | thik, mag… | Okay, then… | Topic transition | Neutral |
| बरं, आता… | bara, aata… | Right, now… | Next step | Neutral |
| मग असं करूया… | mag asa karuya… | Then let's do this… | Proposing solution | Collaborative |
| एवढंच ना? | evdhach na? | That's all, right? | Confirming scope | Conversational |
| बरोबर ना? | barobar na? | Right? | Soft confirmation | Conversational |
| धन्यवाद | dhanyavaad | Thank you | Meaningful service moment/closing | Neutral–polite |
| थँक यू | thank you | Thank you | Urban mixed speech | Neutral |
| बरं, धन्यवाद | bara, dhanyavaad | All right, thank you | Closing | Natural |
| ठीक आहे, नमस्कार | thik aahe, namaskar | All right, goodbye | Safe service close | Polite |
| पुन्हा काही लागलं तर call करा | punha kahi lagla tar call kara | Call again if you need anything | Warm close | Neutral mixed |

Some of these expressions carry substantially more pragmatic information than their dictionary translation suggests.

**हो — ho**

Literal/basic: yes.  
Conversationally: yes, I agree; yes, I'm listening; go on; acknowledgement.

Natural:

Customer: `माझं payment काल झालं.`  
Agent: `हो. Transaction ID आहे का तुमच्याकडे?`

Avoid five consecutive `हो`s while the customer speaks. Human backchannels vary.

**हो का? — ho ka?**

Literal structure: “yes + question marker”.  
Conversational meaning: “Oh really?”, “Is that so?”, “Oh, did it?”

Customer: `मला अजून delivery मिळाली नाही.`  
Agent: `हो का? एक मिनिट, मी status बघतो.`

Appropriate for mild new information. Less good for serious harm:

Customer: `माझ्या account मधून पैसे दोनदा गेले.`  
Weak: `हो का?`  
Better: `अच्छा, समजलं. एक मिनिट, मी दोन्ही transactions बघतो.`

A rising, breezy `हो का?` can otherwise sound as though the agent is merely curious.

**बरं — bara**

Literal lexical roots relate to good/well, but conversationally `बरं` functions as “okay”, “right”, “well”, acceptance, or a transition.

`बरं. मग उद्याची appointment बघूया.`

Excellent voice-agent marker because it acknowledges and moves the conversation.

**बरं का — bara ka**

Can mean roughly “okay?”, “all right?”, “remember that”, often with interpersonal emphasis. Depending on intonation it can sound elder-to-younger, advisory or mildly admonitory.

`औषध वेळेवर घ्या, बरं का?`

Natural there.

Less good for transactional service:

`तुमचा OTP सांगा, बरं का?`

This can sound oddly patronising. Prefer `OTP सांगाल का?`

**ठीक आहे — thik aahe**

Normal and safe. The problem is frequency, not correctness.

Bad rhythm:

Customer: `नाव सागर.`  
Agent: `ठीक आहे.`  
Customer: `पुणे.`  
Agent: `ठीक आहे.`  
Customer: `उद्या हवंय.`  
Agent: `ठीक आहे.`

Better:

`सागर, बरोबर.`  
`हो, पुणे.`  
`बरं. उद्याची availability बघतो.`

Google's conversation-design guidance independently makes the same general point: avoid belabouring confirmations and especially meaningless forms equivalent to “OK, yes”. citeturn23view0

**बरोबर — barobar**

Literal and conversational: correct/right.

Excellent for explicit confirmation:

`नंबर ९८२०…४७१२, बरोबर?`

Less natural as a response to emotion:

Customer: `खूप त्रास झाला मला.`  
Poor: `बरोबर.`  
Better: `हो, समजतंय. त्रास झाला आहे.`

**अच्छा — accha**

A Hindi/Urdu-influenced discourse marker widely intelligible in Maharashtra's multilingual urban environment. Marathi-English research also finds some Hindi-Marathi mixing alongside much larger Marathi-English mixing. citeturn19view0

`अच्छा, म्हणजे payment झालं पण confirmation आलं नाही.`

This can sound completely natural for some speakers, but repeated `अच्छा… अच्छा… अच्छा…` pushes the persona towards Hindi conversational style. Use it as an optional variant, not the agent's primary acknowledgement.

**अरे — are**

“Oh!”, “hey!”, “come on!” depending intonation.

Very natural between friends:

`अरे, राहू दे.`

Usually unsuitable for an unknown customer. It collapses social distance.

**अरेरे — arere**

“Oh no”, sympathetic surprise.

`अरेरे, parcel परत गेलं का?`

Can work with a warm brand persona for small mishaps, but can sound theatrical or patronising in serious complaints. Prefer `अच्छा, समजलं` or `हे त्रासदायक झालं` for consequential problems.

**मग — mag**

Core meanings include “then” and “so”; conversationally it is one of Marathi's most useful transition devices.

`मग उद्या करूया.`  
`मग आता काय करू शकतो ते बघतो.`  
`ठीक. मग address सांगा.`

It gives the dialogue forward motion.

**म्हणजे — mhanje**

Literally “meaning / that means”. Conversation functions include reformulation, self-repair and checking interpretation.

`म्हणजे तुम्हाला booking cancel नाही करायची, date change करायची आहे. बरोबर?`

Very useful for repair. Do not let it become a filler before every sentence.

**ना — na**

Highly context-sensitive.

Shared expectation:

`उद्या येणार ना?`

Soft request/coaxing:

`जरा नंबर सांगा ना.`

Appeal for agreement:

`तेच booking आहे ना?`

For a service agent, use sparingly. `ना` makes language warmer but also more interpersonal. Repeating it can sound cajoling:

`OTP सांगा ना.`  
`एकदा करा ना.`  
`थांबा ना.`

That is too familiar or pressuring for many service contexts.

**का — ka**

A highly productive yes/no question marker: spoken-Marathi grammatical descriptions explicitly derive yes/no questions by adding `का` to statements. citeturn18view6

`Payment झालंय का?`  
`उद्या चालेल का?`  
`मी booking करू का?`

It is also part of expressions such as `हो का?`, whose pragmatic meaning is not simply the sum of “yes + question”.

**काय — kay**

Basic “what”.

`नाव काय आहे?`  
`Problem काय येतोय?`  
`Order number काय आहे?`

Avoid bare `काय?` when recognition fails; depending on intonation it can sound abrupt.

Better:

`माफ करा, काय म्हणालात?`

Better still:

`माफ करा, शेवटचा भाग पुन्हा सांगाल का?`

**एक मिनिट — ek minute**

Very common in contemporary mixed conversation. Naturally occurring Marathi media transcripts contain constructions equivalent to `एक minute, मी check करतो`, illustrating that both the English time noun and English `check` integrate readily into Marathi conversation. citeturn21search0turn21search3

`एक मिनिट, मी check करतो.`

For a polished service persona, vary with:

`एक क्षण.`  
`जरा थांबा.`  
`मी लगेच बघतो.`

Do not say `एक मिनिट` if the operation routinely takes several minutes and the user will experience unexplained silence.

**जरा — jara**

Lexically “a little/somewhat”; spoken descriptions list its attenuating meaning. citeturn11view4 Conversationally it is a powerful request softener:

`जरा थांबा.`  
`जरा हळू सांगाल का?`  
`जरा number पुन्हा सांगा.`

It does not magically make an insulting command polite. `जरा गप्प बसा` is still inappropriate.

**Natural hesitation for an AI**

A voice agent should sound conversational without pretending to have cognitive difficulties. Suitable occasional forms are:

`हं… एक मिनिट.`  
`बरं… बघतो.`  
`म्हणजे… तुम्हाला उद्याची date हवी आहे, बरोबर?`  
`एक सेकंद… हो, मिळालं.`

Avoid manufactured disfluency such as:

`अं… म्हणजे… हं… बरं…`

on every turn. The goal is interactional pacing, not theatrical imitation of uncertainty.

## Marathi-English code-switching: what sounds native and what sounds translated

The evidence for Marathi-English mixing is strong. Urban sociolinguistic work describes the mix as systematic and often unmarked, while the *My Boli* project assembled ten million mixed Marathi-English social-media sentences and found considerable English switching in Marathi posts. citeturn18view8turn19view0 Research on goal-oriented conversational systems in multilingual India likewise argues that code-mixed data is necessary because speakers routinely switch languages during conversation. citeturn1search27

The practical implication is important:

> **Do not optimise for the percentage of words that are Marathi. Optimise for whether the phrase is one a Marathi speaker would naturally choose in that domain.**

Current Marathi digital usage gives direct examples of this integration. Marathi materials routinely use `अपॉइंटमेंट कन्फर्म करा`; WhatsApp's own Marathi material uses `लाईव्ह लोकेशन शेअर करा`; contemporary Marathi technology and service writing uses terms such as OTP, UPI, customer support, request and refund rather than systematically replacing every term with a Sanskritised equivalent. citeturn21search14turn21search15turn15search21turn15search17

**High-value English nouns that should normally remain available to the agent**

| Domain | Natural forms |
|---|---|
| Scheduling | appointment, booking, slot, date, time, reschedule, cancel, confirmation |
| Commerce | order, product, stock, offer, discount, exchange |
| Payments | payment, UPI, card, transaction, OTP, refund |
| Logistics | delivery, pickup, address, location |
| Communication | call, message, WhatsApp, email, SMS |
| Digital service | website, app, application, account, login, update, link |
| Customer service | customer care, support, service, complaint, request, issue, problem |
| Operational | status, process, confirm, check, update |

This does **not** mean replacing perfectly ordinary Marathi:

`नाव` is normally better than “name”.  
`पत्ता` is perfectly natural alongside `address`.  
`पैसे` remains natural alongside `payment`.  
`दुकान` remains natural alongside `store`.  
`वेळ` remains natural alongside `time`.

A native-sounding system mixes by **domain convention**, not randomly.

Compare:

| Over-pure / translated | Natural mixed Marathi |
|---|---|
| आपले आरक्षण झाले आहे काय? | तुमचं booking झालंय का? |
| देयक अदा झाले आहे काय? | payment झालंय का? |
| मागणी नोंदविली आहे का? | order place झाली आहे का? / order केली आहे का? |
| संदेश पाठवा | message करा / message पाठवा |
| भेट निश्चित करा | appointment confirm करा |
| परताव्याची प्रक्रिया सुरू होईल | refund process सुरू होईल |
| मी दूरध्वनी करीन | मी call करतो. |
| आपले स्थान सामायिक करा | location share करा. |
| संकेतस्थळावर भेट द्या | website वर जा. |
| इलेक्ट्रॉनिक पत्र पाठवा | email करा. |
| दूरध्वनी क्रमांक | phone number / mobile number |
| ग्राहक सहाय्य केंद्र | customer care / customer support |
| अद्ययावत करा | update करा. |
| खाते उघडा | account उघडा. |
| अर्ज सादर करा | application submit करा. |

Some “pure” versions are appropriate in formal writing; that is precisely why they can sound wrong in a phone conversation.

**How English nouns enter Marathi grammar**

A highly productive pattern is:

`English noun/stem + Marathi light verb`

Examples:

`call करा`  
`message करा`  
`booking करा`  
`confirm करा`  
`cancel करा`  
`reschedule करा`  
`check करा`  
`update करा`  
`share करा`  
`submit करा`

These verbs then inflect as Marathi verbs:

`मी call करतो.`  
`ती call करते.`  
`त्याने call केला.`  
`तिने call केला.`  
`आपण call करूया.`  
`मी location share केली.`

Another common pattern combines an English nominal concept with Marathi `होणे`:

`payment झालं.`  
`booking झाली.` / `booking झालं.`  
`confirmation आलं.`  
`update झालं.`  
`refund झाला.`  
`delivery झाली.`

The exact gender assigned to English loans can vary between speakers and collocations. Code-mixed corpora themselves show substantial spelling and grammatical variation, so production systems should learn frequent **whole collocations** rather than assume that every English noun has one mechanically predictable Marathi gender. citeturn19view0

That observation matters for several examples in the question.

**`booking केली आहे का?`**

Natural: yes, especially when `booking` is treated as feminine.

Often even smoother:

`Booking झालंय का?`

The second avoids asking who made it and reduces agreement complexity.

**`payment झालं का?`**

Very natural. A contemporary Marathi media search even yields the exact construction `पेमेंट झालं का?`, and payment terminology is routine in current Marathi digital-service discourse. citeturn14search0turn15search21

Preferred conversational version:

`Payment झालंय का?`

**`order place केला का?`**

Understandable, but not the safest pan-Marathi template. Contemporary Marathi usage also shows `ऑर्डर प्लेस झाली`, indicating that `order` agreement does not necessarily follow the masculine pattern implied by `केला`. citeturn14search6

Safer options:

`तुम्ही order place केली आहे का?`  
`Order place झाली आहे का?`  
`Order केली आहे का?`

For an agent, the second is especially useful because it avoids disputable loanword gender in the user's action.

**`message करा`**

Completely plausible mixed-Marathi structure:

`Details WhatsApp वर message करा.`

Also natural:

`Message पाठवा.`

**`appointment confirm करतो`**

Natural structure, but the speaker's gender matters:

Male: `मी appointment confirm करतो.`  
Female: `मी appointment confirm करते.`

Current Marathi material directly uses `अपॉइंटमेंट कन्फर्म करा`. citeturn21search14

**`refund process होईल`**

Understandable and service-natural.

Better depending on intended meaning:

`Refund process सुरू होईल.`  
`Refund process झालाय.`  
`Refund ची process सुरू आहे.`

Do not translate it automatically into something such as `परतफेड प्रक्रिया कार्यान्वित करण्यात येईल` unless the product deliberately wants administrative Marathi.

**`मी call करतो`**

Highly natural urban mixed Marathi.

`मी तुम्हाला संध्याकाळी call करतो.`

**`location share करा`**

Natural and directly reflected in contemporary Marathi product language; even WhatsApp's Marathi pages use the equivalent of “live location share”. citeturn21search2turn21search15

**The critical rule for Hindi influence**

Hindi-derived discourse material is not automatically “bad Marathi”. Maharashtra is multilingual, and Marathi corpora do contain Hindi-Marathi mixing. citeturn19view0 The failure mode is not the occasional `अच्छा`; it is allowing the **underlying grammar to become Hindi**.

Avoid:

`आप मुझे नंबर बताइए.`  
`कोई प्रॉब्लेम नहीं.`  
`आपका payment हो गया है.`

Prefer:

`तुमचा नंबर सांगाल का?`  
`काही प्रॉब्लेम नाही.` / `काही हरकत नाही.`  
`तुमचं payment झालंय.`

English borrowing with Marathi grammar usually sounds much more authentically Maharashtrian than Hindi grammar carrying a few Marathi words.

## Voice-agent turn-taking, confirmation and interaction design

A good Marathi voice agent needs to manage not only grammar but **social timing**. Conversation-design research distinguishes implicit confirmation from explicit confirmation and recommends not repeating everything the user said merely to demonstrate recognition. Explicit confirmation is most valuable for high-risk information such as names, addresses and consequential actions. citeturn23view0 Error handling should likewise be context-specific, concise and varied rather than repeating the identical prompt verbatim after recognition failure. citeturn23view1

A practical turn should usually have this shape:

> **Acknowledge → act/answer → ask only the next necessary thing.**

Customer: `माझी delivery अजून आली नाही.`

Good:

`अच्छा, एक मिनिट. Order number सांगाल का?`

Not:

`ठीक आहे. आपण असे सांगत आहात की आपण केलेल्या order ची delivery अद्याप आपल्याला प्राप्त झालेली नाही. या समस्येचे निराकरण करण्यासाठी कृपया मला आपला order number प्रदान करा.`

The second repeats the customer's entire statement, adds no useful understanding, and delays the next step.

**Acknowledgement library**

Use according to context rather than randomly:

| Function | Natural alternatives |
|---|---|
| Basic listening | हो · हं · सांगा · हो, बोला |
| Acceptance | बरं · ठीक · ठीक आहे · चालेल |
| Correctness | बरोबर · अगदी बरोबर |
| Understanding | समजलं · कळलं · अच्छा, समजलं |
| Information received | मिळालं · हो, मिळाला · ठीक, नोंदवलं |
| Mild surprise | हो का? · असं का? · खरंच? |
| Sympathy | अरेरे · अच्छा, समजलं · हे त्रासदायक झालं |
| Moving forward | मग… · बरं, मग… · ठीक, आता… |
| Starting an action | बघतो · मी चेक करतो · एक मिनिट, बघतो |
| Collaborative thinking | बघूया · पाहूया · मग असं करूया |

Do not choose acknowledgements blindly. `बरोबर` is good after a fact but bad after `मला खूप त्रास झाला`. `हो का?` is appropriate for mildly surprising information but weak after a serious financial problem. `चालेल` means acceptance and should not acknowledge a complaint.

**While checking**

Best:

`एक मिनिट, मी बघतो.`  
`जरा थांबा, status चेक करतो.`  
`हो, मी details बघतोय.`  
`एक क्षण. Order उघडतो.`  
`हं… बघूया.`

After the check, announce the result quickly:

`हो, दिसतोय order.`  
`मिळाला.`  
`हो, इथे status दिसतोय.`

Do not leave several seconds of unexplained silence if your platform can avoid it.

**Interrupting politely**

`माफ करा, एक गोष्ट विचारू?`  
`मध्येच थांबवतोय, पण order number सांगाल का?`  
`एक सेकंद—इथे एक detail confirm करायची आहे.`

The second is polite but slightly heavier; use only when genuinely interrupting.

**When the customer interrupts**

Stop rather than competing for the floor.

Agent: `हो, तुम्ही बोला.`  
Agent: `सांगा.`  
Agent: `हो हो, आधी तुम्ही बोला.`

Then continue:

`ठीक. तुम्ही म्हणत होतात की payment दोनदा झालं, बरोबर?`

**After accidentally speaking over them**

`माफ करा, मध्ये बोललो. तुम्ही पूर्ण करा.`

or simply:

`सॉरी, तुम्ही बोला.`

The short version is often more natural.

**Repeating a phone number**

Do not demand the complete number repeatedly if only one chunk is uncertain.

`शेवटचे चार digits पुन्हा सांगाल का?`

`९८२० नंतर काय होतं?`

`मला middle चे दोन digits नीट ऐकू आले नाहीत. ते पुन्हा सांगाल का?`

That is more conversational and less frustrating than restarting the entire collection.

**Confirming a number**

User: `9820456712.`  
Agent: `९८२० ४५६ ७१२, बरोबर?`

For long digit sequences, speak in natural chunks rather than machine-gunning ten digits at one pace.

**Confirming a name**

`तुमचं नाव सागर पाटील, बरोबर?`

If unclear:

`सागर—S A G A R, बरोबर?`

or:

`आडनाव एकदा spell कराल का?`

For difficult names, explicit confirmation is worth the extra turn; general conversation-design guidance specifically identifies names and similar error-sensitive parameters as cases where confirmation may be justified. citeturn23view0

**Confirming dates**

Avoid ambiguous purely numeric dates when possible.

`म्हणजे १२ ऑक्टोबर, सोमवार. बरोबर?`

For appointment changes:

`ठीक. मग १२ ऑक्टोबरची appointment cancel करून १४ ऑक्टोबरला करू?`

This combines old action and new action in one concise confirmation.

**Confirming addresses**

Do not read the entire address back unless necessary.

`Baner, Pune—411045. बरोबर?`

If house number is high-risk:

`Flat ८०३, Green Heights, बरोबर? बाकी address मिळालाय.`

**Handling silence**

First recovery:

`हॅलो? मी ऐकतोय. सांगा.`

Or if a question was asked:

`तुम्हाला उद्या चालेल का?`

Do not immediately blame the customer with `तुम्ही काही बोलला नाहीत` or repeatedly claim `मला तुमचा आवाज येत नाही` when silence may simply mean they are thinking. General voice-design guidance recommends rephrasing no-input prompts rather than assuming why no response occurred. citeturn23view1

Second attempt:

`उद्या नसेल चालत तर दुसरी date बघू शकतो.`

This adds useful support rather than mechanically repeating the first prompt.

**Changing topic**

`बरं. आता payment बघूया.`  
`ठीक. Delivery बद्दल एक detail विचारतो.`  
`मग पुढचं—address confirm करूया.`  
`हो. आता appointment ची date बघतो.`

**Correcting a misunderstanding**

Customer: `Cancel नाही, reschedule करायचंय.`  
Agent: `अच्छा, बरोबर. Cancel नाही—date change करायची आहे. कोणती date पाहिजे?`

Do not apologise for ten seconds.

**When the agent did not understand**

First failure:

`माफ करा, शेवटचा भाग नीट समजला नाही. पुन्हा सांगाल का?`

Second:

`Phone number म्हणालात की order number?`

Third, if needed:

`एकदा order number हळू सांगाल का?`

Conversation-design guidance specifically recommends a concise initial reprompt, then escalating useful detail rather than repeating the same wording over and over. citeturn23view1

**When the customer changes their mind**

Customer: `राहू द्या, cancel नको.`  
Agent: `ठीक आहे, cancel करत नाही.`

Not:

`आपल्याला खात्री आहे का की आपण cancellation प्रक्रिया रद्द करू इच्छिता?`

Unless an irreversible action has already progressed, respect the change directly. Google similarly recommends allowing users to abandon intents without unnecessary double-checking when little would be lost. citeturn22view0

**Ending**

When the task is complete:

`झालं. Appointment उद्या चार वाजताची confirm आहे. आणखी काही मदत हवी आहे का?`

Customer: `नाही.`  
Agent: `ठीक आहे. धन्यवाद. नमस्कार.`

Good conversation design confirms completion and then provides closure rather than continuing unnecessarily. citeturn22view0

## Good Marathi versus bad Marathi: voice-agent benchmark set

The following is deliberately prescriptive. The “bad” versions include sentences that may be grammatically valid Marathi but fail the **spoken-native-service** test because they are translated, bureaucratic, Hindi-shaped, over-polite, excessively repetitive, badly code-mixed or unnecessarily long. The natural versions apply the spoken grammar, code-mixing and conversation-design evidence above: contextual omission, respectful `तुम्ही`, colloquial reductions, situational rather than literal translation, conventional English borrowing, and minimal confirmation. citeturn18view3turn18view5turn18view6turn18view8turn19view0turn23view0

| # | Situation | Bad / robotic Marathi | Why it sounds wrong | Natural native Marathi | English meaning |
|---:|---|---|---|---|---|
| 1 | Greeting | नमस्कार महोदय, आपल्या सेवेसाठी मी उपस्थित आहे. | Ceremonial | नमस्कार! कशी मदत करू? | Hello, how can I help? |
| 2 | Greeting | आपले आमच्या ग्राहक सहाय्य केंद्रात स्वागत आहे. | IVR/script copy | नमस्कार. सांगा, कशाबद्दल मदत हवी आहे? | Hello. What can I help with? |
| 3 | Greeting | शुभ दिवस, मी आपल्याला कशाप्रकारे सहाय्य करू शकतो? | Literal corporate English | नमस्कार. काय मदत करू? | Hello. How can I help? |
| 4 | Opening | कृपया आपली समस्या कथन करा. | Bureaucratic | सांगा, काय झालं? | Tell me what happened. |
| 5 | Opening | आपल्या दूरध्वनी करण्याचे प्रयोजन काय आहे? | Written/legal | कशाबद्दल call केला होता? | What are you calling about? |
| 6 | Opening | मी आपली कशाप्रकारे मदत करू शकतो? | Grammatically fine but stiff if repeated | कशी मदत करू? | How can I help? |
| 7 | Opening | बोला सर. | `sir` unnecessary by default | हो, सांगा. | Yes, go ahead. |
| 8 | Opening | हो मॅडम, सांगा मॅडम. | Repetitive title | हो, सांगा. | Yes, go ahead. |
| 9 | Opening | सागरजी, मी तुमची कशी मदत करू सागरजी? | Name overuse | सागर, सांगा. कशी मदत करू? | Sagar, how can I help? |
| 10 | Opening | आप मुझे बताइए क्या problem है. | Hindi grammar | सांगा, काय problem येतोय? | Tell me what the problem is. |
| 11 | Name | कृपया आपले शुभनाम सांगावे. | Literary/formal | तुमचं नाव सांगाल का? | Could you tell me your name? |
| 12 | Name | आपले पूर्ण नाव प्रदान करा. | Translationese | पूर्ण नाव सांगाल का? | Could you give me your full name? |
| 13 | Name | तुम नाम बताओ. | Hindi + too familiar | तुमचं नाव काय? | What's your name? |
| 14 | Name | आपले नाव मी योग्य प्रकारे श्रवण केले नाही. | Absurdly written | नाव नीट ऐकू आलं नाही. पुन्हा सांगाल का? | I didn't catch the name. |
| 15 | Name | कृपया spelling चे उच्चारण करा. | Bad hybrid | नाव spell कराल का? | Could you spell the name? |
| 16 | Phone | आपला दूरध्वनी क्रमांक प्रदान करावा. | Administrative | तुमचा phone number सांगाल का? | Could you give me your phone number? |
| 17 | Phone | कृपया दहा अंकी संपर्क क्रमांक सांगा. | Form-like | Mobile number सांगाल का? | Could you give me your mobile number? |
| 18 | Phone | आपका मोबाइल नंबर क्या है? | Hindi | तुमचा mobile number काय आहे? | What's your mobile number? |
| 19 | Phone | कृपया संपूर्ण क्रमांकाची पुनरावृत्ती करा. | Too formal | शेवटचे चार digits पुन्हा सांगाल का? | Repeat the last four digits? |
| 20 | Phone | मी तुमचा नंबर पुनरुच्चारित करतो. | Literary | नंबर एकदा confirm करतो. | Let me confirm the number. |
| 21 | Address | कृपया आपला निवासस्थानाचा संपूर्ण पत्ता कथन करा. | Written/legal | Address सांगाल का? | Could you give me the address? |
| 22 | Address | आप कहाँ रहते हैं? | Hindi | तुम्ही कुठे राहता? | Where do you live? |
| 23 | Address | आपला पिन संकेतांक काय आहे? | Artificial terminology | PIN code काय आहे? | What's the PIN code? |
| 24 | Address | सदर पत्ता योग्य आहे काय? | Legal register | हा address बरोबर आहे ना? | This address is correct, right? |
| 25 | Address | मी आपण सांगितलेला संपूर्ण पत्ता आता पुन्हा सांगणार आहे. | Meta/long | Baner, Pune—411045. बरोबर? | Baner, Pune 411045, correct? |
| 26 | Acknowledge | ठीक आहे. | Fine once, robotic repeatedly | बरं. | Okay. |
| 27 | Acknowledge | हो. हो. हो. हो. | Monotonous | हो… / हं… / बरं… | Mm-hm / okay. |
| 28 | Acknowledge complaint | बरोबर. | Semantically wrong reaction | हो, समजलं. | Yes, I understand. |
| 29 | Acknowledge serious issue | हो का? | Too casual/surprised | अच्छा, समजलं. मी बघतो. | I see. I'll check. |
| 30 | Acknowledge fact | धन्यवाद आपण माहिती प्रदान केली. | Overformal | हो, मिळालं. | Got it. |
| 31 | Clarification | मला आपल्या विधानाचा अर्थ आकलन झाला नाही. | Sanskritised | नीट समजलं नाही. | I didn't quite understand. |
| 32 | Clarification | कृपया पुनरुच्चार करा. | Written | पुन्हा सांगाल का? | Could you repeat that? |
| 33 | Clarification | काय? | Abrupt | माफ करा, काय म्हणालात? | Sorry, what did you say? |
| 34 | Clarification | Repeat करा. | Command-like | एकदा पुन्हा सांगाल का? | Could you say that again? |
| 35 | Clarification | तुमचा आवाज अस्पष्ट स्वरूपात प्राप्त होत आहे. | Technical/scripted | आवाज थोडा clear नाहीये. पुन्हा सांगाल का? | The audio isn't very clear. |
| 36 | Clarification | आपण order म्हणालात का booking म्हणालात हे मला ज्ञात नाही. | Written | Order म्हणालात की booking? | Did you say order or booking? |
| 37 | Clarification | मी समजत नाही आहे. | Hindi/English calque | मला समजत नाहीये. | I don't understand. |
| 38 | Clarification | पुन्हा पूर्ण वाक्य बोला. | Too demanding | शेवटचा भाग पुन्हा सांगाल का? | Could you repeat the last part? |
| 39 | Clarification | कृपया मंद गतीने बोला. | Textbook | थोडं हळू सांगाल का? | Could you speak a little slower? |
| 40 | Clarification | आपल्या म्हणण्याची पुष्टी करण्यासाठी… | Meta-heavy | म्हणजे तुम्हाला date change करायची आहे, बरोबर? | You mean you want to change the date, right? |
| 41 | Product | आपण कोणत्या उत्पादनाविषयी चौकशी करू इच्छिता? | Formal | कोणतं product बघताय? | Which product are you looking at? |
| 42 | Product | सदर वस्तू साठ्यामध्ये उपलब्ध नाही. | Bureaucratic | हे सध्या stock मध्ये नाही. | This isn't in stock right now. |
| 43 | Product | उत्पादनाची उपलब्धता शून्य आहे. | Database language | सध्या available नाही. | It's currently unavailable. |
| 44 | Product | हा उत्पाद तुमच्यासाठी उपलब्ध होईल. | Awkward loan/grammar | हे product उद्यापासून available असेल. | It'll be available tomorrow. |
| 45 | Product | तुम्हाला कोणता प्रोडक्ट आवश्यकता आहे? | Wrong construction | तुम्हाला कोणतं product हवं आहे? | Which product do you want? |
| 46 | Order | आपल्या मागणीचा क्रमांक सांगा. | “मागणी” not domain-natural | Order number सांगाल का? | Could you give the order number? |
| 47 | Order | आपण order place केला आहे काय? | Stiff + questionable agreement | Order place झाली आहे का? | Has the order been placed? |
| 48 | Order | तुमची ऑर्डर स्थापित करण्यात आली आहे. | Literal “placed” translation | तुमची order place झाली आहे. | Your order has been placed. |
| 49 | Order | मी आपल्या order ची स्थिती निरीक्षण करतो. | Literal status checking | मी order status बघतो. | I'll check the order status. |
| 50 | Order | आपला order वर्तमानतः प्रक्रियेमध्ये आहे. | English-to-written Marathi | Order अजून process मध्ये आहे. | The order is still processing. |
| 51 | Delivery | वितरण कधी संपन्न होईल? | Formal | Delivery कधी होईल? | When will it be delivered? |
| 52 | Delivery | आपली वस्तू आज वितरित केली जाईल. | Written passive | Delivery आज होईल. | It'll be delivered today. |
| 53 | Delivery | delivery boy आपल्याशी संपर्क साधेल. | `delivery boy` can be awkward/dated | Delivery partner तुम्हाला call करेल. | The delivery partner will call you. |
| 54 | Delivery issue | आपली वस्तू आपणास प्राप्त झाली नाही असे आपण सांगत आहात. | Repeats customer | अजून delivery मिळाली नाही, बरोबर? | You haven't received it yet, right? |
| 55 | Delivery issue | असुविधेबद्दल आम्ही दिलगीर आहोत आणि आपल्या समस्येचे निवारण करण्याचा प्रयत्न करू. | Call-centre boilerplate | माफ करा, उशीर झालाय. मी status बघतो. | Sorry about the delay. I'll check. |
| 56 | Appointment | आपण भेटीची वेळ निश्चित करू इच्छिता काय? | Written | Appointment book करायची आहे का? | Do you want to book an appointment? |
| 57 | Appointment | आपल्या भेटीकरिता योग्य दिनांक निवडा. | UI copy | कोणती date चालेल? | What date works? |
| 58 | Appointment | कोणता समय आपल्यासाठी सुविधाजनक आहे? | Translationese | किती वाजता चालेल? | What time works? |
| 59 | Appointment | उद्या तीन वाजताचा कालखंड उपलब्ध आहे. | “time slot” translated badly | उद्या तीनचा slot आहे. | There's a 3 pm slot tomorrow. |
| 60 | Appointment | आपणास तीन वाजता येणे शक्य होईल काय? | Heavy | तीन वाजता जमेल का? | Can you make it at three? |
| 61 | Confirm appointment | आपली भेट निश्चित केली गेली आहे. | Written passive | Appointment confirm झाली आहे. | Your appointment is confirmed. |
| 62 | Reschedule | आपण भेट पुनर्नियोजित करू इच्छिता? | Over-pure | Appointment reschedule करायची आहे? | Do you want to reschedule? |
| 63 | Reschedule | जुनी appointment निरस्त करून नवीन appointment करावी लागेल. | Mixed bureaucratic | जुनी date बदलून नवीन date ठेवूया. | Let's change it to a new date. |
| 64 | Cancel | आपण रद्दीकरण करण्यास निश्चित आहात काय? | Literal English UI | Appointment cancel करू? | Shall I cancel it? |
| 65 | Cancel | cancellation सफल झाले आहे. | Hindi/awkward English | Appointment cancel झाली आहे. | The appointment is cancelled. |
| 66 | Payment | आपले देयक भरले गेले आहे काय? | Written | Payment झालंय का? | Has the payment gone through? |
| 67 | Payment | आपण भुगतान केले आहे का? | Hindi `भुगतान` | Payment केलंय का? | Have you paid? |
| 68 | Payment | आपले payment successful झालेले आहे. | Awkward perfect | Payment झालंय. | Payment has gone through. |
| 69 | Payment | मला तुमचे payment दिसत आहे आहे. | Ungrammatical duplication | हो, payment दिसतंय. | Yes, I can see the payment. |
| 70 | Payment failure | आपले transaction असफल झाले आहे. | Hindi-like/Sanskritised | Transaction fail झालंय. | The transaction failed. |
| 71 | Payment pending | व्यवहार प्रलंबित अवस्थेत आहे. | Banking prose | Payment pending दिसतंय. | The payment shows as pending. |
| 72 | OTP | कृपया एकदाच वापरण्यायोग्य संकेतशब्द सांगा. | Over-translated | OTP सांगाल का? | Could you give me the OTP? |
| 73 | Refund | परतफेडीविषयीची आपली चौकशी काय आहे? | Formal | Refund बद्दल काय झालंय? | What's the issue with the refund? |
| 74 | Refund | परतावा प्रक्रिया आरंभ करण्यात आली आहे. | Bureaucratic | Refund process सुरू झाली आहे. | The refund process has started. |
| 75 | Refund | रक्कम आपल्या खात्यावर परत क्रेडिट केली जाईल. | Redundant hybrid | पैसे account मध्ये परत येतील. | The money will go back to your account. |
| 76 | Refund | Refund process केला जाईल. | Awkward agentive hybrid | Refund process सुरू होईल. | The refund process will begin. |
| 77 | Exchange | आपण वस्तूची अदलाबदल करू इच्छिता? | Formal | Product exchange करायचं आहे? | Do you want to exchange it? |
| 78 | Exchange | exchange उपलब्ध नाही आहे. | Awkward auxiliary | Exchange available नाही. | Exchange isn't available. |
| 79 | Waiting | कृपया प्रतीक्षा करा. | Fine in signage, stiff spoken repeatedly | जरा थांबा. | Just a moment. |
| 80 | Waiting | कृपया काही क्षणांसाठी प्रतीक्षा करावी. | Written instruction | एक मिनिट, मी बघतो. | One moment, I'll check. |
| 81 | Checking | मी माहितीची पडताळणी करत आहे. | Formal | मी details check करतोय. | I'm checking the details. |
| 82 | Checking | कृपया hold वर रहा. | Literal call-centre jargon | एक क्षण, line वर राहा. | One moment, stay on the line. |
| 83 | Checking | आपण दोन मिनिटांसाठी hold करू शकता का? | English syntax | दोन मिनिटं थांबाल का? | Could you wait two minutes? |
| 84 | Checking | आपण प्रतीक्षा केल्याबद्दल धन्यवाद. | Scripted if every hold | हो, मिळालं. | Got it. |
| 85 | System issue | प्रणालीमध्ये तांत्रिक अडचण उद्भवलेली आहे. | IT prose | System मध्ये थोडा issue आहे. | There's a system issue. |
| 86 | System issue | माझी प्रणाली प्रतिसाद देत नाही आहे. | Literal English | System response देत नाहीये. | The system isn't responding. |
| 87 | Unavailable | ही सुविधा सध्या कार्यान्वित नाही. | Formal | ही service सध्या available नाही. | This service isn't available now. |
| 88 | Delay | आपणास आणखी काही काळ धैर्य धरावे लागेल. | Patronising | थोडा वेळ लागू शकतो. | It may take a little time. |
| 89 | Complaint | शांत व्हा, मी मदत करतो. | Tells angry customer to calm down | हो, समजतंय. मी काय करता येईल ते बघतो. | I understand. Let me see what I can do. |
| 90 | Complaint | तुम्ही रागावण्याची गरज नाही. | Invalidating | त्रास झाला आहे, समजतंय. | I understand this has been frustrating. |
| 91 | Complaint | आम्हाला झालेल्या गैरसोयीबद्दल मनःपूर्वक खेद आहे. | Boilerplate | माफ करा, हा delay आमच्याकडून झाला. | Sorry, this delay was on our side. |
| 92 | Complaint | क्षमस्व सर, क्षमस्व सर, क्षमस्व. | Excess apology/title | हो, माफ करा. मी आत्ता बघतो. | Sorry. I'll look into it now. |
| 93 | Complaint | आपली तक्रार आमच्यासाठी अत्यंत महत्त्वाची आहे. | Empty corporate line | Complaint नोंदवली आहे. पुढचं काय होईल ते सांगतो. | I've logged it. Let me explain what happens next. |
| 94 | Angry customer | तुम्ही चुकीची माहिती देत आहात. | Confrontational | माझ्याकडे थोडी वेगळी माहिती दिसतेय. एकदा बघूया. | I'm seeing something slightly different. |
| 95 | Angry customer | कृपया आपली भाषा नियंत्रित करा. | Escalatory | मी मदत करतो, पण आपण एकमेकांशी शांतपणे बोलूया. | I'll help, but let's speak calmly. |
| 96 | Empathy | अरेरे! किती वाईट! | Can sound theatrical | अच्छा, समजलं. हा त्रास झाला आहे. | I see. That's been troublesome. |
| 97 | Apology | झालेल्या असुविधेसाठी आम्ही आपली क्षमा मागतो. | Written boilerplate | माफ करा, तुम्हाला wait करावं लागलं. | Sorry you had to wait. |
| 98 | Responsibility | ही आमची चूक नाही आहे. | Defensive | इथे नेमकं काय झालं ते आधी बघूया. | Let's first see what happened. |
| 99 | Human escalation | मी आपणास मानवी प्रतिनिधीकडे हस्तांतरित करतो. | Literal/formal | मी तुम्हाला agent कडे transfer करतो. | I'll transfer you to an agent. |
| 100 | Human escalation | आपण थांबा, मी senior ला connect करत आहे. | Mixed but clunky | एक मिनिट, senior team ला connect करतो. | One moment, I'll connect you. |
| 101 | Escalation | आपली समस्या उच्च विभागाकडे वाढविण्यात येईल. | Literal “escalate” | हा case senior team कडे देतो. | I'll pass this case to the senior team. |
| 102 | Escalation | तिकीट निर्माण करण्यात आले आहे. | Literal ticketing | तुमची complaint नोंदवली आहे. | Your complaint has been logged. |
| 103 | Next steps | आपणास २४ ते ४८ कार्यकारी तासांमध्ये प्रतिसाद प्राप्त होईल. | Written | २४ ते ४८ तासांत update मिळेल. | You'll get an update within 24–48 hours. |
| 104 | Follow-up | आम्ही आपल्याशी पुनः संपर्क प्रस्थापित करू. | Bureaucratic | आम्ही पुन्हा call करू. | We'll call again. |
| 105 | Closing | आपल्याला आणखी कोणत्याही प्रकारच्या सहाय्याची आवश्यकता आहे काय? | Heavy | आणखी काही मदत हवी आहे का? | Anything else I can help with? |
| 106 | Closing | आज आमच्याशी संपर्क केल्याबद्दल आपले हार्दिक आभार. | Scripted | धन्यवाद. | Thank you. |
| 107 | Closing | आपला दिवस अत्यंत शुभ आणि फलदायी जावो. | Overdone | ठीक आहे. धन्यवाद. नमस्कार. | Thank you. Goodbye. |
| 108 | Closing | Goodbye सर, thank you सर, have a nice day सर. | Call-centre parody | धन्यवाद. नमस्कार. | Thank you. Goodbye. |
| 109 | Closing | सागरजी, अजून काही सागरजी? | Name repetition | आणखी काही आहे का? | Anything else? |
| 110 | Closing | जर आपल्याला भविष्यात सहाय्याची गरज भासली तर कृपया आमच्या ग्राहक सेवा केंद्राशी संपर्क साधावा. | Written paragraph | पुन्हा काही लागलं तर call करा. | Call us again if you need anything. |

A useful quality test for every generated utterance is:

> **Would a competent Marathi-speaking employee actually say this aloud to a customer, or would they only write it in a notice, form, policy document or translated script?**

If the answer is the latter, rewrite.

## Few-shot conversation patterns for training

The mini-dialogues below can be used almost directly as system-prompt few-shot examples. They deliberately keep turns short. This matches general voice-design recommendations to avoid verbose error recovery, over-confirmation and repetitive paraphrasing. citeturn23view0turn23view1

**Greeting**

Robotic:

Agent: `नमस्कार महोदय. आमच्या ग्राहक सहाय्य सेवेत आपले स्वागत आहे. मी आपल्याला कशाप्रकारे सहाय्य करू शकतो?`  
Customer: `माझ्या order बद्दल विचारायचं होतं.`  
Agent: `नक्कीच महोदय. कृपया आपल्या order विषयी अधिक माहिती प्रदान करा.`

Natural:

Agent: `नमस्कार! कशी मदत करू?`  
Customer: `माझ्या order बद्दल विचारायचं होतं.`  
Agent: `हो, सांगा. काय झालंय order ला?`

**Asking how to help**

Robotic:

Agent: `आपल्या दूरध्वनीचा उद्देश कृपया स्पष्ट करा.`

Natural:

Agent: `सांगा, कशाबद्दल मदत हवी आहे?`

**General customer enquiry**

Robotic:

Customer: `मला एक माहिती हवी होती.`  
Agent: `कृपया आपली चौकशी स्पष्ट स्वरूपात व्यक्त करा.`

Natural:

Customer: `मला एक माहिती हवी होती.`  
Agent: `हो, सांगा.`

**Product enquiry**

Robotic:

Customer: `हा model available आहे का?`  
Agent: `मी सदर उत्पादनाची साठा उपलब्धता तपासतो.`  
Agent: `सदर उत्पादन वर्तमानतः उपलब्ध आहे.`

Natural:

Customer: `हा model available आहे का?`  
Agent: `एक मिनिट, stock बघतो.`  
Agent: `हो, आहे. दोन pieces दिसतायत.`

**Appointment booking**

Robotic:

Agent: `आपल्याला कोणत्या दिनांकास आणि कोणत्या वेळी भेट निश्चित करावयाची आहे?`  
Customer: `उद्या.`  
Agent: `उद्याच्या दिवशी उपलब्ध वेळा दुपारी तीन आणि सायंकाळी पाच आहेत.`

Natural:

Agent: `कोणत्या दिवशी appointment हवी आहे?`  
Customer: `उद्या.`  
Agent: `उद्या तीन आणि पाचचे slots आहेत. कोणता चालेल?`  
Customer: `पाच.`  
Agent: `ठीक. पाचची book करतो.`

**Order-status enquiry**

Robotic:

Customer: `माझी order कुठे आहे?`  
Agent: `आपण केलेल्या order ची सद्यस्थिती जाणून घेण्यासाठी कृपया order number प्रदान करा.`

Natural:

Customer: `माझी order कुठे आहे?`  
Agent: `Order number सांगाल का?`  
Customer: `45821.`  
Agent: `हो, एक मिनिट… मिळाली. उद्याची delivery दिसतेय.`

**Delivery issue**

Robotic:

Customer: `आज delivery होती पण आली नाही.`  
Agent: `आपण असे सांगत आहात की नियोजित दिनांकास आपली delivery प्राप्त झाली नाही.`

Natural:

Customer: `आज delivery होती पण आली नाही.`  
Agent: `अच्छा. Order number द्या, status बघतो.`  
Customer: `45821.`  
Agent: `हो. इथे delay दिसतोय. Delivery उद्यावर गेली आहे.`

**Payment issue**

Robotic:

Customer: `पैसे गेले पण order झाली नाही.`  
Agent: `आपले payment debit झाले असून order generate झालेली नाही असे आपण म्हणत आहात का?`

Natural:

Customer: `पैसे गेले पण order झाली नाही.`  
Agent: `हो, समजलं. Transaction ID आहे का?`  
Customer: `आहे.`  
Agent: `सांगा. Payment कुठे अडकलंय ते बघतो.`

**Refund enquiry**

Robotic:

Customer: `Refund कधी येईल?`  
Agent: `आपला परतावा प्रक्रियेमध्ये असून निर्धारित कालावधीमध्ये आपल्या मूळ देयक पद्धतीमध्ये जमा केला जाईल.`

Natural:

Customer: `Refund कधी येईल?`  
Agent: `एक मिनिट, status बघतो.`  
Agent: `हो, refund process झालाय. अजून दोन-तीन दिवस लागू शकतात.`

**Complaint**

Robotic:

Customer: `तीन वेळा call केला आहे मी!`  
Agent: `आपल्याला झालेल्या असुविधेसाठी आम्ही मनःपूर्वक दिलगीर आहोत.`

Natural:

Customer: `तीन वेळा call केला आहे मी!`  
Agent: `हो, समजतंय. पुन्हा पुन्हा call करावा लागला, sorry. आता case बघतो.`

**Customer does not understand**

Agent: `Refund source account मध्ये reverse होईल.`  
Customer: `म्हणजे?`

Bad:

Agent: `मी स्पष्ट केले की refund source account मध्ये reverse होईल.`

Natural:

Agent: `म्हणजे पैसे ज्या account मधून गेले होते, त्याच account मध्ये परत येतील.`

**Agent does not understand**

Customer: `[unclear]`

Robotic:

Agent: `क्षमस्व. आपले इनपुट ओळखता आले नाही. कृपया पुन्हा प्रयत्न करा.`

Natural:

Agent: `माफ करा, शेवटचा भाग नीट ऐकू आला नाही. पुन्हा सांगाल का?`

**Asking someone to repeat information**

Customer: `नंबर ९८२०… [unclear] …७१२.`

Bad:

Agent: `कृपया संपूर्ण दूरध्वनी क्रमांक पुन्हा सांगा.`

Natural:

Agent: `९८२० नंतरचे digits पुन्हा सांगाल का?`

**Incorrect information**

Agent: `Delivery पुण्याला आहे.`  
Customer: `नाही, Nashik आहे.`

Robotic:

Agent: `आपण दिलेली माहिती पूर्वीच्या माहितीशी विसंगत आहे.`

Natural:

Agent: `अच्छा, Nashik. बरोबर. Address एकदा confirm करूया.`

This is exactly the kind of one-step correction a dialogue system should support rather than restarting the entire flow. citeturn23view0

**Angry customer**

Customer: `तुमची service अगदी useless आहे!`

Bad:

Agent: `कृपया शांत व्हा आणि सभ्य भाषेचा वापर करा.`

Natural:

Agent: `हो, त्रास झाला आहे, समजतंय. आधी problem solve करूया. Order number द्या.`

If abuse becomes severe, boundary-setting can follow; do not lead with confrontation.

**Customer changes their mind**

Customer: `Appointment cancel करा.`  
Agent: `ठीक, cancel करतो.`  
Customer: `नाही, थांबा. Cancel नको.`

Bad:

Agent: `आपण cancellation request मागे घेऊ इच्छिता याची पुष्टी करा.`

Natural:

Agent: `ठीक आहे, cancel करत नाही. Date change करायची आहे का?`

**Customer interrupts**

Agent: `तुमच्या order ची delivery—`  
Customer: `एक मिनिट, address चुकीचा आहे.`

Bad:

Agent: `कृपया मला माझे वाक्य पूर्ण करू द्या.`

Natural:

Agent: `हो, सांगा.`  
Customer: `Address Nashik चा आहे.`  
Agent: `अच्छा. मग आधी address दुरुस्त करूया.`

**Agent and customer speak simultaneously**

Agent: `उद्या—`  
Customer: `मी—`

Natural:

Agent: `सॉरी, तुम्ही बोला.`

Customer finishes.

Agent: `हो. आता सांगतो.`

**Human escalation**

Customer: `मला senior शी बोलायचं आहे.`

Bad:

Agent: `आपली विनंती योग्य प्रतिनिधीकडे हस्तांतरित करण्याची प्रक्रिया आरंभ करत आहे.`

Natural:

Agent: `ठीक आहे. एक मिनिट, senior team ला connect करतो.`

**Closing**

Agent: `Appointment confirm झाली आहे. उद्या चार वाजता.`  
Customer: `ठीक आहे.`  
Agent: `आणखी काही मदत हवी आहे का?`  
Customer: `नाही, एवढंच.`  
Agent: `ठीक आहे. धन्यवाद. नमस्कार.`

Do not continue:

`आपण आमची app download केली आहे का? आमचे offers ऐकायचे आहेत का?`

unless the product explicitly calls for a highly relevant next action. Conversation-design guidance recommends giving users closure once their intent is fulfilled and not continuing after they have signalled that they are done. citeturn22view0

## Sentence length, pacing and a deployment-ready language policy

For TTS, a grammatically elegant sentence can still be a bad spoken sentence. The agent should normally deliver **one proposition, one confirmation or one question at a time**. This is a design recommendation rather than a hard grammatical rule, but it follows both the structure of natural conversational teaching materials and modern voice-interaction guidance to keep reprompts and confirmations concise. citeturn18view3turn23view0turn23view1

Here are more than thirty transformations suitable for fine-tuning or prompt examples.

| Long / robotic version | Natural voice version |
|---|---|
| आपल्या order ची सद्यस्थिती तपासण्यासाठी मला आपला order number आवश्यक आहे. | Order number सांगाल का? |
| आपण दिलेला order number मी प्रणालीमध्ये तपासत आहे, त्यामुळे कृपया काही क्षण प्रतीक्षा करा. | एक मिनिट, order बघतो. |
| आपल्या order ची delivery उद्या दुपारी होण्याची अपेक्षा आहे. | Delivery उद्या दिसतेय. |
| आपल्या payment ची नोंद आमच्या प्रणालीमध्ये अद्याप दिसत नाही. | Payment अजून दिसत नाहीये. |
| आपण केलेले payment यशस्वी झाले आहे की नाही हे मी तपासून पाहतो. | Payment check करतो. |
| कृपया आपण वापरलेला transaction ID मला प्रदान करा. | Transaction ID सांगाल का? |
| मला आपले नाव योग्य प्रकारे समजले नाही, त्यामुळे कृपया ते पुन्हा सांगा. | नाव पुन्हा सांगाल का? |
| कृपया आपला phone number हळूहळू आणि स्पष्टपणे पुन्हा सांगा. | नंबर थोडा हळू सांगाल का? |
| आपण सांगितलेल्या phone number मधील शेवटचे चार अंक मला समजले नाहीत. | शेवटचे चार digits पुन्हा सांगाल का? |
| आपण सांगितलेला address योग्य आहे याची मला पुष्टी करायची आहे. | Address एकदा confirm करूया. |
| कृपया आपल्या राहण्याच्या ठिकाणाचा PIN code सांगा. | PIN code काय आहे? |
| आपण उद्याच्या दिवशी appointment घेण्यास इच्छुक आहात का? | उद्याची appointment हवी आहे? |
| उद्या दुपारी तीन वाजता आणि सायंकाळी पाच वाजता appointment उपलब्ध आहे. | उद्या तीन आणि पाचचे slots आहेत. |
| यापैकी कोणती वेळ आपल्या सोयीची असेल ते कृपया सांगा. | कोणता slot चालेल? |
| आपण निवडलेली appointment मी आता confirm करत आहे. | ठीक, appointment confirm करतो. |
| आपली appointment यशस्वीरित्या confirm करण्यात आली आहे. | झालं. Appointment confirm आहे. |
| आपण appointment रद्द करण्याऐवजी तिची date बदलू इच्छिता का? | Cancel नको, date change करायची आहे? |
| कृपया आपण appointment cancel करू इच्छिता याची अंतिम पुष्टी करा. | Appointment cancel करू? |
| आपला refund सध्या processing च्या अवस्थेमध्ये आहे. | Refund process मध्ये आहे. |
| refund पूर्ण होण्यासाठी आणखी तीन ते पाच दिवसांचा कालावधी लागू शकतो. | अजून तीन ते पाच दिवस लागू शकतात. |
| refund आपल्या मूळ payment method वर परत जमा केला जाईल. | पैसे त्याच account मध्ये परत येतील. |
| आपल्या delivery ला झालेल्या विलंबाबद्दल आम्ही दिलगीर आहोत. | माफ करा, delivery ला उशीर झालाय. |
| मी आपल्या complaint ची नोंद करून ती संबंधित team कडे पाठवतो. | Complaint नोंदवतो आणि team कडे देतो. |
| संबंधित team कडून आपल्याला पुढील चोवीस तासांत update मिळेल. | २४ तासांत update मिळेल. |
| कृपया आपण line वर राहा कारण मी senior representative शी संपर्क साधत आहे. | एक मिनिट, senior team ला connect करतो. |
| आपण व्यक्त केलेली समस्या मला पूर्णपणे समजली आहे. | हो, problem समजला. |
| आपणास झालेल्या असुविधेबद्दल पुन्हा एकदा क्षमा मागतो. | माफ करा, त्रास झाला. |
| आपल्या म्हणण्याप्रमाणे payment झाले आहे परंतु confirmation मिळालेले नाही, बरोबर? | Payment झालं, पण confirmation नाही आलं. बरोबर? |
| मी आपल्या मागील statement ची पडताळणी करू इच्छितो. | एक detail confirm करू? |
| आपल्या account मध्ये कोणती समस्या निर्माण होत आहे ते कृपया स्पष्ट करा. | Account ला काय problem येतोय? |
| आपल्या application ची सद्यस्थिती तपासण्यासाठी थोडा वेळ द्या. | एक मिनिट, application status बघतो. |
| आपल्याला message प्राप्त झाल्यानंतर त्यातील link वर click करावी लागेल. | Message आला की link वर click करा. |
| आपण WhatsApp द्वारे आपले current location आमच्याशी share करू शकता. | WhatsApp वर location share करा. |
| जर आपल्याला आणखी काही प्रश्न असतील तर आपण मला सांगू शकता. | आणखी काही विचारायचं आहे का? |
| आमच्याशी संपर्क साधल्याबद्दल धन्यवाद आणि आपला दिवस शुभ जावो. | धन्यवाद. नमस्कार. |
| भविष्यात आणखी काही मदत आवश्यक असल्यास कृपया आमच्याशी पुन्हा संपर्क साधावा. | पुन्हा काही लागलं तर call करा. |

The preferred pacing is therefore:

`हो, order मिळाली.`  
[pause]  
`Delivery उद्या दिसतेय.`  
[pause]  
`उद्या चालेल ना?`

rather than:

`हो, आपली order मला प्रणालीमध्ये मिळाली असून तिची delivery उद्याच्या दिवशी होणे अपेक्षित आहे, त्यामुळे कृपया उद्याची delivery आपल्याला योग्य आहे की नाही हे confirm करा.`

**Deployment-ready language policy**

The most effective system prompt for this agent should encode the following behaviour as hard preferences.

**Speak Marathi natively; do not translate.** Construct the utterance directly in conversational Marathi. *Spoken Marathi* explicitly recommends situational responses rather than translation exercises as the route to natural speech. citeturn18view3

**Default to `तुम्ही`.** Use respectful second-person Marathi for unknown adult customers. Avoid `तू` unless the product persona and relationship clearly justify familiarity. Spoken grammatical descriptions explicitly tie the distinction to social relationship and respect. citeturn18view4

**Use spoken contractions.** Prefer forms such as `समजलं`, `झालं`, `केलं`, `म्हणताय`, `करतोय`, `झालंय` where appropriate rather than consistently producing full written forms. Spoken descriptions document reductions such as `करतो आहे → करतोय`. citeturn18view9

**Omit recoverable information.** Do not restate the customer, company name, customer's name, order number and topic in every turn. Marathi independently permits omission of understood subjects, and conversational context makes still more material recoverable. citeturn18view5

**Ask short Marathi questions.** `का` naturally forms yes/no questions and information questions need not copy English word order. citeturn18view6

**Use English where Marathi speakers actually use English.** Keep high-frequency service concepts such as `order`, `payment`, `booking`, `appointment`, `delivery`, `refund`, `OTP`, `call`, `message`, `location`, `account`, `website`, `update`, `status`, `confirm`, `cancel`, `reschedule`, `check` and `process` available as ordinary vocabulary. Extensive Marathi-English corpus and sociolinguistic evidence shows that this type of mixing is a normal feature of contemporary Marathi communication, especially in urban environments. citeturn18view8turn19view0

**But preserve Marathi grammar.**

Good:

`Payment झालंय.`  
`मी call करतो.`  
`Location share करा.`  
`Appointment confirm करू?`

Bad:

`आपका payment हो गया.`  
`आप मुझे location भेजिए.`

**Do not code-switch for decoration.** `नाव`, `पैसे`, `काय`, `कधी`, `आज`, `उद्या`, `सांगा`, `बघतो`, `माहित`, `हवं`, `झालं` are strong conversational Marathi. A sentence in which every content word becomes English stops sounding like native code-mixed Marathi and starts sounding like English with Marathi morphology.

**Use acknowledgement semantically.**

Fact → `बरोबर`, `हो`, `मिळालं`  
Problem → `समजलं`, `अच्छा`, `हो, बघतो`  
Proposal → `चालेल`, `ठीक आहे`  
Surprise → `हो का?`, `असं का?`  
Continuation → `सांगा`, `हो, बोला`  
Transition → `बरं, मग…`

Do not choose a random acknowledgement token from a list.

**Never say `ठीक आहे` after every turn.** Confirmation should carry information or move the conversation forward; generic repeated confirmations are discouraged in conversation-design practice. citeturn23view0

**Do not overuse `sir`, `madam` or the customer's name.** They may appear once when context makes them useful, but repeated vocatives are characteristic of scripted call-centre speech rather than relaxed Marathi conversation.

**Use `कृपया` sparingly.** It is valid Marathi, not forbidden Marathi. But spoken politeness is better achieved through respectful verb forms and constructions such as:

`सांगाल का?`  
`जरा थांबा.`  
`एकदा confirm करू?`  
`शक्य असेल तर…`

**Never mistake formality for respect.**

Respectful and natural:

`तुमचा नंबर सांगाल का?`

Over-formal:

`कृपया आपला संपर्क क्रमांक प्रदान करावा.`

Casual/rude:

`नंबर सांग.`

**Keep most turns to one or two short sentences.** Split answer and next question:

`Refund process झालाय. अजून दोन दिवस लागू शकतात.`

Then, only if necessary:

`आणखी काही बघायचं आहे का?`

**Do not narrate internal mechanics.**

Avoid:

`मी आपल्या request च्या अनुषंगाने database मध्ये query execute करत आहे.`

Say:

`एक मिनिट, मी बघतो.`

**Do not repeat the user's entire sentence.** Use implicit confirmation when possible; general conversation-design guidance explicitly recommends confirming useful parameters without dwelling on “what you said” or “what I heard”. citeturn23view0

Customer: `मला शुक्रवारची appointment सोमवारला shift करायची आहे.`

Good:

`ठीक. सोमवारचे slots बघतो.`

Only if there is ambiguity:

`म्हणजे शुक्रवारची cancel करून सोमवारला करायची, बरोबर?`

**Explicitly confirm high-cost details and actions.**

Confirm names when uncertain.  
Confirm critical phone digits.  
Confirm addresses before dispatch.  
Confirm exact dates if confusion is possible.  
Confirm cancellation/refund/payment before an irreversible transaction.

That is consistent with established conversation-design guidance to reserve explicit confirmation for parameters or actions whose misrecognition has meaningful cost. citeturn23view0

**On recognition failure, repair locally.**

Bad:

`कृपया पुन्हा सांगा.`

again:

`कृपया पुन्हा सांगा.`

again:

`कृपया पुन्हा सांगा.`

Better:

`माफ करा, शेवटचा भाग पुन्हा सांगाल का?`

Then:

`Order number म्हणालात की phone number?`

Then:

`Order number एकदा हळू सांगाल का?`

Voice-design guidance similarly recommends changing and enriching successive reprompts rather than repeating the identical prompt verbatim. citeturn23view1

**Handle overlap like a person.**

`हो, तुम्ही बोला.`  
`सॉरी, मध्ये बोललो.`  
`आधी तुम्ही पूर्ण करा.`

Do not enforce artificial turn ownership.

**Use fillers lightly.** `हं`, `बरं`, `म्हणजे`, `एक मिनिट`, `बघूया` can create conversational rhythm. They should signal a real discourse function, not be randomly injected to imitate humanness.

**Avoid strongly region-marked vocabulary in the pan-Maharashtra base model.** Marathi has genuine dialect diversity, and major corpora warn about geographic representativeness. citeturn19view0 Add Varhadi, Malvani, Ahirani/Khandeshi or other regional layers only when the agent is intentionally localised and evaluated by speakers from that region.

**Do not over-normalise Roman Marathi.** Users may write or ASR may emit `kay`, `kaay`, `kaye`; `ahe`, `aahe`; `zala`, `zhala`; `mala`, etc. Romanised Marathi has substantial legitimate spelling variation. citeturn19view0 Normalise internally for semantic processing but do not assume one spelling represents one sociolinguistic identity.

**Match emotional temperature.**

Routine query → efficient and friendly.  
Confusion → patient.  
Mild inconvenience → sympathetic but brief.  
Angry customer → acknowledge frustration, then act.  
Serious financial/service failure → avoid playful `अरेरे` or breezy `हो का?`.  
Happy customer → warmth can increase slightly.

**The final native-speech test**

A strong Marathi voice-agent response should usually pass all of these checks:

| Test | Pass condition |
|---|---|
| Translation test | It does not look like an English/Hindi sentence translated word by word |
| Read-aloud test | It sounds plausible when spoken, not merely grammatical on paper |
| Respect test | Unknown adults are addressed respectfully without ceremonial language |
| Brevity test | It communicates one thought or action at a time |
| Code-mix test | English appears where Marathi speakers naturally use it, not randomly |
| Marathi-grammar test | Borrowed English words sit inside Marathi syntax and inflection |
| Confirmation test | The agent confirms only information worth confirming |
| Repetition test | Customer statements are not unnecessarily repeated |
| Backchannel test | `हो`, `ठीक आहे`, etc. are varied according to meaning |
| Emotion test | Acknowledgement matches the customer's emotional state |
| Repair test | Misrecognition triggers a specific, increasingly helpful repair |
| Voice test | Pauses and short clauses create conversation rather than a spoken paragraph |
| Persona test | Gendered first-person forms stay consistent with the voice |
| Regional test | Base language is neutral; dialect features are deliberate rather than accidental |
| Five-minute test | After several turns, the agent still sounds like a Marathi speaker rather than a translation engine |

The strongest overall benchmark is therefore **not grammatical purity**. It is this:

> **Use Marathi grammar, Marathi conversational rhythm and Marathi social norms as the foundation; mix in the English vocabulary that Marathi speakers themselves routinely mix in; shorten what a speaker would shorten; omit what context already supplies; respect the customer without sounding ceremonial; and treat every response as a turn in a conversation rather than a sentence in a document.**

That approach is consistent with both the older descriptive tradition of teaching Marathi through natural conversational situations and the newer empirical evidence showing extensive contemporary Marathi-English mixing, regional variation, Roman-script variability and the importance of conversational rather than purely written language data. citeturn18view3turn18view8turn19view0 It also aligns with established voice-conversation design principles: confirm selectively, support one-step corrections, vary error recovery, avoid needless repetition and give the user clear closure when the task is complete. citeturn23view0turn23view1turn22view0
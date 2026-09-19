---
title: "Your Voice Agent Costs 11 Cents a Minute. That Is the Input That Matters Least."
description: "A cost-per-resolved-call model built only from published inputs: BLS wage data, Eurostat labour cost, contact centre benchmarks and five vendors' own pricing pages. The formula, three worked examples with every number linked to its source, and the algebra showing which input actually moves the answer."
date: "2026-09-19"
category: "Industry Research"
readingTime: "13"
keywords: "cost per resolved call, contact centre cost model, AI voice agent cost per minute, voice agent pricing comparison, containment rate benchmark, cost per contact benchmark, voice AI ROI model"
---

## Every vendor leads with the per-minute price. It decides almost nothing.

Eleven cents a minute. Eight cents a minute. Six cents plus telephony. The per-minute rate is the number on every voice-agent pricing page, and it is the first thing a buyer writes down.

Work the arithmetic through to cost per resolved call and the per-minute rate turns out to be a small term. In the worked example below it accounts for seventeen percent of what a human call costs, and the difference between the cheapest vendor and the dearest moves the final answer by about eight points. The input that moves it by fifty is the one no vendor publishes and most buyers accept on faith.

This is a model, not a survey. Nobody was polled. Every input below comes from a page we fetched on 19 September 2026, and every one is linked. Each source carries a class so you can weigh it yourself:

**Official statistics** for wage and labour-cost data. **Industry benchmark** for handle time, occupancy and cost per contact. **Vendor-published** for anything a supplier says about its own prices or its own results.

Where no published figure exists, the model takes an assumption and says so in those words. That happens once, and it happens on the input that matters most.

If you want the framework for a whole programme rather than a unit cost, the [total cost of ownership piece](/blog/en/ai-total-cost-ownership-framework.html) covers the parts a per-call model deliberately leaves out.

## The formula

Four quantities on the human side, two on the machine side, one that joins them.

**L** is the fully loaded cost of an hour of agent time. Salary plus employer taxes and benefits, not salary alone.

**o** is occupancy: the share of a logged-in hour actually spent on contacts.

**t** is average handle time in minutes, talk plus after-call work.

**Human cost per handled call:**

`Ch = L × t ÷ (60 × o)`

**m** is the all-in machine price per minute: platform, speech-to-text, the model, speech synthesis and telephony added together. Not the platform fee on its own, which is how most comparisons go wrong.

**tm** is how long the agent takes on the same call.

**Machine cost per call attempt:**

`Cm = m × tm`

**r** is containment: the share of calls the agent finishes with no human involved.

Every call reaches the agent. A fraction `1 − r` then also costs a full human handle. So:

**Blended cost per resolved call = Cm + (1 − r) × Ch**

That is the whole model. Nothing in it is clever, and that is the point: anything harder to audit is harder to trust.

## The published inputs

| Input | Value | Unit | Class | Source |
| --- | --- | --- | --- | --- |
| US customer service rep, mean hourly wage | $22.40 | hourly USD, May 2025 OEWS | Official statistics | [BLS OEWS 43-4051](https://data.bls.gov/dataViewer/view/timeseries/OEUN000000000000043405103) |
| US customer service rep, mean annual wage | $46,590 | annual USD, May 2025 | Official statistics | [BLS OEWS 43-4051](https://data.bls.gov/dataViewer/view/timeseries/OEUN000000000000043405104) |
| US private industry, total compensation per hour worked | $46.89 | hourly USD, Q2 2026 | Official statistics | [BLS ECEC](https://data.bls.gov/dataViewer/view/timeseries/CMU2010000000000D) |
| US private industry, wages and salaries per hour worked | $32.82 | hourly USD, Q2 2026 | Official statistics | [BLS ECEC](https://data.bls.gov/dataViewer/view/timeseries/CMU2020000000000D) |
| France, labour cost per hour, NACE section N | €31.80 | hourly EUR, 2024, fully loaded | Official statistics | [Eurostat lc_lci_lev](https://ec.europa.eu/eurostat/databrowser/view/lc_lci_lev/default/table?lang=en) |
| EU27, labour cost per hour, NACE section N | €25.40 | hourly EUR, 2024, fully loaded | Official statistics | [Eurostat lc_lci_lev](https://ec.europa.eu/eurostat/databrowser/view/lc_lci_lev/default/table?lang=en) |
| India, customer service representative, average salary | ₹335,000 | annual INR | Surveyed | [Talent.com India](https://in.talent.com/salary?job=customer+service+representative) |
| India, customer support executive, average | ₹280,000 | annual INR, n≈37,000 self-reported | Surveyed | [AmbitionBox, archived 8 Aug 2024](https://web.archive.org/web/20240808103622/https://www.ambitionbox.com/profile/customer-support-executive-salary) |
| Average handle time | 6 min 3 s | seconds per call | Industry benchmark | [Call Centre Helper](https://www.callcentrehelper.com/industry-standards-metrics-125584.htm) |
| Maximum occupancy | 83.3% | share of logged-in time | Industry benchmark | [Call Centre Helper](https://www.callcentrehelper.com/industry-standards-metrics-125584.htm) |
| Shrinkage | 30% stated, 26.6% observed in their own tool | share of paid time | Industry benchmark | [Call Centre Helper](https://www.callcentrehelper.com/industry-standards-metrics-125584.htm) |
| Typical cost per inbound call, UK | £6.26 (€7.25, $7.68) | per call, all-in | Industry benchmark, quoted | [ContactBabel 2023-24 guide, p.97, via Call Centre Helper](https://www.callcentrehelper.com/how-to-calculate-cost-per-inbound-call-228537.htm) |
| Average cost per call, reader poll | £3.50 | per call, all-in | Industry benchmark, weak | [Call Centre Helper poll, 2014](https://www.callcentrehelper.com/poll-what-is-your-average-cost-per-call-68854.htm) |
| Occupancy, 417 US contact centres | 74%, range 50 to 90% | share | Surveyed, vendor-commissioned | [IDC InfoBrief for Talkdesk](https://www.talkdesk.com/blog/cost-to-value-how-does-your-contact-center-stack-up/) |
| Reference rate, 18 Sep 2026 | EUR/USD 1.1460, EUR/INR 109.8755 | daily reference | Official statistics | [ECB euro reference rates](https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml) |


Two notes on the handle-time and occupancy rows, because their method matters more than the numbers.

Call Centre Helper states its own method plainly: the 6 min 3 s and the 83.3% are "based on 190,702 entries into our Erlang Calculator". That is an aggregate of what users typed into a free tool, not a measured sample of call recordings. It is the most widely quoted contact centre benchmark in the world and it is self-selected input. The same page also reports 30 to 35% shrinkage from site visits while its own calculator average sits at 26.6%, which the publisher attributes to "widespread confusion over the definition".

The AHT-by-sector table on that page is attributed to "a Cornell University report" with no link, year or title. The famous 6 min 3 s figure is **not** the Cornell number. It is Call Centre Helper's own. Attributions in this area drift.

## The vendor prices

Fetched 19 September 2026. All **vendor-published**, which is the correct class for anything a supplier says about its own price.

| Vendor | Rate | What the rate covers | Source |
| --- | --- | --- | --- |
| ElevenLabs Agents | $0.080 per call minute | Platform, text-to-speech and speech-to-text. "The LLM model and any telephony are billed separately on top, based on usage." Burst rate $0.160 above your concurrency limit | [ElevenLabs Agents pricing](https://elevenlabs.io/pricing/agents) |
| Vapi | $0.05 per minute hosting | Platform only. Models pass through "at cost". Their own calculator shows Deepgram $0.0095 to $0.0099, OpenAI $0.0077 to $0.0452 and ElevenLabs voice $0.0146 to $0.0238 per minute. Transport extra: Twilio inbound $0.008, outbound $0.014 | [Vapi pricing](https://vapi.ai/pricing) |
| Retell AI | $0.11 per minute all-in, default configuration | Itemised on the page as Retell voice infra $0.055, LLM $0.04, TTS $0.015. Telephony from $0.015. Knowledge base +$0.005, PII removal +$0.01 | [Retell pricing](https://www.retellai.com/pricing) |
| Cartesia | $0.06 per minute, base rate | "Base rate for all voice agent calls", billed in US dollars rather than credits. Telephony add-on +$0.014 when using a Cartesia number | [Cartesia docs, pricing](https://docs.cartesia.ai/pricing) |
| Sarvam AI | No per-minute agent rate published | Meters components instead: speech to text ₹30 per hour, speech synthesis ₹30 per 10,000 characters, sarvam-105b ₹29.28 per million input tokens and ₹73.20 per million output tokens | [Sarvam pricing](https://docs.sarvam.ai/api-reference-docs/pricing) |


Sarvam is the row worth pausing on. Four vendors quote a price in the unit this comparison uses. The fifth does not, anywhere. Its docs sitemap contains exactly one pricing page and that page meters in hours, characters and tokens.

We could produce a per-minute figure for it by assuming a speaking rate, a character count per word and a token ratio. We have not, because a derived number printed in the same column as four measured ones looks identical to them and carries none of the same warrant. The unit is the finding. Treat a component-priced stack as something you build and measure, not something you cite.

Assembled into one number, a Vapi stack of platform plus Deepgram plus a mid-range model plus ElevenLabs voice plus Twilio lands near $0.108 per minute. Retell's default configuration prices at $0.11. Two vendors, two pricing philosophies, the same answer to two decimal places. The model below uses **$0.11 as the base case and $0.06 as the low case**.

## Worked example one: a US support line

Fully loaded hourly cost. The BLS publishes the wage, and separately publishes what wages are as a share of total employer cost.

`L = $22.40 ÷ 0.700 = $32.00 per hour`

Wages were 70.0% of total private-industry compensation in Q2 2026 ($32.82 of $46.89). The loading multiplier is 1.4287. Applying an economy-wide ratio to one occupation is an approximation, and it is the only way to get there from published data.

**Human cost per handled call:**

`Ch = $32.00 × 6.05 ÷ (60 × 0.833) = $3.87`

**Machine cost per call, at $0.11 per minute and the same handle time:**

`Cm = $0.11 × 6.05 = $0.67`

| Containment | Blended cost per resolved call | Against $3.87 human-only |
| --- | --- | --- |
| 30% | $3.38 | 13% lower |
| 50% | $2.60 | 33% lower |
| 76% | $1.60 | 59% lower |
| 90% | $1.05 | 73% lower |


Sanity check against the published all-in benchmarks. Our $3.87 is **agent labour only**. It excludes supervision, quality assurance, workforce management, telephony, facilities, licences and recruitment. ContactBabel's typical UK cost per inbound call is $7.68 all-in, almost exactly double. That gap is the shape you would expect, and it is the reason a labour-only model understates the saving rather than overstating it.

The two cost-per-contact figures you will see quoted most often are worth less than either of those. The "$5 to $12 per call" range has no traceable publisher we could find. The "$1.3 trillion spent on 265 billion customer service calls a year" figure traces to a [2017 IBM Consulting social post](https://x.com/ibmconsulting/status/930533299797352449?lang=en) carrying no methodology, no sample and no report behind it. IBM's own later phrasing, as reported by the [Bangkok Post in January 2018](https://www.bangkokpost.com/business/1392134/ibm-thailand-predicts-ai-upheaval-in-customer-service-this-year), is "more than US$1 trillion". A number that moves by three hundred billion between tellings is not a benchmark.

## Worked example two: France

Eurostat publishes labour cost directly, already loaded. No multiplier needed.

NACE section N, Administrative and support service activities, 2024: France €31.80 per hour, EU27 €25.40. Section N is broader than call centres; the narrower N82 and N8220 codes return an empty value set in that dataset, so section N is as close as published data gets.

At the ECB reference rate of 18 September 2026, €31.80 is $36.44.

`Ch = $36.44 × 6.05 ÷ (60 × 0.833) = $4.41 per handled call`

Same machine cost of $0.67. At 50% containment the blended cost is $2.87, which is 35% below human-only. At 76% it is $1.72, or 61% below.

The direction is the same as the US and the magnitude is slightly better, because the labour is dearer and the machine costs the same.

## Worked example three: India, where the answer flips

`L = ₹335,000 ÷ 2,080 hours = ₹161.06 per hour`

The 2,080-hour convention is the model's assumption, not a published Indian figure. A 48-hour week would put it nearer 2,496 hours and cut the hourly cost by about 17%. We could not fetch a published India-specific loading factor for employer contributions, so this row is wage-only and therefore understates the human cost.

`Ch = ₹161.06 × 6.05 ÷ (60 × 0.833) = ₹19.50 per handled call`

At the ECB-derived rate of ₹95.88 to the dollar, $0.11 per minute is ₹10.55 per minute.

`Cm = ₹10.55 × 6.05 = ₹63.81 per call`

The machine costs **3.3 times** what the human costs, per call, before containment enters the arithmetic at all. There is no containment rate that rescues it. At 90% containment the blended cost is ₹65.76 against ₹19.50 for doing it the old way.

Drop to the cheapest base rate in the table, $0.06 per minute, and the machine still costs 1.8 times the human.

This is not an argument against voice agents in India. It is an argument that the case for them there is not a labour cost case. It is a coverage case, a language case and a consistency case: the 21:40 call that nobody is staffed for, the four languages one agent handles, the answer that is the same at 09:00 and 23:00. Our [multilingual coverage piece](/blog/en/multilingual-ai-jewellery-india.html) is about exactly that trade, and none of it shows up in a cost-per-call model.

It also explains why Indian vendors price in rupees per hour and per ten thousand characters rather than dollars per minute. The model gives the target directly: at 80% containment, break-even lands at **₹2.58 per minute**. That is the number an India-market stack has to clear. Whether a component-priced one does is a measurement, not a citation.

## The sensitivity, which is algebra rather than opinion

Divide the blended cost by the human cost and the saving fraction comes out as:

`saving = r − (Cm ÷ Ch)`

Substitute and, when the agent takes the same time on a call as a person does, the handle time cancels:

`saving = r − (60 × m × o ÷ L)`

That result is worth sitting with. **Average handle time disappears from the answer.** It scales both sides equally. The moment the agent is faster or slower than a person the term returns as the ratio `tm ÷ t`, but nobody's published AHT benchmark belongs anywhere near this calculation as long as the two are similar.

What is left is three inputs.

**Containment moves the answer one-for-one.** Ten points of containment is ten points of saving. Nothing else in the model comes close.

**The per-minute price and the loaded wage arrive together, as a ratio.** In the US example at $0.11 they subtract 17.2 points. Halving the rate to $0.06 recovers about eight of those points. Real money, and roughly a sixth of what ten points of containment does.

**Occupancy is a scaler on the small term.** Moving it from 83.3% to 74%, the figure the IDC survey of 417 US contact centres reported, changes the US answer by under two points.

The break-even containment, the point below which the whole exercise loses money, is that same expression:

| Setting | Per-minute rate | Break-even containment |
| --- | --- | --- |
| US, $32.00 per hour loaded | $0.11 | 17.2% |
| US, $32.00 per hour loaded | $0.06 | 9.4% |
| France, $36.44 per hour loaded | $0.11 | 15.1% |
| France, $36.44 per hour loaded | $0.06 | 8.2% |
| India, ₹161 per hour | $0.11 | Unreachable |
| India, ₹161 per hour | $0.06 | Unreachable |


In the US and France the bar is low. Almost any working deployment clears it. Which means the interesting question was never whether an agent beats break-even. It is how far above it you land, and that is containment.

## The number we will not assert

Containment decides the answer and nobody has measured it for voice.

We went looking for an independently measured voice containment rate. There is not one. Here is the entire published range, with what each figure actually is.

| Figure | What it measures | Class | Source |
| --- | --- | --- | --- |
| 80% by 2029 | A forecast. "By 2029, agentic AI will autonomously resolve 80% of common customer service issues without human intervention, leading to a 30% reduction in operational costs." No survey, sample or data cited in the release | Analyst forecast | [Gartner, 5 Mar 2025, archived](https://web.archive.org/web/2025/https://www.gartner.com/en/newsroom/press-releases/2025-03-05-gartner-predicts-agentic-ai-will-autonomously-resolve-80-percent-of-common-customer-service-issues-without-human-intervention-by-20290) |
| 80% | What leaders expect, not what happened. "75% of CX leaders expecting 80% of customer interactions to be resolved without human intervention in the next few years." Survey of roughly 5,100 consumers and 5,400 CX leaders across 22 countries, fielded June to July 2024 | Surveyed expectation | [Zendesk CX Trends 2025](https://www.zendesk.com/newsroom/articles/2025-cx-trends-report/) |
| 76% | Chat and email, self-reported. "Industry leading resolution rates, averaging 76% across 12,000+ customers" | Vendor-published | [Intercom Fin](https://fin.ai/) |
| 76%, 5% escalated | Web self-service on a vendor's own help portal, 1.7 million conversations against 740,000 knowledge articles. Best-case conditions | Vendor-published, own deployment | [Salesforce Agentforce](https://www.salesforce.com/customer-stories/agentforce-for-customer-support/) |
| 98% | Voice, three languages, one customer. Self-reported, published by us | Vendor-published | [Le Marquier case study](/case-studies/le-marquier.html) |


Read Intercom's own definition before using their 76%: "A resolution is a type of outcome that is counted when, following Fin's last answer in a conversation, the customer either confirms the answer was satisfactory (confirmed resolution), or **exits the conversation without requesting further assistance** (assumed resolution)."

Silence counts as success. A customer who gave up and went to a competitor is scored the same as one who got the answer. That is a defensible billing definition. It is not a containment rate, and the difference is the entire margin of the model.

None of the five figures above is a measured voice containment rate from an independent party. Four are text or web. One is ours, for one customer, and we are linking to it rather than building on it.

So the model takes containment as an assumption and shows the answer across a range. Anyone who hands you a single containment number for your business, before seeing your call mix, has not measured anything either. They have picked a number from this same table.

## What the model leaves out

**Build cost and the ramp.** Knowledge base construction, integration work, the weeks at partial volume. A per-call model prices steady state. The [hidden costs piece](/blog/en/hidden-costs-ai-automation.html) covers the rest.

**Everything except agent labour on the human side.** Supervision, QA, workforce management, facilities, licences, attrition. This is why our $3.87 sits at roughly half of ContactBabel's all-in $7.68.

**Resolution quality.** A contained call that produced a wrong answer costs less and is worth less than nothing. The model counts calls, not outcomes.

**Repeat contacts.** A first-contact resolution rate belongs in this model as a divisor on both sides. We left it out because the published FCR benchmarks we could reach share the Erlang-calculator method already flagged above, and a second self-selected input compounding the first is not worth the precision it pretends to add.

**Revenue.** Every figure here is cost. What a faster answer does to conversion is a separate question, and the evidence on it is set out in the [lead response time study](/blog/en/lead-response-time-study.html).

## Running it on your own numbers

Five inputs. Four of them you already have.

Your loaded hourly cost, which your finance team knows. Your occupancy, which your workforce tool reports. Your handle time, which your telephony platform reports. Your all-in per-minute rate, which you compute by adding every line on the vendor invoice rather than reading the headline.

Then containment, which you cannot know until you run it. Pick a threshold before you start, hold it fixed, and count only calls that ended without a person and without a repeat contact inside seven days.

The formula is `saving = r − (60 × m × o ÷ L)`. Everything on the right except `r` is knowable this afternoon. Compute that term, and you have the containment rate your deployment has to beat before it is worth anything. Then go and find out whether it does.

---

*Every figure in this article links to a page we fetched on 19 September 2026. Sources are labelled official statistics, industry benchmark or vendor-published. Vendor pricing changes without notice and the rates above carry the unit each vendor meters in, so a later reader can check the unit before checking the number. Where no published figure exists, the model states an assumption in those words rather than borrowing someone else's estimate.*

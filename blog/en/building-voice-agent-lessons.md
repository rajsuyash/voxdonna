---
title: "What Building a Production Voice Agent Taught Us About AI"
description: "Building a voice AI agent in production reveals gaps that no vendor demo covers — from latency architecture to off-script conversations, human handoffs, and cost structure. Here are the decisions that actually determine whether a deployment succeeds."
date: "2026-09-08"
category: "Behind the Scenes"
readingTime: "9"
keywords: "voice AI production deployment, voice agent lessons learned, building voice AI production, production voice AI challenges, voice AI implementation lessons, AI voice agent latency architecture, voice AI cost structure, voice AI handoff design, building conversational AI"
---

# What Building a Production Voice Agent Taught Us About AI

## The Gap Nobody Warns You About

Every voice AI vendor has a compelling demo. The agent responds quickly, understands the question, gives a confident answer, and — if you push it slightly — gracefully redirects back on track. It works.

The problem is that what you see in a demo is a system optimized for a single, well-lit path. Production is everything else: the caller who starts a sentence, thinks better of it, and restarts mid-word. The customer phoning from a noisy construction site. The accent the training data underrepresented. The question the knowledge base doesn't cover. The moment when the agent should stop being an agent.

We have spent the past year building and running voice AI in production. This piece documents what we learned — the decisions that aren't in any vendor manual, the tradeoffs that only become visible at scale, and the questions every executive should ask before signing a voice AI contract.

---

## Lesson 1: Latency Is Architecture, Not a Setting

The most common misconception about voice AI latency is that it is a parameter you configure. It is not. It is the sum of a pipeline, and each stage is additive.

A complete end-to-end voice agent moves through four stages: speech recognition (STT) converts the caller's audio to text; the language model processes that text and generates a response; a text-to-speech engine (TTS) converts the response back to audio; and an audio player buffers and plays it. Every one of these stages contributes latency, and none of them can be made instantaneous.

ElevenLabs' Flash TTS models — among the fastest commercially available — achieve approximately 75ms of model inference time for short inputs under normal load. That sounds quick. But by the time you add network round-trips (typically 20–200ms depending on geography), LLM response time, speech recognition processing, and a 500ms audio player buffer that most implementations use to prevent stuttering, a caller is waiting somewhere between 1.5 and 3 seconds before hearing the agent's first word.

At 1.5 seconds, a conversation still feels natural. Above 2 seconds, callers begin to wonder whether the call dropped. Above 3 seconds, a meaningful portion hang up or start talking again, creating interruption handling challenges.

The practical implication: before you buy or build, get an end-to-end latency measurement — not API benchmark figures — from your geographic region, under peak load, with your full pipeline assembled. A TTS model that benchmarks at 75ms will not deliver a 75ms experience to your callers.

---

## Lesson 2: Your Users Will Not Follow the Script

Conversational design for voice AI typically starts with a flow diagram: the agent asks A, the caller responds with B or C, the agent proceeds accordingly. This is a useful design tool. It is not an accurate model of how real callers behave.

Callers interrupt. They answer a different question than the one asked. They volunteer information the system didn't request. They say "wait, actually" halfway through a response and start over. They ask the agent to repeat something four times. They put the phone down mid-conversation and come back.

None of this is unreasonable human behaviour. It is simply the normal variability of spoken conversation, and a voice AI system that handles only expected inputs will fail at a much higher rate in production than it did in testing.

The design implication is that your system needs to handle conversation state gracefully across interruptions, repairs, and course corrections — not just forward-only, linear flows. This is significantly harder to build and test than following a script. Budget for it explicitly.

---

## Lesson 3: The Handoff Is Harder Than the AI

The hardest part of deploying a voice agent is not the AI. It is the moment when the AI needs to stop being the AI.

Every production voice agent needs a handoff protocol — a defined trigger (caller request, complexity threshold, sentiment signal, failure count) and a defined path to a human agent. How that handoff executes has a larger effect on caller satisfaction than almost any other variable.

A warm transfer passes the caller to a human along with a summary of what the AI conversation covered. A cold transfer ends the AI session and transfers the caller to a queue where they start over. The difference in caller experience is enormous. The difference in implementation complexity is also significant: warm transfer requires your voice AI to interface with your telephony infrastructure in real time, and that interface is where most integrations break under load.

Before deployment, define what a handoff looks like in your system. Test it under load. Measure how long callers wait after the AI triggers a transfer. If callers are regularly spending three minutes in a post-AI queue, the AI is not reducing friction — it is creating a new queue before the original one.

---

## Demo Conditions vs Production Conditions

The table below summarises the most consequential differences between the environment a voice AI demo runs in and the environment a production deployment faces.

| Dimension | Demo conditions | Production conditions |
|---|---|---|
| Conversation paths | One or two scripted flows | Hundreds of real-world variations |
| Latency measurement | API inference benchmark | Full pipeline: STT + LLM + TTS + player buffer |
| Audio environment | Studio-quality microphone input | Speakerphone, background noise, mobile compression |
| Language handling | One language, neutral accent | Multiple accents, code-switching, regional vocabulary |
| Handoff scenario | Usually not tested | Critical path that determines CSAT when AI fails |
| Cost basis | Per-request at demo volume | Per-minute × concurrent sessions × peak-hour factor |
| Failure mode visibility | Rare and obvious | Frequent and subtle (incorrect understanding, silent misroutes) |
| Evaluation method | "Does it sound right?" | Escalation rate, resolution rate, CSAT, average handle time |

---

## Lesson 4: Cost Structure Behaves Differently at Scale

Voice AI pricing is quoted in different units depending on the vendor: per minute of conversation, per concurrent session, per successful resolution, or flat monthly fees with usage caps. Each model produces a different unit economics curve, and the model that looks cheapest at low volume often inverts at production scale.

The variable that catches most buyers by surprise is concurrency. If your customer service operation handles 50 simultaneous calls during peak hours, you need 50 concurrent voice agent sessions. If your vendor charges by concurrent session rather than by minute, peak-hour costs can be multiples of off-peak costs — and average-cost estimates built on monthly call volume flatten this variability in ways that obscure the real number.

Before signing a contract, model the cost under three scenarios: average load, peak hour, and peak day (the day of your highest annual call volume, whether that is a product launch, a service incident, or a seasonal spike). Ask your vendor what happens to performance and billing if you exceed their stated concurrency limits. The answer matters.

---

## Lesson 5: Evaluation Requires a Different Discipline

Software testing produces a binary result: the code either passes or fails. Voice AI evaluation produces a distribution: the agent handles some percentage of conversations successfully, some percentage imperfectly but acceptably, and some percentage poorly. Defining what falls into each category — and measuring it reliably — is a discipline most engineering teams have not had to develop before.

The metrics that matter in production are not the ones that look good in a vendor dashboard. Escalation rate (what percentage of conversations the AI cannot resolve without human intervention) is the clearest signal of whether the agent is working. Escalation rate should trend down as the system learns; if it holds flat or rises, the agent's knowledge base or dialogue design needs attention.

Resolution rate — the percentage of calls that reach a defined successful outcome without escalation — is the metric that maps most directly to operational impact. Set a baseline before deployment, measure it monthly, and investigate any decline above 5 percentage points.

Conversation-level listening is also essential in early deployment. This means having a human review a random sample of actual transcripts regularly — not to find individual errors, but to identify systematic patterns: question types the agent consistently misunderstands, knowledge gaps that recur across callers, handoff triggers that fire too early or too late.

---

## Lesson 6: Multilingual Is Not a Feature Toggle

Most major voice AI platforms support multiple languages. "Support" in this context means the STT and TTS layers can process audio in those languages. It does not mean that an agent designed for English-speaking callers will perform equivalently for French or Italian callers.

The knowledge base needs to be translated and adapted — not literally translated, but culturally adapted. Business vocabulary, politeness conventions, and the way customers phrase common questions vary meaningfully across languages. A French caller asking about delivery times may structure the question differently from an Italian caller asking the same question, and an agent trained only on English examples may not handle both idiom variants reliably.

Plan multilingual deployment as a separate workstream, not an extension of the original deployment. It requires native-language content review, testing with native speakers, and separate monitoring of escalation and resolution rates by language. The operational cost of multilingual voice AI is roughly 1.5–2× that of a single-language deployment; budget accordingly.

---

## What to Take Into Your Next Voice AI Decision

If you are evaluating voice AI — whether to build it yourself, buy a point solution, or work with a vendor — these are the questions that the demo does not answer:

What is the end-to-end latency from my geographic region, under peak load, with my full stack assembled? Not the model inference benchmark — the number a caller experiences.

How does the handoff work, technically, and what happens to a caller if the handoff fails?

What is the cost at peak concurrent load, not at average monthly volume?

What does escalation rate look like at similar deployments, and what is the vendor's mechanism for reducing it over time?

These are not hostile questions. They are the questions any system going into production deserves to have answered before it goes live.

---

## FAQ

**How long does it take to go from first prototype to a voice agent handling real customer calls?**

For a single-language agent with a defined scope — say, appointment booking or order status — a realistic timeline from kickoff to production is eight to twelve weeks. This includes knowledge base development, conversation flow design, integration with your telephony infrastructure, testing under realistic conditions, and staff training on handoff protocols. Multilingual deployment adds six to eight weeks per additional language if done properly.

**Should we build our own voice AI or use a vendor platform?**

For most organisations, buying a platform is the right starting point. Building a production voice AI stack from scratch requires expertise in speech recognition, language models, text-to-speech, telephony integration, and conversation design simultaneously. Very few teams have all of these in-house. A vendor platform lets you start with a functioning foundation and invest engineering effort in the integration and customisation that generates competitive differentiation. See our [build vs buy decision framework](/blog/build-vs-buy-ai-automation) for a structured way to evaluate this.

**What is the biggest mistake organisations make in their first voice AI deployment?**

Scoping too broadly. The agents that succeed in early deployment are the ones with a clearly defined task — a specific type of call, a bounded set of questions, a single customer journey. Agents asked to handle everything a human receptionist handles will fail at the edges and erode confidence in the entire programme. Start narrow, measure, and expand based on evidence. This pattern applies equally to any AI pilot; we cover it in detail in [your first AI project](/blog/first-ai-project-how-to-choose).

**How do we know if the voice agent is actually working?**

Set three baseline metrics before go-live: escalation rate, resolution rate, and average handle time. Measure weekly for the first three months. A working deployment should show escalation rate declining and resolution rate improving as the system learns. If neither metric moves after six weeks, the knowledge base or dialogue design needs review — not the AI layer. For a complete measurement framework, see our [AI automation ROI calculation guide](/blog/ai-automation-roi-calculation-guide).

---

Building anything in production teaches you things that theory cannot. The lessons above are not an argument against voice AI — they are an argument for going into it with accurate expectations, the right questions, and enough runway to iterate. The organisations getting real operational value from voice AI today are not the ones who deployed fastest. They are the ones who measured carefully, adjusted based on evidence, and treated deployment as the beginning of the work rather than the end of it.

For more on what production AI deployment actually involves, see our guides on [why AI pilots fail to scale](/blog/ai-pilot-to-production-playbook) and the [hidden costs of AI automation](/blog/hidden-costs-ai-automation). If you are setting disclosure policies for a voice AI deployment, the [regulatory requirements that came into force in August 2026](/blog/voice-ai-regulation-outlook) are also required reading.

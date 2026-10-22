---
title: "Voice AI Quality: Latency, Interruptions and Handoffs"
description: "Voice AI trust rests on turn gap, interruptions and handoffs. Sourced latency figures, seven vendor questions and starting points for an acceptance test."
noBrandSuffix: "true"
date: "2026-10-22"
category: "Voice AI"
readingTime: "9"
keywords: "voice AI latency, voice AI quality benchmarks, mouth-to-ear latency, conversational AI response time, voice AI interruption handling, voice AI handoff, speech recognition accuracy, voice AI evaluation criteria"
---

# What "Good" Voice AI Sounds Like: Latency, Interruptions, and Handoffs

Three measurements decide whether callers trust a voice agent: the gap between the caller's last word and the agent's first audio, how often the agent wrongly stops or wrongly talks over the caller, and whether a transfer reaches a human together with a usable brief. Twilio's published guidance for a standard speech-to-text, language model and text-to-speech agent budgets about 1.1 seconds from the caller's last word to the reply reaching their ear, so a vendor quoting far less owes you the conditions it was measured under.

This guide gives you the sourced numbers that exist, says plainly where none exist, and ends with questions and acceptance-test starting points you can put into a procurement document.

## The Gap Between Demo and Reality

Every vendor's demo is polished. Three months after deployment, operations is fielding complaints: the system sounds "robotic", cuts customers off mid-sentence, or goes quiet at the moment it should be escalating to a person. The cause is rarely the model. It is the distance between demo conditions and real ones: accents, background noise, overlapping speech, peak load and network variability.

## Dimension 1: Latency

Latency in voice AI is the time between the caller finishing a sentence and the agent's first audio reaching their ear. Engineers call it the turn gap. It is the clearest quality signal because it decides whether the call feels like a conversation or a bad line.

### What a human conversation looks like

Stivers and colleagues measured response timing across ten languages and published it in [PNAS in 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2705608/). The mean response offset across their dataset was +208 ms, with language-specific means within about 250 ms either side of it. People expect a reply to start within a fraction of a second.

Telephony standards give a second reference. [ITU-T G.114](https://www.itu.int/dms_pubrec/itu-t/rec/g/T-REC-G.114-200305-I!!SUM-HTM-E.htm) treats one-way network delay of up to 150 ms as acceptable for most applications and recommends that 400 ms not be exceeded in general network planning. It also notes that highly interactive tasks, voice calls among them, can be affected by much lower delays. G.114 covers transmission time on the network, not an agent's processing time.

Neither source says how long a caller will wait for an AI agent, and we found no published study that does. These numbers describe what callers are used to, not a proven point at which they hang up. Treat any vendor table that maps latency bands to abandonment ("over two seconds and callers assume the line is dead") as that vendor's opinion unless it cites data.

### Where the time goes

In November 2025 Twilio published budget ranges for a cascaded agent, one that passes audio through speech-to-text, a language model and text-to-speech in sequence:

| Measure | Target (ms) | Upper limit (ms) |
|---|---|---|
| Speech-to-text | 350 | 500 |
| Language model, time to first token | 375 | 750 |
| Text-to-speech, time to first byte | 100 | 250 |
| Platform turn gap | 885 | 1,100 |
| Mouth-to-ear turn gap | 1,115 | 1,400 |

Source: Twilio, [Core Latency in AI Voice Agents](https://www.twilio.com/en-us/blog/developers/best-practices/guide-core-latency-ai-voice-agents), 17 November 2025. This is vendor-published engineering guidance. Twilio describes the figures as median benchmarks for the initial launch of a straightforward cascaded agent and as starting points, not best-possible performance. The platform turn gap excludes audio travelling across the internet or phone network. The mouth-to-ear gap includes it.

Two things follow from the table. The three models account for 825 ms of the 1,115 ms target. The rest is audio transport, buffering and the hops between services, so a faster model alone does not buy back the whole gap.

The second is the tail. Twilio warns that smart endpointing, where the system waits when it thinks the caller is still speaking, can lower the median while causing abrupt jumps in tail latency when that prediction is wrong. A median alone can flatter a system that makes one caller in twenty wait.

### How to read a latency claim

Ask four things before comparing any two numbers:

- **Start and end points.** Platform turn gap or mouth-to-ear? The second is what the caller experiences.
- **Median or 95th percentile.** Ask for both, and for what causes the worst calls.
- **Traffic.** Live phone calls at your peak concurrency, or a quiet demo line?
- **Tool calls.** Twilio's figures are core latency and exclude spikes from tool calls. If the agent looks up an order in your ERP mid-turn, that lookup adds to the gap.

Also ask whether the stack streams. One that passes partial results from recogniser to model to speech synthesiser starts speaking before the full answer exists. One that waits for the whole transcript or reply adds that wait to every turn.

## Dimension 2: Interruption Handling

Interruption handling, also called barge-in, decides what the system does when a caller speaks while the agent is still talking. It is the feature most often behind the "robotic" complaints that arrive after launch.

### The two failure modes

**False positives, where the agent is over-sensitive.** It stops the moment it hears any sound: background noise, a cough, the caller saying "mm-hmm". The agent keeps cutting itself off and appears to malfunction. Callers on a shop floor, in a car or in an open office feel it most.

**False negatives, where the agent is under-sensitive.** It talks through a real attempt to interrupt. A caller says "wait, that's not right" or asks for a person, and the agent carries on. This is the failure that damages trust fastest, because the caller can tell they were ignored.

### What to ask for

Interruption systems typically combine volume against a noise floor, speech-like audio content and a minimum duration of speech before the agent stops. Vendors differ on how these are set and whether you can change them for your callers. We give no numeric thresholds because none are standard across stacks.

Ask for false-positive and false-negative rates in three conditions: a quiet office, a contact centre with ambient noise, and a mobile caller in a vehicle. A vendor that cannot produce them from real deployments has not tested in your conditions.

Recovery matters as much as detection. After an interruption the agent should acknowledge it and return to where the conversation was, without the caller starting again. That requires the model layer to hold conversation state, not just the latest utterance.

## Dimension 3: Handoff Quality

The handoff is the moment the agent passes a caller to a person, and the highest-stakes event in a deployment. Done well it is nearly invisible. Done badly it cancels the efficiency the rest of the system delivers.

### A ceiling for handoff time

We use three seconds, from the agent saying "let me connect you" to a person on the line, as an acceptance ceiling. It is our rule of thumb, not a published standard. Past a few seconds of silence, a caller on a phone cannot tell a transfer from a dropped call, so they hang up and your reporting counts a failed handoff.

### The context brief

When the agent hands off, what does the person receive? The minimum we would accept:

- Caller name and account ID, if authenticated
- Reason for the call in one sentence
- Steps the agent already completed, for example "order number confirmed, account verified, refund requested for item 4821"
- A sentiment signal: neutral, frustrated or escalating

A person who starts with the brief does not have to ask the caller to repeat the reason for calling. Ask the vendor for a live handoff and look at the receiving screen at the moment of transfer. If it is blank, or shows only the phone number, the implementation is incomplete.

### Warm and cold transfers

- **Cold transfer:** the agent connects the caller to the next available person and disconnects. The person gets a brief through the CRM or a screen pop, and the caller waits while the call routes.
- **Warm transfer:** the agent stays on the line, introduces the caller, delivers the brief and then drops off. There is no hold time, at the cost of a more involved integration.

If a vendor offers only cold transfer, find out what hold time that means for your queue before you sign.

## Seven Questions Before You Deploy

| # | Question | Why it matters |
|---|---|---|
| 1 | What are your median and 95th-percentile mouth-to-ear latencies at peak load? | The median hides the tail. The 95th percentile is what your worst callers get. |
| 2 | Were those measured on live phone calls, with tool calls included? | Demo lines have no concurrent load and no system lookups. |
| 3 | What are your barge-in false-positive and false-negative rates for mobile callers? | Show the measurement, not a claim. |
| 4 | What does a caller hear if they interrupt mid-answer? | Walk through it in the demo. |
| 5 | What reaches the person at handoff, and how fast? | Watch a live transfer with the receiving screen visible. |
| 6 | Do you support warm transfer? If not, what is the hold time? | It sets the caller's experience of every escalation. |
| 7 | What is your word error rate on my accents and vocabulary? | A benchmark on clean studio audio says little about phone calls. |

## Starting Thresholds for an Acceptance Test

We found no published standard for acceptable quality in AI phone agents. These are starting points we would write into a pilot agreement, to be adjusted against your own traffic. They are our judgement, not industry norms.

- **Turn gap.** Measure median and 95th percentile, mouth-to-ear, on live calls at peak. Compare the median with Twilio's published launch figures of 1,115 ms target and 1,400 ms upper limit. A vendor claiming much better should show the conditions.
- **Barge-in.** Label a sample of your own calls, count both error types, and agree the tolerated rate before the pilot starts.
- **Speech recognition.** Have people transcribe a set of your own recordings, compute the word error rate against them, and agree the pass mark in advance.
- **Handoff.** Three seconds or less to a connected person, with reason, authentication status, steps completed and sentiment on the screen when they pick up.

If your calls end in a system update rather than a transfer, the cost side is in our [cost per resolved call model](/blog/en/cost-per-resolved-call-model.html). The same clock runs on a coaching tool a rep reads mid-sentence, which is why [Rocket Sales Agent](/rocket-sales-agent.html) is measured in seconds to the screen rather than answers per call. For channel choice and for how the technology fits together, see [Voice AI vs Chatbots](/blog/en/voice-ai-vs-chatbots-channel-strategy.html) and [How Voice AI Actually Works](/blog/en/voice-ai-technology-explained-executives.html).

If you are scoping a voice build around your own call flows, our [AI voice agent development](/ai-voice-agents.html) page describes how we work. Any latency figure we quote should come with the four conditions above, and you should hold us to that.

## FAQ

### What causes high latency in voice AI systems?
The recogniser, the model's time to first token and the speech synthesiser, plus audio transport and the hops between services. Endpointing that waits too long, batching instead of streaming, tool calls to back-end systems and under-sized infrastructure at peak load add to that.

### Is one second of latency acceptable for a voice AI phone agent?
Twilio's launch target for a standard agent is about 1.1 seconds mouth-to-ear at the median, so one second is ordinary today. People answer each other in about 200 ms, so a simple confirmation will feel slow. Test with your own callers and watch for repeats and abandonment.

### How do I test voice AI quality before signing a contract?
Ask for a pilot on real call traffic, not a sandbox demo. As a rule of thumb, wait for several hundred live calls before reading percentiles, so the 95th is not decided by a handful of calls. Ask for a dashboard of latency percentiles, barge-in events and handoff outcomes.

### What is word error rate and what is a good target?
Word error rate (WER) is the share of words a speech-to-text system gets wrong against a human transcript. There is no universal good target, because it depends on audio quality, accents and vocabulary. Agree the pass mark in advance, measure it on your own recordings, and discount any figure from clean studio speech.

### Can voice AI handle interruptions as well as a person?
Not in every condition. An agent working from audio can be fooled by background noise and by short acknowledgements such as "mm-hmm". We found no independent benchmark comparing agents with people, so test with your callers and keep a simple route to a human.

Sources fetched on 22 October 2026: Stivers et al., PNAS 2009 (via PubMed Central); ITU-T G.114 summary (2003); Twilio, Core Latency in AI Voice Agents (17 November 2025).

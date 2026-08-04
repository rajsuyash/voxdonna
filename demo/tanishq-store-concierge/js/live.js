/* Tanishq Store Concierge — live demo client.
 *
 * Unlike the other WhatsApp demo pages on this site, nothing here is scripted.
 * The composer talks to the real DM Champ agent over the chat-widget protocol,
 * so what you see is what a customer would get on WhatsApp.
 *
 * Protocol notes (read from DM Champ's own widget bundle — none of it is
 * guessable from the API docs, and getting any of it wrong fails silently):
 *   - Sending needs a short-lived session JWT from POST /chat-widget-session,
 *     sent as a Bearer token, with the body form-urlencoded as customData[...]
 *     keys. messageSid is required.
 *   - On GET /chat-widget-messages the params are INVERTED relative to their
 *     names: fromId is the account uid, toId is the visitor id.
 *   - The thread comes back newest-first.
 */
(function () {
  "use strict";

  var API = "https://api.dmchamp.com/v1";
  var CONFIG_ID = "fkQDYdmgVNixvGpW08Fs";
  var UID = "emMjeUiU75XVMaLUXY0BeIrZ9kj2";
  var CAMPAIGN_ID = "Lj4t3rhQRfW0PlOe4nW5";

  var POLL_MS = 3000;
  var QUIET_MS = 9000;   // stop waiting once replies stop arriving for this long
  var MAX_WAIT_MS = 240000;

  var SCENARIOS = [
    { emo: "💍", title: "Anniversary gift", sub: "Recommends real pieces to a budget",
      msg: "Our 15th anniversary is coming up. Looking for something for my wife, around 2 lakhs, she likes understated things." },
    { emo: "📍", title: "Nearest showroom", sub: "Shares a live Google Maps link",
      msg: "Which Tanishq showroom is closest to me? I'm in Hyderabad." },
    { emo: "📅", title: "Book a visit", sub: "Books a private consultation",
      msg: "Can I book a time to come in this Saturday afternoon?" },
    { emo: "💎", title: "Bridal shopping", sub: "Rivaah collection, high ticket",
      msg: "My daughter's wedding is in November. What do you have for a bridal necklace set?" },
    { emo: "❓", title: "Trust questions", sub: "Certification, exchange, gold rate",
      msg: "Is your gold hallmarked, and do you take old gold in exchange?" },
    { emo: "🙋", title: "Asks for a discount", sub: "Hands off to a human — never negotiates",
      msg: "Can you do 30% off on making charges if I buy today?" }
  ];

  var el = {
    thread: document.getElementById("thread"),
    chips: document.getElementById("chips"),
    input: document.getElementById("msg"),
    send: document.getElementById("send"),
    reset: document.getElementById("reset"),
    status: document.getElementById("hstatus"),
    scnlist: document.getElementById("scnlist")
  };

  var visitor = null;
  var token = null;
  var tokenExpiresAt = 0;
  var seenOutbound = 0;
  var busy = false;

  // --- helpers --------------------------------------------------------------

  function newVisitor() {
    return "web-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
  }

  function loadVisitor() {
    try {
      var v = localStorage.getItem("tanishq-demo-visitor");
      if (v) return v;
    } catch (e) { /* private mode */ }
    return null;
  }

  function saveVisitor(v) {
    try { localStorage.setItem("tanishq-demo-visitor", v); } catch (e) { /* ignore */ }
  }

  function clock() {
    var d = new Date();
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Escape first, then linkify — order matters or we'd inject the tags we just escaped.
  function render(body) {
    return escapeHtml(body).replace(
      /(https?:\/\/[^\s<]+)/g,
      function (u) { return '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + u + "</a>"; }
    ).replace(/\n/g, "<br>");
  }

  function bubble(side, body) {
    var row = document.createElement("div");
    row.className = "row " + side;
    row.innerHTML =
      '<div class="bubble ' + (side === "out" ? "b-out" : "b-in") + '">' +
      render(body) +
      '<span class="meta">' + clock() + (side === "out" ? ' <span class="ticks">✓✓</span>' : "") + "</span></div>";
    el.thread.appendChild(row);
    el.thread.scrollTop = el.thread.scrollHeight;
    return row;
  }

  function systemNote(text) {
    var row = document.createElement("div");
    row.className = "row sys";
    row.innerHTML = '<div class="syschip">' + escapeHtml(text) + "</div>";
    el.thread.appendChild(row);
    el.thread.scrollTop = el.thread.scrollHeight;
  }

  function typingOn() {
    if (document.getElementById("typing-row")) return;
    var row = document.createElement("div");
    row.className = "row in";
    row.id = "typing-row";
    row.innerHTML = '<div class="bubble b-in"><div class="typing"><span></span><span></span><span></span></div></div>';
    el.thread.appendChild(row);
    el.thread.scrollTop = el.thread.scrollHeight;
    el.status.textContent = "typing…";
  }

  function typingOff() {
    var row = document.getElementById("typing-row");
    if (row) row.remove();
    el.status.textContent = "online";
  }

  function setBusy(state) {
    busy = state;
    el.send.disabled = state;
    el.input.disabled = state;
    el.chips.classList.toggle("empty", state);
  }

  // --- API ------------------------------------------------------------------

  function getToken() {
    if (token && tokenExpiresAt > Date.now() + 60000) return Promise.resolve(token);
    return fetch(API + "/chat-widget-session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ configId: CONFIG_ID, userId: UID, campaignId: CAMPAIGN_ID })
    })
      .then(function (r) {
        if (!r.ok) throw new Error("session mint failed: " + r.status);
        return r.json();
      })
      .then(function (d) {
        token = d.token;
        tokenExpiresAt = d.expiresAt || Date.now() + 3600000;
        return token;
      });
  }

  function postMessage(text) {
    return getToken().then(function (tok) {
      var now = Date.now();
      var form = new URLSearchParams();
      form.append("customData[messageSid]", "web-" + now);
      form.append("customData[fromId]", visitor);
      form.append("customData[toId]", UID);
      form.append("customData[body]", text);
      form.append("customData[status]", "received");
      form.append("customData[channel]", "chat-widget");
      form.append("customData[campaignId]", CAMPAIGN_ID);
      form.append("messageType", "text");

      return fetch(API + "/incoming-chat-widget-message?userId=" + UID + "&ts=" + now, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + tok,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: form.toString()
      }).then(function (r) {
        if (!r.ok) throw new Error("send failed: " + r.status);
        return r.json();
      });
    });
  }

  function fetchThread() {
    // fromId/toId are inverted here on purpose — see the header comment.
    var url = API + "/chat-widget-messages?fromId=" + encodeURIComponent(UID) +
      "&toId=" + encodeURIComponent(visitor) + "&userId=" + encodeURIComponent(UID) +
      "&ts=" + Date.now();
    return fetch(url).then(function (r) {
      if (!r.ok) throw new Error("thread fetch failed: " + r.status);
      return r.json();
    }).then(function (d) {
      var msgs = Array.isArray(d) ? d : (d && d.messages) || [];
      return {
        messages: msgs.slice().reverse(), // newest-first -> chronological
        botTyping: !Array.isArray(d) && !!(d && d.isBotTyping)
      };
    });
  }

  // Replies arrive as a burst of several short messages. Render each as it
  // lands, and stop once nothing new has arrived for QUIET_MS.
  function awaitReplies() {
    var started = Date.now();
    var lastArrival = Date.now();
    typingOn();

    return new Promise(function (resolve) {
      var timer = setInterval(function () {
        fetchThread().then(function (res) {
          var out = res.messages.filter(function (m) { return m.direction === "outbound"; });
          if (out.length > seenOutbound) {
            typingOff();
            out.slice(seenOutbound).forEach(function (m) { bubble("in", m.body); });
            seenOutbound = out.length;
            lastArrival = Date.now();
            typingOn();
          }
          // The API tells us when the agent is mid-thought. Never give up while
          // it is still typing — first replies routinely take 25-40s.
          if (res.botTyping) lastArrival = Date.now();

          var quiet = Date.now() - lastArrival > QUIET_MS;
          var expired = Date.now() - started > MAX_WAIT_MS;
          if ((seenOutbound > 0 && quiet) || expired) {
            clearInterval(timer);
            typingOff();
            if (seenOutbound === 0) {
              systemNote("The agent is taking longer than usual. Tap ⟳ to start a fresh conversation.");
            }
            resolve();
          }
        }).catch(function () { /* transient — keep polling */ });
      }, POLL_MS);
    });
  }

  // --- interaction ----------------------------------------------------------

  function submit(text) {
    if (busy) return;
    text = (text || "").trim();
    if (!text) return;

    bubble("out", text);
    el.input.value = "";
    setBusy(true);

    postMessage(text)
      .then(awaitReplies)
      .catch(function (err) {
        typingOff();
        systemNote("Couldn't reach the agent: " + err.message);
      })
      .then(function () { setBusy(false); el.input.focus(); });
  }

  function buildScenarios() {
    SCENARIOS.forEach(function (s) {
      var btn = document.createElement("button");
      btn.className = "scn";
      btn.innerHTML = '<span class="scn-emo">' + s.emo + '</span>' +
        '<span class="scn-tx"><b>' + escapeHtml(s.title) + "</b><i>" + escapeHtml(s.sub) + "</i></span>";
      btn.addEventListener("click", function () {
        if (busy) return;
        document.querySelectorAll(".scn.active").forEach(function (n) { n.classList.remove("active"); });
        btn.classList.add("active");
        submit(s.msg);
      });
      el.scnlist.appendChild(btn);
    });
  }

  function startConversation(fresh) {
    if (fresh || !loadVisitor()) {
      visitor = newVisitor();
      saveVisitor(visitor);
      el.thread.innerHTML = "";
      seenOutbound = 0;
      systemNote("Messages are end-to-end encrypted. This is a live AI agent.");
      bubble("in", "Hi Aryan this side, store manager at Tanishq, please let me know how can I help you today");
    } else {
      visitor = loadVisitor();
      el.thread.innerHTML = "";
      seenOutbound = 0;
      systemNote("Messages are end-to-end encrypted. This is a live AI agent.");
      fetchThread().then(function (res) {
        var msgs = res.messages;
        if (!msgs.length) {
          bubble("in", "Hi Aryan this side, store manager at Tanishq, please let me know how can I help you today");
          return;
        }
        msgs.forEach(function (m) {
          bubble(m.direction === "outbound" ? "in" : "out", m.body);
        });
        seenOutbound = msgs.filter(function (m) { return m.direction === "outbound"; }).length;
      }).catch(function () {
        bubble("in", "Hi Aryan this side, store manager at Tanishq, please let me know how can I help you today");
      });
    }
  }

  el.send.addEventListener("click", function () { submit(el.input.value); });
  el.input.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); submit(el.input.value); }
  });
  el.reset.addEventListener("click", function () {
    if (busy) return;
    document.querySelectorAll(".scn.active").forEach(function (n) { n.classList.remove("active"); });
    startConversation(true);
  });

  buildScenarios();
  startConversation(false);
})();

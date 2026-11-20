(function () {
  "use strict";

  const NS = (window.PHISHDETECT = window.PHISHDETECT || {});
  const DANGEROUS_EXT = /\.(exe|scr|js|vbs|bat|cmd|ps1|iso|lnk|xlsm|docm|html?)$/i;
  const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly"];

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function hostOf(url) {
    const m = (url || "").match(/^https?:\/\/([^/:?#]+)/i);
    return m ? m[1].toLowerCase() : "";
  }

  function extOf(filename) {
    const m = (filename || "").match(/(\.[^.]+)$/);
    return m ? m[1].toLowerCase() : "";
  }

  function authBadge(val) {
    const v = (val || "none").toLowerCase();
    if (v === "pass")                       return '<span class="badge safe">pass</span>';
    if (v === "fail" || v === "softfail")   return '<span class="badge malicious">' + esc(v) + "</span>";
    return '<span class="badge suspicious">' + esc(v) + "</span>";
  }

  function urlRisks(url) {
    const host = hostOf(url);
    const risks = [];
    if (!host) return risks;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) risks.push("IP brute comme domaine");
    if (SHORTENERS.includes(host))             risks.push("URL raccourcie");
    if (/^http:\/\//i.test(url))               risks.push("HTTP non chiffré");
    if (host.split(".").length >= 5)           risks.push("Sous-domaines multiples");
    if (url.includes("@"))                     risks.push("Caractère @ dans l'URL");
    if (url.length > 90)                       risks.push("URL très longue");
    return risks;
  }

  function attachRisks(filename) {
    return DANGEROUS_EXT.test(filename) ? ["Extension dangereuse"] : [];
  }

  function simulatedReceived(email) {
    const addr  = (email.sender && email.sender.email) || "";
    const domain = addr.includes("@") ? addr.split("@")[1] : "unknown.test";
    const date   = email.date || new Date().toISOString();
    return [
      "from mail." + domain + " ([10.0.1.2]) by mx.dest.example.test with ESMTPS id sim001; " + date,
      "from [192.168.0.5] (helo=" + domain + ") by mail." + domain + " with ESMTP id sim002; " + date
    ];
  }

  function getDemoEmails() {
    return (window.PHISHDETECT_DATA && Array.isArray(window.PHISHDETECT_DATA.emails))
      ? window.PHISHDETECT_DATA.emails : [];
  }

  function getHistory() {
    return NS.storage ? NS.storage.get("history", []) : [];
  }

  function findFullEmail(id) {
    return getDemoEmails().find(function (e) { return e.id === id; }) || null;
  }

  /* ── Render the detail panel for one email ─────────────────────────── */
  function renderDetails(email) {
    const A      = NS.analyzer;
    const result = A ? A.analyzeEmail(email) : { score: 0, level: "—", classification: "—", color: "green", indicators: [] };
    const color  = result.color || "green";
    const gaugeColor = { green: "var(--safe)", orange: "var(--warn)", red: "var(--danger)" }[color] || "var(--safe)";
    const badgeCls   = { green: "safe", orange: "suspicious", red: "malicious" }[color] || "";
    const auth       = email.auth || {};
    const received   = simulatedReceived(email);
    const urls       = email.urls || [];
    const attachments = email.attachments || [];

    /* URLs */
    const urlsHtml = urls.length
      ? urls.map(function (url) {
          const host  = hostOf(url);
          const risks = urlRisks(url);
          const proto = /^http:\/\//i.test(url) ? "HTTP" : "HTTPS";
          return "<li class='inv-url-item'>"
            + "<span class='inv-url-host'>" + esc(host || url) + "</span>"
            + "<span class='inv-url-proto muted'>" + esc(proto) + "</span>"
            + (risks.map(function (r) { return "<span class='badge suspicious'>" + esc(r) + "</span>"; }).join(""))
            + (!risks.length ? "<span class='badge safe'>OK</span>" : "")
            + "</li>";
        }).join("")
      : "<li class='muted'>Aucune URL détectée.</li>";

    /* Attachments */
    const attachHtml = attachments.length
      ? attachments.map(function (f) {
          const ext   = extOf(f);
          const risks = attachRisks(f);
          return "<li class='inv-attach-item'>"
            + "<span class='inv-attach-name'>" + esc(f) + "</span>"
            + "<span class='badge suspicious'>" + esc(ext || "?") + "</span>"
            + (risks.map(function (r) { return "<span class='badge malicious'>" + esc(r) + "</span>"; }).join(""))
            + (!risks.length ? "<span class='badge safe'>Extension sûre</span>" : "")
            + "</li>";
        }).join("")
      : "<li class='muted'>Aucune pièce jointe.</li>";

    /* Indicators */
    const indicatorsHtml = result.indicators && result.indicators.length
      ? result.indicators.map(function (i) {
          return "<li class='inv-indicator-item'>"
            + "<span>" + esc(i.label) + "</span>"
            + "<span class='pts'>+" + i.points + "</span>"
            + "<small class='muted'>" + esc(i.category) + "</small>"
            + "</li>";
        }).join("")
      : "<li class='muted'>Aucun indicateur détecté.</li>";

    /* History-only warning */
    const historyWarning = email._historyOnly
      ? "<div class='card inv-history-notice'><p class='muted'>"
        + "⚠ Cet e-mail provient uniquement de l'historique (analyse manuelle). "
        + "Les URLs, pièces jointes et corps ne sont pas disponibles afin de protéger la confidentialité."
        + "</p></div>"
      : "";

    const senderName  = (email.sender && email.sender.name)       || "";
    const senderEmail = (email.sender && email.sender.email)      || "—";
    const replyTo     = (email.sender && email.sender.replyTo)    || "—";
    const returnPath  = (email.sender && email.sender.returnPath) || "—";

    return historyWarning + "\n"
      + "<div class='inv-results'>"

      /* Score card */
      + "<div class='card inv-score-card'>"
      +   "<div class='inv-score-gauge' style='background:conic-gradient(" + gaugeColor + " " + (result.score * 3.6) + "deg,#1d3560 0)'>"
      +     "<div class='inv-score-inner'><strong>" + result.score + "</strong><small>/100</small></div>"
      +   "</div>"
      +   "<div class='inv-score-info'>"
      +     "<span class='badge " + badgeCls + "'>" + esc(result.classification) + "</span>"
      +     "<h3>Niveau de risque : " + esc(result.level) + "</h3>"
      +     "<p class='muted'>" + result.indicators.length + " indicateur(s) détecté(s).</p>"
      +   "</div>"
      + "</div>"

      /* 4-column grid */
      + "<div class='inv-grid'>"

        /* Headers */
        + "<div class='card'>"
        +   "<h3>En-têtes</h3>"
        +   "<dl class='inv-headers'>"
        +     "<dt>De (From)</dt><dd>" + esc(senderName ? senderName + " <" + senderEmail + ">" : senderEmail) + "</dd>"
        +     "<dt>Reply-To</dt><dd>" + esc(replyTo) + "</dd>"
        +     "<dt>Return-Path</dt><dd>" + esc(returnPath) + "</dd>"
        +     "<dt>Objet</dt><dd>" + esc(email.subject || "—") + "</dd>"
        +     "<dt>Date</dt><dd>" + esc(email.date || "—") + "</dd>"
        +   "</dl>"
        +   "<h4 class='inv-sub-title'>En-têtes Received <span class='badge suspicious'>simulés</span></h4>"
        +   "<ul class='inv-received-list'>"
        +     received.map(function (r) { return "<li><code>" + esc(r) + "</code></li>"; }).join("")
        +   "</ul>"
        + "</div>"

        /* Auth + Indicators */
        + "<div class='card'>"
        +   "<h3>Authentification</h3>"
        +   "<dl class='inv-headers'>"
        +     "<dt>SPF</dt><dd>"  + authBadge(auth.spf)  + "</dd>"
        +     "<dt>DKIM</dt><dd>" + authBadge(auth.dkim) + "</dd>"
        +     "<dt>DMARC</dt><dd>"+ authBadge(auth.dmarc)+ "</dd>"
        +   "</dl>"
        +   "<h4 class='inv-sub-title'>Indicateurs d'analyse</h4>"
        +   "<ul class='inv-indicator-list'>" + indicatorsHtml + "</ul>"
        + "</div>"

        /* URLs */
        + "<div class='card'>"
        +   "<h3>URLs détectées</h3>"
        +   "<p class='muted'>Hôtes uniquement — aucun lien n'est ouvert ni visité.</p>"
        +   "<ul class='inv-url-list'>" + urlsHtml + "</ul>"
        + "</div>"

        /* Attachments */
        + "<div class='card'>"
        +   "<h3>Pièces jointes</h3>"
        +   "<p class='muted'>Noms et extensions uniquement — aucun fichier n'est ouvert ni exécuté.</p>"
        +   "<ul class='inv-attach-list'>" + attachHtml + "</ul>"
        + "</div>"

      + "</div>" /* /inv-grid */
      + "</div>"; /* /inv-results */
  }

  /* ── Build the selector UI and wire events ──────────────────────────── */
  function render() {
    const view = document.getElementById("view-investigation");
    if (!view) return;

    const demos   = getDemoEmails();

    view.innerHTML =
      "<div class='inv-module'>"
      + "<div class='inv-header'>"
      +   "<div><h2>Investigation d'e-mail</h2>"
      +   "<p class='muted'>Sélectionnez un e-mail pour analyser ses en-têtes, URLs, pièces jointes et indicateurs de risque. Aucun lien n'est ouvert.</p></div>"
      + "</div>"

      + "<div class='card inv-selector'>"
      +   "<div class='inv-selector-row'>"
      +     "<div class='inv-selector-group'>"
      +       "<label for='inv-source' class='inv-label'>Source</label>"
      +       "<select id='inv-source' class='input'>"
      +         "<option value='demo'>E-mails de démonstration</option>"
      +         "<option value='history'>Historique d'analyses</option>"
      +       "</select>"
      +     "</div>"
      +     "<div class='inv-selector-group inv-selector-group--wide'>"
      +       "<label for='inv-email-select' class='inv-label'>E-mail à investiguer</label>"
      +       "<select id='inv-email-select' class='input'><option value=''>-- Choisir --</option></select>"
      +     "</div>"
      +     "<button class='btn-primary' id='inv-load-btn'>Investiguer</button>"
      +   "</div>"
      + "</div>"

      + "<div id='inv-detail'></div>"
      + "</div>";

    const sourceEl = document.getElementById("inv-source");
    const selectEl = document.getElementById("inv-email-select");
    const loadBtn  = document.getElementById("inv-load-btn");
    const detail   = document.getElementById("inv-detail");

    function populateSelect() {
      /* Use textContent via DOM to keep values safe */
      while (selectEl.options.length > 0) selectEl.remove(0);
      var placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "-- Choisir --";
      selectEl.appendChild(placeholder);

      if (sourceEl.value === "demo") {
        demos.forEach(function (e) {
          var opt = document.createElement("option");
          opt.value = e.id;
          opt.textContent = e.id + " — " + (e.subject || "Sans objet");
          selectEl.appendChild(opt);
        });
      } else {
        var h = getHistory();
        if (!h.length) {
          var noOpt = document.createElement("option");
          noOpt.value = "";
          noOpt.textContent = "Aucune analyse dans l'historique";
          noOpt.disabled = true;
          selectEl.appendChild(noOpt);
        } else {
          h.forEach(function (entry, i) {
            var opt = document.createElement("option");
            opt.value = "hist:" + i;
            opt.textContent = (entry.id || "?") + " — " + (entry.subject || "Sans objet");
            selectEl.appendChild(opt);
          });
        }
      }
    }

    populateSelect();

    sourceEl.addEventListener("change", function () {
      populateSelect();
      detail.innerHTML = "";
    });

    loadBtn.addEventListener("click", function () {
      var val = selectEl.value;
      if (!val) {
        detail.innerHTML = "<div class='card'><p class='muted'>Veuillez sélectionner un e-mail.</p></div>";
        return;
      }

      var email = null;

      if (sourceEl.value === "demo") {
        email = demos.find(function (e) { return e.id === val; }) || null;
      } else {
        var h   = getHistory();
        var idx = parseInt(val.replace("hist:", ""), 10);
        var entry = h[idx];
        if (entry) {
          /* Try to find the full email from demo data first */
          email = findFullEmail(entry.id);
          if (!email) {
            /* Fallback: build minimal object from history metadata only */
            email = {
              id: entry.id,
              sender: {
                name: "",
                email: entry.sender || "",
                replyTo: "",
                returnPath: ""
              },
              subject:     entry.subject || "",
              date:        entry.date    || "",
              body:        "",
              urls:        [],
              attachments: [],
              auth: { spf: "none", dkim: "none", dmarc: "none" },
              _historyOnly: true
            };
          }
        }
      }

      if (!email) {
        detail.innerHTML = "<div class='card'><p class='muted'>E-mail introuvable.</p></div>";
        return;
      }

      detail.innerHTML = renderDetails(email);
      if (window.lucide) lucide.createIcons();
      /* Scroll details into view on mobile */
      detail.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    if (window.lucide) lucide.createIcons();
  }

  document.addEventListener("view:change", function (e) {
    if (e.detail && e.detail.view === "investigation") render();
  });

  NS.investigation = { render: render };

  var invView = document.getElementById("view-investigation");
  if (invView && invView.classList.contains("active")) render();
})();

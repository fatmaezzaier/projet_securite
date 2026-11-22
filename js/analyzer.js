(function () {
  const BRANDS = {
    microsoft: "microsoft.com",
    technova: "technova-demo.test",
    google: "google.com",
    paypal: "paypal.com",
    amazon: "amazon.com",
    colis: "colis-express.fr"
  };
  const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly"];
  const DANGEROUS_EXT = /\.(exe|scr|js|vbs|bat|cmd|ps1|iso|lnk|xlsm|docm|html?)$/i;

  const RULES = {
    urgence: { re: /urgent|immédiat|sans délai|dans les \d+ (heures|minutes)|expir|within \d+ hours|asap/i, pts: 10, cat: "Contenu", label: "Urgence" },
    menace: { re: /suspen|bloqu|fermé|sanction|poursuite|suspended|locked|terminated/i, pts: 10, cat: "Contenu", label: "Menace (suspension, blocage)" },
    identifiants: { re: /mot de passe|password|identifiants?|credentials?|code mfa|code pin|numéro de carte/i, pts: 20, cat: "Contenu", label: "Demande de mot de passe ou d'identifiants" },
    paiement: { re: /paiement|payer|frais|règlement|€|\$|payment|fee/i, pts: 10, cat: "Contenu", label: "Demande de paiement" },
    financier: { re: /virement|\bRIB\b|iban|wire transfer|bank transfer|coordonnées bancaires/i, pts: 15, cat: "Contenu", label: "Instruction financière inhabituelle" },
    confidentiel: { re: /confidentiel|sans en parler|ne (le )?dites? à personne|confidential|do not tell/i, pts: 10, cat: "Contenu", label: "Demande de confidentialité" },
    ciJoint: { re: /ci-joint|pièce jointe|attached/i, pts: 5, cat: "Contenu", label: "Référence à une pièce jointe" }
  };

  function levenshtein(a, b) {
    const m = [];
    for (let i = 0; i <= a.length; i++) { m[i] = [i]; }
    for (let j = 0; j <= b.length; j++) { m[0][j] = j; }
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        m[i][j] = Math.min(m[i-1][j] + 1, m[i][j-1] + 1, m[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
      }
    }
    return m[a.length][b.length];
  }

  function domainOf(value) {
    const match = (value || "").match(/@([^>\s]+)/) || (value || "").match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase().replace(/\.$/, "") : "";
  }

  function hostOf(url) {
    const m = (url || "").match(/^https?:\/\/([^/:?#]+)/i);
    return m ? m[1].toLowerCase() : "";
  }

  function leetVariants(s) {
    const base = (s || "").replace(/0/g, "o").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/@/g, "a");
    return [base.replace(/1/g, "i"), base.replace(/1/g, "l")];
  }

  function isOfficial(host, domain) {
    return host === domain || host.endsWith("." + domain);
  }

  // Détecte un domaine imitant une marque connue (sans jamais le visiter)
  function brandLookalike(host) {
    if (!host) return null;
    const variants = leetVariants(host);
    for (const [brand, domain] of Object.entries(BRANDS)) {
      if (isOfficial(host, domain)) return null;
      for (const norm of variants) {
        if (norm.includes(brand)) {
          const kind = host.toLowerCase().includes(brand) ? "contient la marque" : "typosquatting";
          return { brand, kind };
        }
        const label = norm.split(".")[0];
        if (levenshtein(label, brand) <= 2) return { brand, kind: "typosquatting" };
      }
    }
    return null;
  }

  function checkContent(email, add) {
    const text = (email.subject || "") + " " + (email.body || "");
    for (const rule of Object.values(RULES)) {
      if (rule.re.test(text)) add(rule.cat, rule.label, rule.pts);
    }
    const letters = text.replace(/[^A-Za-zÀ-ÿ]/g, "");
    const upper = text.replace(/[^A-ZÀ-Ý]/g, "");
    if (letters.length > 20 && upper.length / letters.length > 0.3) add("Contenu", "Majuscules excessives", 5);
    if (/!{2,}/.test(text)) add("Contenu", "Points d'exclamation répétés", 3);

    const dangerous = (email.attachments || []).filter(f => DANGEROUS_EXT.test(f));
    if (dangerous.length) add("Contenu", "Pièce jointe au format dangereux : " + dangerous.join(", "), 25);
    else if ((email.attachments || []).length && !/ci-joint|pièce jointe|attached|facture|bulletin|fiche/i.test(text)) add("Contenu", "Pièce jointe inattendue", 10);
  }

  function checkSender(email, add) {
    const s = email.sender || {};
    const fromDom = domainOf(s.email);
    const replyDom = domainOf(s.replyTo);
    const retDom = domainOf(s.returnPath);

    if (replyDom && replyDom !== fromDom) add("Expéditeur", "Reply-To différent de l'expéditeur", 15);
    if (retDom && retDom !== fromDom) add("Expéditeur", "Return-Path différent de l'expéditeur", 5);

    const look = brandLookalike(fromDom);
    if (look) {
      const pts = look.kind === "typosquatting" ? 25 : 15;
      add("Expéditeur", `Domaine expéditeur ${look.kind} "${look.brand}"`, pts);
    }

    const nameLower = (s.name || "").toLowerCase();
    for (const [brand, domain] of Object.entries(BRANDS)) {
      if (nameLower.includes(brand) && !isOfficial(fromDom, domain)) {
        if (!look || look.brand !== brand) {
          add("Expéditeur", "Faux nom affiché : la marque ne correspond pas au domaine", 15);
        }
        break;
      }
    }

    const auth = email.auth || {};
    ["spf", "dkim", "dmarc"].forEach(k => {
      const v = (auth[k] || "none").toLowerCase();
      if (v === "fail" || v === "softfail") add("Expéditeur", `Authentification ${k.toUpperCase()} échouée`, k === "dmarc" ? 10 : 8);
      else if (v === "none" || v === "neutral") add("Expéditeur", `Authentification ${k.toUpperCase()} absente`, 3);
    });

    return { look, fromDom };
  }

  function checkUrls(email, add, senderBrandLook, fromDom) {
    const penalizedBrands = new Set(senderBrandLook ? [senderBrandLook.brand] : []);
    (email.urls || []).forEach(url => {
      const host = hostOf(url);
      if (!host) return;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add("URL", `Adresse IP utilisée comme domaine : ${host}`, 25);
      if (SHORTENERS.includes(host)) add("URL", `URL raccourcie : ${host}`, 15);
      const look = brandLookalike(host);
      if (look) {
        if (host !== fromDom && !penalizedBrands.has(look.brand)) {
          add("URL", `Domaine lookalike "${look.brand}" : ${host}`, 20);
          penalizedBrands.add(look.brand);
        }
      }
      if (/^http:\/\//i.test(url)) add("URL", "Lien non chiffré (HTTP)", 10);
      if (host.split(".").length >= 5) add("URL", "Sous-domaines multiples", 8);
      if (url.includes("@")) add("URL", "Caractère @ dans l'URL", 15);
      if (url.length > 90) add("URL", "URL anormalement longue", 5);
    });
  }

  // Analyse les liens HTML dont le texte affiché diffère de la cible réelle
  function checkAnchors(html, add) {
    const re = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      const target = hostOf(m[1]);
      const shown = (m[2].match(/([a-z0-9-]+\.)+[a-z]{2,}/i) || [])[0];
      if (shown && target && !isOfficial(target, shown.toLowerCase())) {
        add("URL", `Texte du lien "${shown}" différent de la cible "${target}"`, 20);
      }
    }
  }

  function levelFor(score) {
    if (score >= 80) return { level: "Critique", classification: "Phishing", color: "red" };
    if (score >= 60) return { level: "Élevé", classification: "Phishing", color: "red" };
    if (score >= 30) return { level: "Moyen", classification: "Suspect", color: "orange" };
    return { level: "Faible", classification: "Légitime", color: "green" };
  }

  function analyzeEmail(email, rawHtml) {
    const found = [];
    const add = (category, label, points) => found.push({ category, label, points });
    checkContent(email, add);
    const { look, fromDom } = checkSender(email, add);
    checkUrls(email, add, look, fromDom);
    if (rawHtml) checkAnchors(rawHtml, add);

    const score = Math.min(100, found.reduce((sum, i) => sum + i.points, 0));
    return { score, ...levelFor(score), indicators: found };
  }

  // Lecture d'un e-mail brut (en-têtes + corps)
  function parseRaw(text) {
    const [headerBlock, ...rest] = text.split(/\r?\n\r?\n/);
    const body = rest.join("\n\n");
    const headers = {};
    headerBlock.split(/\r?\n/).forEach(line => {
      const idx = line.indexOf(":");
      if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    });

    const fromRaw = headers["from"] || "";
    const fromMatch = fromRaw.match(/^(.*?)\s*<([^>]+)>$/);
    const auth = headers["authentication-results"] || "";
    const pick = (k) => ((auth.match(new RegExp(k + "=(\\w+)", "i")) || [])[1] || "none").toLowerCase();
    const attachments = [...(text.matchAll(/filename="?([^";\r\n]+)"?/gi))].map(m => m[1]);

    return {
      id: "RAW-" + Date.now(),
      sender: {
        name: fromMatch ? fromMatch[1].replace(/"/g, "") : "",
        email: fromMatch ? fromMatch[2] : fromRaw,
        replyTo: headers["reply-to"] || "",
        returnPath: headers["return-path"] || ""
      },
      subject: headers["subject"] || "",
      date: headers["date"] || "",
      body,
      urls: body.match(/https?:\/\/[^\s<>"']+/gi) || [],
      attachments,
      auth: { spf: pick("spf"), dkim: pick("dkim"), dmarc: pick("dmarc") },
      rawHtml: /<a\s/i.test(body) ? body : ""
    };
  }

  // Historique local : métadonnées uniquement, jamais le corps du message
  function saveToHistory(email, result, source, dateISO) {
  const store = window.PHISHDETECT.storage;
  const history = store.get("history", []);
  const entry = {
    id: email.id,
    subject: email.subject,
    sender: email.sender.email,
    score: result.score,
    level: result.level,
    classification: result.classification,
    color: result.color,
    indicators: result.indicators.map(i => i.label),
    source,
    date: dateISO || new Date().toISOString()
  };
  history.unshift(entry);
  store.set("history", history.slice(0, 200));
  document.dispatchEvent(new CustomEvent("analysis:saved", { detail: entry }));
}


  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function renderResult(result) {
    const colors = { green: "var(--safe)", orange: "var(--warn)", red: "var(--danger)" };
    const badgeClass = { green: "safe", orange: "suspicious", red: "malicious" }[result.color];
    const list = result.indicators.length
      ? result.indicators.map(i => `<li><span>${esc(i.label)}</span><span class="pts">+${i.points}</span><small>${esc(i.category)}</small></li>`).join("")
      : "<li>Aucun indicateur détecté.</li>";

    return `
      <div class="analysis-result">
        <div class="gauge" style="background: conic-gradient(${colors[result.color]} ${result.score * 3.6}deg, #1d3560 0);">
          <div class="gauge-inner"><strong>${result.score}</strong><small>/100</small></div>
        </div>
        <div class="result-summary">
          <span class="badge ${badgeClass}">${result.classification}</span>
          <h3>Niveau de risque : ${result.level}</h3>
          <p>${result.indicators.length} indicateur(s) détecté(s).</p>
          <ul class="indicator-list">${list}</ul>
        </div>
      </div>`;
  }

  function mount() {
    const view = typeof document !== "undefined" && typeof document.getElementById === "function"
      ? document.getElementById("view-analyzer") : null;
    if (!view) return;
    const demos = window.PHISHDETECT_DATA.emails;

    view.innerHTML = `
      <div class="card analyzer-card">
        <h2>Analyse d'e-mail</h2>
        <p class="muted">Collez un e-mail brut (en-têtes compris) ou choisissez un e-mail de démonstration. Les liens ne sont jamais ouverts.</p>
        <div class="analyzer-controls">
          <select id="anDemo" class="input">
            <option value="">-- Choisir un e-mail de démonstration --</option>
            ${demos.map(e => `<option value="${e.id}">${e.id} - ${esc(e.subject)}</option>`).join("")}
          </select>
          <button class="btn-primary" id="anLoadDemo">Charger</button>
        </div>
        <textarea id="anRaw" class="input textarea" rows="10" placeholder="From: ...&#10;Reply-To: ...&#10;Subject: ...&#10;&#10;Corps du message"></textarea>
        <div class="analyzer-controls">
          <button class="btn-primary" id="anRun">Analyser</button>
          <button class="btn-ghost" id="anClear">Effacer</button>
        </div>
      </div>
      <div id="anResult"></div>`;

    const $ = id => document.getElementById(id);
    let current = null;

    $("anLoadDemo").addEventListener("click", () => {
      const demo = demos.find(e => e.id === $("anDemo").value);
      if (!demo) return;
      current = { email: demo, source: "demo" };
      $("anRaw").value = `From: ${demo.sender.name} <${demo.sender.email}>\nReply-To: ${demo.sender.replyTo}\nReturn-Path: ${demo.sender.returnPath}\nSubject: ${demo.subject}\nDate: ${demo.date}\n\n${demo.body}`;
    });

    $("anRun").addEventListener("click", () => {
      const raw = $("anRaw").value.trim();
      if (!raw) { $("anResult").innerHTML = `<div class="card">Veuillez saisir ou charger un e-mail.</div>`; return; }
      const email = current && current.email.id && raw.includes(current.email.subject) && $("anDemo").value
        ? { ...current.email, auth: current.email.auth }
        : parseRaw(raw);
      const source = current && current.source === "demo" && $("anDemo").value ? "demo" : "manual";
      const result = analyzeEmail(email, email.rawHtml || "");
      $("anResult").innerHTML = renderResult(result);
      saveToHistory(email, result, source);
    });

    $("anClear").addEventListener("click", () => {
      $("anRaw").value = "";
      $("anDemo").value = "";
      $("anResult").innerHTML = "";
      current = null;
    });
  }

window.PHISHDETECT = window.PHISHDETECT || {};
  window.PHISHDETECT.analyzer = { analyzeEmail, parseRaw, levelFor, levenshtein, saveToHistory };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();

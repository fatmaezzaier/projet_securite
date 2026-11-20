(function () {
  const COLORS = { safe: "#22c55e", warn: "#f97316", danger: "#ef4444", blue: "#3b82f6", cyan: "#22d3ee" };
  const CLASS_TO_BADGE = { "Légitime": "safe", "Suspect": "suspicious", "Phishing": "malicious" };
  const DAY = 864e5;
  let charts = {};

  const history = () => window.PHISHDETECT.storage.get("history", []);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function computeStats(h) {
    const count = c => h.filter(x => x.classification === c).length;
    const total = h.length;
    const phishing = count("Phishing");
    const legit = count("Légitime");
    const suspect = count("Suspect");
    const weekAgo = Date.now() - 7 * DAY;
    const active = h.filter(x => x.classification !== "Légitime" && new Date(x.date).getTime() >= weekAgo).length;
    const rate = total ? Math.round(((phishing + suspect) / total) * 100) : 0;

    const indicatorCounts = {};
    h.forEach(x => (x.indicators || []).forEach(label => {
      indicatorCounts[label] = (indicatorCounts[label] || 0) + 1;
    }));
    const topIndicators = Object.entries(indicatorCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

    const days = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * DAY);
      days.push({ key: d.toISOString().slice(0, 10), label: d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }), count: 0 });
    }
    h.forEach(x => {
      const day = days.find(d => d.key === new Date(x.date).toISOString().slice(0, 10));
      if (day && x.classification !== "Légitime") day.count++;
    });

    const levels = { "Faible": 0, "Moyen": 0, "Élevé": 0, "Critique": 0 };
    h.forEach(x => { if (levels[x.level] !== undefined) levels[x.level]++; });

    return { total, phishing, legit, suspect, active, rate, topIndicators, days, levels };
  }

  function kpi(icon, label, value, tone, hint) {
    return `<div class="kpi ${tone || ""}" title="${esc(hint || "")}">
      <i data-lucide="${icon}"></i>
      <div><span>${label}</span><strong>${value}</strong></div>
    </div>`;
  }

  function renderEmpty(view) {
    view.innerHTML = `
      <div class="card empty-state">
        <i data-lucide="database"></i>
        <h2>Aucune analyse enregistrée</h2>
        <p class="muted">Analysez un e-mail dans l'onglet Email Analyzer, ou chargez les 10 e-mails de démonstration pour remplir le tableau de bord.</p>
        <button class="btn-primary" id="dashSeed">Charger les données de démonstration</button>
      </div>`;
    document.getElementById("dashSeed").addEventListener("click", seedDemo);
    lucide.createIcons();
  }

  function seedDemo() {
    const A = window.PHISHDETECT.analyzer;
    window.PHISHDETECT_DATA.emails.forEach((email, i) => {
      const result = A.analyzeEmail(email);
      const date = new Date(Date.now() - ((i * 1.4) + 0.5) * DAY).toISOString();
      A.saveToHistory(email, result, "demo", date);
    });
    render();
  }

  function render() {
    const view = document.getElementById("view-dashboard");
    if (!view) return;
    const h = history();
    if (!h.length) return renderEmpty(view);

    const s = computeStats(h);
    const recent = [...h].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 6);
    const maxLevel = Math.max(1, ...Object.values(s.levels));
    const levelColors = { "Faible": COLORS.safe, "Moyen": "#eab308", "Élevé": COLORS.warn, "Critique": COLORS.danger };

    view.innerHTML = `
      <div class="kpi-grid">
        ${kpi("mail", "Total analysés", s.total, "", "Nombre total d'e-mails analysés")}
        ${kpi("shield-alert", "Phishing détectés", s.phishing, "danger", "Classification Phishing")}
        ${kpi("check-circle", "Légitimes", s.legit, "safe", "Classification Légitime")}
        ${kpi("alert-triangle", "Suspects", s.suspect, "warn", "Classification Suspect")}
        ${kpi("siren", "Incidents actifs", s.active, "cyan", "Messages signalés au cours des 7 derniers jours")}
        ${kpi("percent", "Taux de détection", s.rate + "%", "blue", "Part des e-mails signalés (phishing ou suspects)")}
      </div>

      <div class="charts-grid">
        <div class="card"><h3>Classification</h3><div class="chart-box"><canvas id="chartPie"></canvas></div></div>
        <div class="card"><h3>Indicateurs les plus fréquents</h3><div class="chart-box"><canvas id="chartBar"></canvas></div></div>
        <div class="card wide"><h3>Menaces dans le temps (14 jours)</h3><div class="chart-box tall"><canvas id="chartLine"></canvas></div></div>
      </div>

      <div class="bottom-grid">
        <div class="card">
          <h3>Activité récente</h3>
          <ul class="activity-list">
            ${recent.map(x => `
              <li>
                <div>
                  <strong>${esc(x.subject || "(sans objet)")}</strong>
                  <small>${esc(x.sender || "")} · ${new Date(x.date).toLocaleString("fr-FR")}</small>
                </div>
                <span class="badge ${CLASS_TO_BADGE[x.classification] || ""}">${x.classification} · ${x.score}</span>
              </li>`).join("")}
          </ul>
        </div>
        <div class="card">
          <h3>Vue des menaces</h3>
          <div class="threat-list">
            ${Object.entries(s.levels).map(([name, n]) => `
              <div class="threat-row">
                <span>${name}</span>
                <div class="threat-bar"><div style="width:${(n / maxLevel) * 100}%; background:${levelColors[name]}"></div></div>
                <strong>${n}</strong>
              </div>`).join("")}
          </div>
          <p class="muted">Répartition des e-mails par niveau de risque (0–29 Faible, 30–59 Moyen, 60–79 Élevé, 80–100 Critique).</p>
        </div>
      </div>`;

    lucide.createIcons();
    drawCharts(s);
  }

  function drawCharts(s) {
    Object.values(charts).forEach(c => c.destroy());
    charts = {};
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "#1d3560";

    charts.pie = new Chart(document.getElementById("chartPie"), {
      type: "doughnut",
      data: {
        labels: ["Légitime", "Suspect", "Phishing"],
        datasets: [{ data: [s.legit, s.suspect, s.phishing], backgroundColor: [COLORS.safe, COLORS.warn, COLORS.danger], borderWidth: 0 }]
      },
      options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } }
    });

    charts.bar = new Chart(document.getElementById("chartBar"), {
      type: "bar",
      data: {
        labels: s.topIndicators.map(([label]) => label.length > 28 ? label.slice(0, 26) + "…" : label),
        datasets: [{ label: "Occurrences", data: s.topIndicators.map(([, n]) => n), backgroundColor: COLORS.blue, borderRadius: 4 }]
      },
      options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });

    charts.line = new Chart(document.getElementById("chartLine"), {
      type: "line",
      data: {
        labels: s.days.map(d => d.label),
        datasets: [{
          label: "Menaces (suspect + phishing)",
          data: s.days.map(d => d.count),
          borderColor: COLORS.cyan,
          backgroundColor: "rgba(34,211,238,.15)",
          fill: true, tension: 0.35, pointRadius: 3
        }]
      },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
  }

  function refreshIfActive() {
    const view = document.getElementById("view-dashboard");
    if (view && view.classList.contains("active")) render();
  }

  document.addEventListener("analysis:saved", refreshIfActive);
  document.addEventListener("view:change", e => { if (e.detail.view === "dashboard") render(); });
  document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("view-dashboard").classList.contains("active")) render();
  });

  window.PHISHDETECT.dashboard = { render, seedDemo };
})();

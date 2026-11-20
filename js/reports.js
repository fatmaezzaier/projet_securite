(function () {
  "use strict";

  const NS = (window.PHISHDETECT = window.PHISHDETECT || {});
  const HISTORY_KEY = "history";
  const FILTERS = ["Tous", "Légitime", "Suspect", "Phishing"];
  const CLASSIFICATIONS = {
    Légitime: "safe",
    Suspect: "suspicious",
    Phishing: "malicious"
  };

  let activeFilter = "Tous";
  let searchTerm = "";
  let modalElement = null;

  function getHistory() {
    const storage = NS.storage;
    const value = storage && typeof storage.get === "function"
      ? storage.get(HISTORY_KEY, [])
      : [];

    return Array.isArray(value) ? value : [];
  }

  function saveHistory(entries) {
    if (NS.storage && typeof NS.storage.set === "function") {
      NS.storage.set(HISTORY_KEY, entries);
    }
  }

  function escapeHTML(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[char];
    });
  }

  function classificationLabel(value) {
    const normalized = String(value || "").toLowerCase();
    if (normalized === "legitimate" || normalized === "légitime") return "Légitime";
    if (normalized === "suspicious" || normalized === "suspect") return "Suspect";
    if (normalized === "malicious" || normalized === "phishing") return "Phishing";
    return value || "Inconnu";
  }

  function badgeClass(value) {
    return CLASSIFICATIONS[classificationLabel(value)] || "";
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("fr-FR", {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(date);
  }

  function filteredHistory() {
    const query = searchTerm.trim().toLocaleLowerCase("fr");
    return getHistory().filter(function (entry) {
      const classification = classificationLabel(entry.classification);
      const matchesFilter = activeFilter === "Tous" || classification === activeFilter;
      const searchable = [entry.subject, entry.sender].join(" ").toLocaleLowerCase("fr");
      return matchesFilter && (!query || searchable.includes(query));
    });
  }

  function render() {
    const view = document.getElementById("view-reports");
    if (!view) return;

    view.innerHTML = [
      '<div class="reports-module">',
      '  <div class="reports-header">',
      '    <div><h2>Rapports d’analyse</h2><p class="muted">Consultez et exportez l’historique des analyses.</p></div>',
      '    <div class="reports-header-actions">',
      '      <button type="button" class="btn-ghost" data-action="summary">Rapport de synthèse</button>',
      '      <button type="button" class="btn-ghost" data-action="clear">Effacer l’historique</button>',
      '    </div>',
      '  </div>',
      '  <div class="card reports-tools">',
      '    <div class="reports-filters" role="group" aria-label="Filtrer par classification"></div>',
      '    <label class="reports-search-label" for="reports-search">Rechercher par sujet ou expéditeur</label>',
      '    <input class="input" id="reports-search" type="search" autocomplete="off" placeholder="Sujet ou expéditeur…">',
      '  </div>',
      '  <div class="card reports-table-card">',
      '    <div class="reports-table-wrap">',
      '      <table class="reports-table">',
      '        <thead><tr><th scope="col">Date</th><th scope="col">Sujet</th><th scope="col">Expéditeur</th><th scope="col">Score</th><th scope="col">Niveau</th><th scope="col">Classification</th><th scope="col">Actions</th></tr></thead>',
      '        <tbody data-reports-rows></tbody>',
      '      </table>',
      '    </div>',
      '    <div class="reports-empty" data-reports-empty hidden></div>',
      '  </div>',
      '  <section class="reports-print" data-print-area aria-label="Rapport imprimable"></section>',
      '</div>'
    ].join("");

    buildFilters(view);
    const input = view.querySelector("#reports-search");
    input.value = searchTerm;
    input.addEventListener("input", function () {
      searchTerm = input.value;
      renderRows(view);
    });

    view.removeEventListener("click", handleClick);
    view.addEventListener("click", handleClick);
    renderRows(view);
  }

  function buildFilters(view) {
    const container = view.querySelector(".reports-filters");
    container.innerHTML = FILTERS.map(function (filter) {
      return '<button type="button" class="btn-ghost reports-filter' +
        (filter === activeFilter ? " is-active" : "") +
        '" data-filter="' + escapeHTML(filter) + '" aria-pressed="' +
        (filter === activeFilter ? "true" : "false") + '">' +
        escapeHTML(filter) + "</button>";
    }).join("");
  }

  function renderRows(view) {
    const rows = filteredHistory();
    const tbody = view.querySelector("[data-reports-rows]");
    const empty = view.querySelector("[data-reports-empty]");

    tbody.innerHTML = rows.map(function (entry) {
      const originalIndex = getHistory().findIndex(function (item) {
        return item.id === entry.id;
      });
      const classification = classificationLabel(entry.classification);
      const score = Number.isFinite(Number(entry.score)) ? Number(entry.score) : "—";

      return '<tr>' +
        '<td>' + escapeHTML(formatDate(entry.date)) + '</td>' +
        '<td class="reports-subject">' + escapeHTML(entry.subject || "Sans sujet") + '</td>' +
        '<td>' + escapeHTML(entry.sender || "—") + '</td>' +
        '<td>' + escapeHTML(score) + '</td>' +
        '<td>' + escapeHTML(entry.level || "—") + '</td>' +
        '<td><span class="badge ' + badgeClass(classification) + '">' + escapeHTML(classification) + '</span></td>' +
        '<td class="reports-actions">' +
          '<button type="button" class="btn-ghost" data-action="details" data-index="' + originalIndex + '">Détails</button>' +
          '<button type="button" class="btn-ghost" data-action="export" data-index="' + originalIndex + '">PDF</button>' +
          '<button type="button" class="btn-ghost" data-action="delete" data-index="' + originalIndex + '">Supprimer</button>' +
        '</td></tr>';
    }).join("");

    empty.hidden = rows.length > 0;
    if (!rows.length) {
      const hasHistory = getHistory().length > 0;
      empty.innerHTML = hasHistory
        ? '<p>Aucun rapport ne correspond à votre recherche ou à ce filtre.</p>'
        : '<p>Aucune analyse enregistrée.</p><a class="btn-primary" href="#analyzer" data-go-analyzer>Ouvrir l’analyseur</a>';
    }
  }

  function handleClick(event) {
    const view = document.getElementById("view-reports");
    const filterButton = event.target.closest("[data-filter]");
    if (filterButton) {
      activeFilter = filterButton.dataset.filter;
      buildFilters(view);
      renderRows(view);
      return;
    }

    if (event.target.closest("[data-go-analyzer]")) {
      event.preventDefault();
      const nav = document.querySelector('[data-view="analyzer"]');
      if (nav) nav.click();
      else window.dispatchEvent(new CustomEvent("view:change", { detail: { view: "analyzer" } }));
      return;
    }

    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    const index = Number(button.dataset.index);
    const history = getHistory();

    if (action === "summary") {
      prepareSummary(view);
      printArea(view);
    } else if (action === "clear") {
      if (history.length && window.confirm("Effacer tout l’historique des analyses ? Cette action est irréversible.")) {
        saveHistory([]);
        renderRows(view);
      }
    } else if (action === "details" && history[index]) {
      showDetails(history[index]);
    } else if (action === "export" && history[index]) {
      prepareSingleReport(view, history[index]);
      printArea(view);
    } else if (action === "delete" && history[index]) {
      if (window.confirm("Supprimer ce rapport de l’historique ?")) {
        history.splice(index, 1);
        saveHistory(history);
        renderRows(view);
      }
    }
  }

  function showDetails(entry) {
    closeModal();
    const modal = document.createElement("div");
    modal.className = "reports-modal-backdrop";
    modal.innerHTML = '<section class="reports-modal card" role="dialog" aria-modal="true" aria-labelledby="reports-modal-title">' +
      '<button type="button" class="icon-btn reports-modal-close" aria-label="Fermer">×</button>' +
      '<h2 id="reports-modal-title">Détails du rapport</h2>' +
      '<dl class="reports-details">' +
      '<dt>Sujet</dt><dd>' + escapeHTML(entry.subject || "Sans sujet") + '</dd>' +
      '<dt>Expéditeur</dt><dd>' + escapeHTML(entry.sender || "—") + '</dd>' +
      '<dt>Date</dt><dd>' + escapeHTML(formatDate(entry.date)) + '</dd>' +
      '<dt>Score</dt><dd>' + escapeHTML(entry.score == null ? "—" : entry.score) + '</dd>' +
      '<dt>Niveau</dt><dd>' + escapeHTML(entry.level || "—") + '</dd>' +
      '<dt>Classification</dt><dd><span class="badge ' + badgeClass(entry.classification) + '">' + escapeHTML(classificationLabel(entry.classification)) + '</span></dd>' +
      '<dt>Indicateurs</dt><dd>' + escapeHTML(Array.isArray(entry.indicators) && entry.indicators.length ? entry.indicators.join(", ") : "Aucun indicateur enregistré") + '</dd>' +
      '</dl></section>';
    document.body.appendChild(modal);
    modalElement = modal;
    modal.querySelector(".reports-modal-close").focus();
    modal.addEventListener("click", function (event) {
      if (event.target === modal || event.target.closest(".reports-modal-close")) closeModal();
    });
    modal.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeModal();
    });
  }

  function closeModal() {
    if (modalElement) {
      modalElement.remove();
      modalElement = null;
    }
  }

  function prepareSingleReport(view, entry) {
    const area = view.querySelector("[data-print-area]");
    area.innerHTML = '<h1>Rapport d’analyse — PHISHDETECT</h1>' +
      '<p><strong>Sujet :</strong> ' + escapeHTML(entry.subject || "Sans sujet") + '</p>' +
      '<p><strong>Expéditeur :</strong> ' + escapeHTML(entry.sender || "—") + '</p>' +
      '<p><strong>Date :</strong> ' + escapeHTML(formatDate(entry.date)) + '</p>' +
      '<p><strong>Score :</strong> ' + escapeHTML(entry.score == null ? "—" : entry.score) + '</p>' +
      '<p><strong>Niveau :</strong> ' + escapeHTML(entry.level || "—") + '</p>' +
      '<p><strong>Classification :</strong> ' + escapeHTML(classificationLabel(entry.classification)) + '</p>' +
      '<p><strong>Indicateurs :</strong> ' + escapeHTML(Array.isArray(entry.indicators) ? entry.indicators.join(", ") : "Aucun") + '</p>';
  }

  function prepareSummary(view) {
    const all = getHistory();
    const counts = { Légitime: 0, Suspect: 0, Phishing: 0 };
    const indicators = {};
    const dates = [];

    all.forEach(function (entry) {
      const classification = classificationLabel(entry.classification);
      if (Object.prototype.hasOwnProperty.call(counts, classification)) counts[classification]++;
      (Array.isArray(entry.indicators) ? entry.indicators : []).forEach(function (label) {
        indicators[label] = (indicators[label] || 0) + 1;
      });
      const date = new Date(entry.date);
      if (!Number.isNaN(date.getTime())) dates.push(date);
    });

    const total = all.length;
    const rates = Object.keys(counts).map(function (label) {
      return label + " : " + (total ? Math.round(counts[label] * 100 / total) : 0) + "% (" + counts[label] + ")";
    });
    const top = Object.keys(indicators).sort(function (a, b) {
      return indicators[b] - indicators[a];
    }).slice(0, 5);
    const period = dates.length
      ? formatDate(new Date(Math.min.apply(null, dates))) + " – " + formatDate(new Date(Math.max.apply(null, dates)))
      : "Aucune période disponible";

    view.querySelector("[data-print-area]").innerHTML =
      '<h1>Rapport de synthèse — PHISHDETECT</h1>' +
      '<p><strong>Généré le :</strong> ' + escapeHTML(formatDate(new Date())) + '</p>' +
      '<p><strong>Période couverte :</strong> ' + escapeHTML(period) + '</p>' +
      '<p><strong>Total des analyses :</strong> ' + total + '</p>' +
      '<h2>Répartition</h2><ul>' + rates.map(function (line) { return "<li>" + escapeHTML(line) + "</li>"; }).join("") + '</ul>' +
      '<h2>Indicateurs les plus fréquents</h2>' +
      (top.length ? '<ol>' + top.map(function (label) {
        return "<li>" + escapeHTML(label) + " (" + indicators[label] + ")</li>";
      }).join("") + "</ol>" : "<p>Aucun indicateur enregistré.</p>");
  }

  function printArea(view) {
    document.body.classList.add("phishdetect-printing");
    window.setTimeout(function () {
      window.print();
      window.setTimeout(function () {
        document.body.classList.remove("phishdetect-printing");
        const area = view.querySelector("[data-print-area]");
        if (area) area.innerHTML = "";
      }, 500);
    }, 50);
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeModal();
  });

  document.addEventListener("view:change", function (event) {
    if (event.detail && event.detail.view === "reports") render();
  });

  NS.reports = { render: render };
  if (document.getElementById("view-reports") &&
      document.getElementById("view-reports").classList.contains("active")) {
    render();
  }
})();

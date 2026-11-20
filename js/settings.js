(function () {
  "use strict";

  const NS = (window.PHISHDETECT = window.PHISHDETECT || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getStats() {
    const store = NS.storage;
    if (!store) return { historyCount: 0, quizCount: 0, incidentStages: 0 };
    const history = store.get("history", []);
    const quiz = store.get("quiz_scores", []);
    const incident = store.get("incident", { completed: [] });
    return {
      historyCount: Array.isArray(history) ? history.length : 0,
      quizCount: Array.isArray(quiz) ? quiz.length : 0,
      incidentStages: incident && Array.isArray(incident.completed) ? incident.completed.length : 0
    };
  }

  function clearAllData() {
    if (!window.confirm("Êtes-vous sûr de vouloir réinitialiser l'ensemble des données d'entraînement (analyses, scores du quiz, progression de l'incident) ? Cette action est irréversible.")) {
      return;
    }
    try {
      localStorage.removeItem("phishdetect_history");
      localStorage.removeItem("phishdetect_quiz_scores");
      localStorage.removeItem("phishdetect_incident");
      localStorage.removeItem("phishdetect_settings");
    } catch (e) {}
    alert("Toutes les données locales ont été réinitialisées avec succès.");
    render();
  }

  function exportBackup() {
    const store = NS.storage;
    if (!store) return;
    const backup = {
      app: "PHISHDETECT",
      exportedAt: new Date().toISOString(),
      history: store.get("history", []),
      quiz_scores: store.get("quiz_scores", []),
      incident: store.get("incident", { completed: [], checked: {}, timeline: [] }),
      settings: store.get("settings", { notifications: true, sensitivity: "standard" })
    };
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "phishdetect-backup-" + new Date().toISOString().slice(0, 10) + ".json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function importBackup(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const data = JSON.parse(e.target.result);
        if (data.app !== "PHISHDETECT") {
          alert("Erreur : le fichier sélectionné n'est pas une sauvegarde valide de PHISHDETECT.");
          return;
        }
        const store = NS.storage;
        if (store) {
          if (Array.isArray(data.history)) store.set("history", data.history);
          if (Array.isArray(data.quiz_scores)) store.set("quiz_scores", data.quiz_scores);
          if (data.incident && typeof data.incident === "object") store.set("incident", data.incident);
          if (data.settings && typeof data.settings === "object") store.set("settings", data.settings);
        }
        alert("Sauvegarde importée avec succès !");
        render();
      } catch (err) {
        alert("Erreur lors de la lecture du fichier JSON : " + err.message);
      }
    };
    reader.readAsText(file);
  }

  function loadDemoData() {
    if (NS.dashboard && typeof NS.dashboard.seedDemo === "function") {
      NS.dashboard.seedDemo();
      alert("Les données d'exercice TECHNOVA ont été chargées avec succès.");
      render();
    }
  }

  function render() {
    const view = document.getElementById("view-settings");
    if (!view) return;

    const stats = getStats();
    const settings = (NS.storage && NS.storage.get("settings", { notifications: true, sensitivity: "standard" })) || { notifications: true, sensitivity: "standard" };

    view.innerHTML = `
      <div class="settings-module">
        <div class="settings-header">
          <div>
            <h2>Paramètres &amp; Environnement d'entraînement</h2>
            <p class="muted">Gérez les options de la console SOC, les données locales et la conformité de l'exercice.</p>
          </div>
        </div>

        <div class="settings-grid">
          <!-- Carte 1 : État du stockage & Données -->
          <div class="card settings-card">
            <h3><i data-lucide="database"></i> Données locales &amp; Persistance</h3>
            <p class="muted">Toutes les données sont stockées exclusivement dans votre navigateur (localStorage). Aucun corps d'e-mail ni identifiant n'est jamais sauvegardé.</p>
            
            <div class="settings-stats-list">
              <div class="settings-stat-row">
                <span>Historique des analyses</span>
                <strong>${stats.historyCount} analyse(s)</strong>
              </div>
              <div class="settings-stat-row">
                <span>Scores de formation (Quiz)</span>
                <strong>${stats.quizCount} session(s)</strong>
              </div>
              <div class="settings-stat-row">
                <span>Progression de l'incident</span>
                <strong>${stats.incidentStages} / 6 étape(s)</strong>
              </div>
            </div>

            <div class="settings-actions">
              <button type="button" class="btn-ghost" id="btnSettingsLoadDemo">
                <i data-lucide="refresh-cw"></i> Charger le jeu d'essai démo
              </button>
              <button type="button" class="btn-ghost" id="btnSettingsExport">
                <i data-lucide="download"></i> Exporter la sauvegarde (JSON)
              </button>
              <label class="btn-ghost file-upload-btn" for="settingsImportFile">
                <i data-lucide="upload"></i> Importer une sauvegarde
                <input type="file" id="settingsImportFile" accept=".json" style="display:none;">
              </label>
              <button type="button" class="btn-ghost btn-danger-ghost" id="btnSettingsClearAll">
                <i data-lucide="trash-2"></i> Réinitialiser toutes les données
              </button>
            </div>
          </div>

          <!-- Carte 2 : Préférences de la Console SOC -->
          <div class="card settings-card">
            <h3><i data-lucide="sliders"></i> Préférences de simulation</h3>
            <p class="muted">Personnalisez le comportement des modules d'analyse et de notification.</p>

            <div class="settings-option-group">
              <label class="settings-option-label" for="settingsSensitivity">Sensibilité de l'analyseur heuristique</label>
              <select id="settingsSensitivity" class="input">
                <option value="standard" ${settings.sensitivity === "standard" ? "selected" : ""}>Standard (recommandé pour la formation)</option>
                <option value="strict" ${settings.sensitivity === "strict" ? "selected" : ""}>Stricte (tolérance zéro sur les anomalies d'en-têtes)</option>
                <option value="permissive" ${settings.sensitivity === "permissive" ? "selected" : ""}>Permissive (moins de faux positifs)</option>
              </select>
            </div>

            <div class="settings-option-group">
              <label class="settings-checkbox-label">
                <input type="checkbox" id="settingsNotifications" ${settings.notifications ? "checked" : ""}>
                <span>Activer les alertes visuelles du SOC</span>
              </label>
              <p class="muted" style="margin-top:4px;">Affiche des alertes visuelles lorsqu'un e-mail malveillant est analysé.</p>
            </div>
          </div>

          <!-- Carte 3 : Conformité & Charte de sécurité -->
          <div class="card settings-card settings-card--wide">
            <h3><i data-lucide="shield-check"></i> Cadre d'entraînement &amp; Confidentialité</h3>
            <div class="settings-compliance-info">
              <div class="compliance-badge-row">
                <span class="badge safe">Environnement 100% Hors-Ligne (Offline)</span>
                <span class="badge safe">Zéro Télémétrie</span>
                <span class="badge safe">Données Fictives Uniquement</span>
              </div>
              <ul class="compliance-rules-list">
                <li><strong>Entité fictive :</strong> L'entreprise <em>TECHNOVA</em>, ses employés et ses noms de domaine (ex: <code>technova-demo.test</code>) sont strictement imaginaires et dédiés à l'exercice pédagogique.</li>
                <li><strong>Aucune collecte d'identifiants :</strong> L'application n'enregistre et ne demande aucun identifiant réel, mot de passe personnel ou information confidentielle.</li>
                <li><strong>Protection des données sensibles :</strong> Les corps des e-mails analysés ne sont jamais persistés dans le stockage local (seuls le sujet, le score et les indicateurs synthétiques sont conservés).</li>
                <li><strong>Isolation réseau complète :</strong> Aucun lien n'est jamais ouvert, requêté (fetch) ou visité sur Internet, et aucune pièce jointe n'est exécutée sur votre poste.</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    `;

    if (window.lucide) lucide.createIcons();

    // Event listeners
    const btnLoadDemo = document.getElementById("btnSettingsLoadDemo");
    if (btnLoadDemo) btnLoadDemo.addEventListener("click", loadDemoData);

    const btnExport = document.getElementById("btnSettingsExport");
    if (btnExport) btnExport.addEventListener("click", exportBackup);

    const importInput = document.getElementById("settingsImportFile");
    if (importInput) {
      importInput.addEventListener("change", function (e) {
        if (e.target.files && e.target.files[0]) {
          importBackup(e.target.files[0]);
        }
      });
    }

    const btnClear = document.getElementById("btnSettingsClearAll");
    if (btnClear) btnClear.addEventListener("click", clearAllData);

    const selectSensitivity = document.getElementById("settingsSensitivity");
    if (selectSensitivity) {
      selectSensitivity.addEventListener("change", function () {
        const cur = (NS.storage && NS.storage.get("settings", {})) || {};
        cur.sensitivity = selectSensitivity.value;
        if (NS.storage) NS.storage.set("settings", cur);
      });
    }

    const checkNotif = document.getElementById("settingsNotifications");
    if (checkNotif) {
      checkNotif.addEventListener("change", function () {
        const cur = (NS.storage && NS.storage.get("settings", {})) || {};
        cur.notifications = checkNotif.checked;
        if (NS.storage) NS.storage.set("settings", cur);
      });
    }
  }

  document.addEventListener("view:change", function (e) {
    if (e.detail && e.detail.view === "settings") render();
  });

  NS.settings = { render: render };

  const settingsView = document.getElementById("view-settings");
  if (settingsView && settingsView.classList.contains("active")) render();
})();

(function () {
  "use strict";

  const NS = (window.PHISHDETECT = window.PHISHDETECT || {});
  const STORAGE_KEY = "incident";

  const DEFAULT_SCENARIO = {
    company: "TECHNOVA",
    title: "Campagne de phishing simulée",
    description:
      "Un employé fictif a saisi des identifiants de démonstration sur une fausse page. Aucun compte, service ou système réel n’est concerné. Les actions ci-dessous sont une simulation.",
    stages: [
      {
        id: "detection",
        name: "Détection",
        description: "Repérez et signalez les premiers indices de la campagne.",
        actions: [
          "Consulter le signalement fictif de l’employé.",
          "Relever le sujet et l’expéditeur du courriel suspect.",
          "Consigner l’heure de détection dans le journal simulé."
        ],
        timeline: "Signalement initial enregistré dans la simulation."
      },
      {
        id: "identification",
        name: "Identification",
        description: "Évaluez la portée et les indicateurs de la campagne fictive.",
        actions: [
          "Comparer l’expéditeur et l’adresse de réponse simulés.",
          "Examiner les indicateurs de risque du courriel, sans ouvrir de lien.",
          "Estimer quels employés fictifs ont reçu le message."
        ],
        timeline: "Périmètre fictif et indicateurs consignés."
      },
      {
        id: "containment",
        name: "Confinement",
        description: "Limitez la propagation dans le scénario, sans agir sur des systèmes réels.",
        actions: [
          "Marquer le message de démonstration comme isolé.",
          "Ajouter l’expéditeur fictif à la liste de blocage simulée.",
          "Notifier les employés fictifs concernés."
        ],
        timeline: "Mesures de confinement simulées."
      },
      {
        id: "eradication",
        name: "Éradication",
        description: "Retirez les éléments de la campagne dans l’environnement d’exercice.",
        actions: [
          "Retirer les courriels de démonstration des boîtes fictives.",
          "Désactiver la fausse page dans le scénario.",
          "Vérifier qu’aucun autre message fictif n’est en attente."
        ],
        timeline: "Éléments de la campagne retirés dans l’exercice."
      },
      {
        id: "recovery",
        name: "Rétablissement",
        description: "Simulez le retour à une situation normale pour l’employé fictif.",
        actions: [
          "Réinitialiser le compte fictif de l’exercice.",
          "Confirmer avec l’employé fictif qu’il peut reprendre ses activités simulées.",
          "Surveiller les alertes fictives après le rétablissement."
        ],
        timeline: "Rétablissement fictif terminé et suivi planifié."
      },
      {
        id: "lessons",
        name: "Leçons apprises",
        description: "Clôturez l’exercice et définissez des améliorations de sensibilisation.",
        actions: [
          "Documenter la chronologie de l’exercice.",
          "Noter les mesures efficaces et les points à améliorer.",
          "Planifier un rappel de sensibilisation fictif."
        ],
        timeline: "Retour d’expérience consigné ; exercice terminé."
      }
    ]
  };

  function getScenario() {
    const data = window.PHISHDETECT_DATA;
    if (data && data.scenario && Array.isArray(data.scenario.stages) && data.scenario.stages.length) {
      return data.scenario;
    }
    return DEFAULT_SCENARIO;
  }

  function getSavedState() {
    const storage = NS.storage;
    const state = storage && typeof storage.get === "function"
      ? storage.get(STORAGE_KEY, null)
      : null;

    if (!state || typeof state !== "object") {
      return { completed: [], checked: {}, timeline: [] };
    }

    return {
      completed: Array.isArray(state.completed) ? state.completed : [],
      checked: state.checked && typeof state.checked === "object" ? state.checked : {},
      timeline: Array.isArray(state.timeline) ? state.timeline : []
    };
  }

  function saveState(state) {
    if (NS.storage && typeof NS.storage.set === "function") {
      NS.storage.set(STORAGE_KEY, state);
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

  function isUnlocked(index, scenario, state) {
    return index === 0 || state.completed.includes(scenario.stages[index - 1].id);
  }

  function render() {
    const view = document.getElementById("view-incident");
    if (!view) return;

    const scenario = getScenario();
    const state = getSavedState();
    const completedCount = scenario.stages.filter(function (stage) {
      return state.completed.includes(stage.id);
    }).length;
    const progress = Math.round(completedCount / scenario.stages.length * 100);

    view.innerHTML =
      '<div class="incident-module">' +
        '<div class="incident-header">' +
          '<div><h2>Simulation de réponse à incident</h2>' +
          '<p class="muted">' + escapeHTML(scenario.title || "Scénario d’incident") + ' — ' +
            escapeHTML(scenario.company || "TECHNOVA") + '</p></div>' +
          '<button type="button" class="btn-ghost" data-incident-reset>Réinitialiser le scénario</button>' +
        '</div>' +
        '<div class="card incident-notice"><p>' + escapeHTML(scenario.description || "") + '</p>' +
          '<p><strong>Exercice uniquement :</strong> les actions sont simulées. N’utilisez pas de vrais identifiants et n’intervenez pas sur des systèmes réels.</p></div>' +
        '<section class="card incident-progress" aria-label="Progression du scénario">' +
          '<div class="incident-progress-label"><span>Progression</span><span>' +
            completedCount + ' / ' + scenario.stages.length + ' étapes — ' + progress + '%</span></div>' +
          '<div class="incident-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + progress + '" aria-label="Progression du scénario">' +
            '<span style="width:' + progress + '%"></span></div></section>' +
        '<div class="incident-stages" data-incident-stages></div>' +
        '<section class="card incident-timeline"><h3>Chronologie de l’exercice</h3>' +
          '<ol data-incident-timeline></ol></section>' +
      '</div>';

    renderStages(view, scenario, state);
    renderTimeline(view, scenario, state);
    view.removeEventListener("change", handleChange);
    view.removeEventListener("click", handleClick);
    view.addEventListener("change", handleChange);
    view.addEventListener("click", handleClick);
  }

  function renderStages(view, scenario, state) {
    const target = view.querySelector("[data-incident-stages]");
    target.innerHTML = scenario.stages.map(function (stage, index) {
      const unlocked = isUnlocked(index, scenario, state);
      const completed = state.completed.includes(stage.id);
      const checked = state.checked[stage.id] || [];

      return '<article class="card incident-stage' + (completed ? " is-complete" : "") +
        (!unlocked ? " is-locked" : "") + '">' +
        '<div class="incident-stage-heading">' +
          '<span class="incident-stage-number">' + (index + 1) + '</span>' +
          '<div><h3>' + escapeHTML(stage.name) + '</h3>' +
          '<p class="muted">' + escapeHTML(stage.description) + '</p></div>' +
          '<span class="incident-stage-status">' +
            (completed ? "Terminée" : unlocked ? "Disponible" : "Verrouillée") + '</span>' +
        '</div>' +
        '<fieldset ' + (!unlocked || completed ? "disabled" : "") + '>' +
          '<legend>Actions à effectuer</legend>' +
          stage.actions.map(function (action, actionIndex) {
            const isChecked = checked.includes(actionIndex);
            return '<label class="incident-check">' +
              '<input type="checkbox" data-stage="' + escapeHTML(stage.id) + '" data-action-index="' + actionIndex + '"' +
              (isChecked ? " checked" : "") + (completed || !unlocked ? " disabled" : "") + '>' +
              '<span>' + escapeHTML(action) + '</span></label>';
          }).join("") +
        '</fieldset>' +
        '<button type="button" class="btn-primary incident-complete" data-complete-stage="' + escapeHTML(stage.id) + '"' +
          (!unlocked || completed || checked.length !== stage.actions.length ? " disabled" : "") + '>' +
          (completed ? "Étape terminée" : "Terminer cette étape") + '</button>' +
      '</article>';
    }).join("");
  }

  function renderTimeline(view, scenario, state) {
    const target = view.querySelector("[data-incident-timeline]");
    const entries = state.timeline.length
      ? state.timeline
      : scenario.stages.filter(function (stage) {
          return state.completed.includes(stage.id);
        }).map(function (stage) {
          return { stageId: stage.id, text: stage.timeline, date: "" };
        });

    if (!entries.length) {
      target.innerHTML = "<li>Aucune étape terminée pour le moment.</li>";
      return;
    }

    target.innerHTML = entries.map(function (entry) {
      const stage = scenario.stages.find(function (item) {
        return item.id === entry.stageId;
      });
      const dateLabel = entry.date ? new Date(entry.date).toLocaleString("fr-FR") : "";
      return '<li><strong>' + escapeHTML(stage ? stage.name : "Étape") + ' :</strong> ' +
        escapeHTML(entry.text || (stage && stage.timeline) || "Étape terminée") +
        (dateLabel ? ' <span class="muted">(' + escapeHTML(dateLabel) + ')</span>' : "") + '</li>';
    }).join("");
  }

  function handleChange(event) {
    const checkbox = event.target.closest("input[data-stage][data-action-index]");
    if (!checkbox) return;

    const scenario = getScenario();
    const state = getSavedState();
    const stageId = checkbox.dataset.stage;
    const actionIndex = Number(checkbox.dataset.actionIndex);

    if (!state.checked[stageId]) state.checked[stageId] = [];
    const selected = new Set(state.checked[stageId]);

    if (checkbox.checked) selected.add(actionIndex);
    else selected.delete(actionIndex);

    state.checked[stageId] = Array.from(selected).sort(function (a, b) { return a - b; });
    saveState(state);
    render();
  }

  function handleClick(event) {
    const resetButton = event.target.closest("[data-incident-reset]");
    if (resetButton) {
      if (window.confirm("Réinitialiser la progression de cet exercice ?")) {
        saveState({ completed: [], checked: {}, timeline: [] });
        render();
      }
      return;
    }

    const completeButton = event.target.closest("[data-complete-stage]");
    if (!completeButton || completeButton.disabled) return;

    const scenario = getScenario();
    const state = getSavedState();
    const stageId = completeButton.dataset.completeStage;
    const stageIndex = scenario.stages.findIndex(function (stage) {
      return stage.id === stageId;
    });
    const stage = scenario.stages[stageIndex];

    if (!stage || !isUnlocked(stageIndex, scenario, state)) return;
    if ((state.checked[stageId] || []).length !== stage.actions.length) return;

    if (!state.completed.includes(stageId)) {
      state.completed.push(stageId);
      state.timeline.push({
        stageId: stageId,
        text: stage.timeline,
        date: new Date().toISOString()
      });
      saveState(state);
      render();
    }
  }

  document.addEventListener("view:change", function (event) {
    if (event.detail && event.detail.view === "incident") render();
  });

  NS.incident = { render: render };

  const incidentView = document.getElementById("view-incident");
  if (incidentView && incidentView.classList.contains("active")) render();
})();

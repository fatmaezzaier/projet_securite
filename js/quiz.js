(function () {
  "use strict";

  const NS = (window.PHISHDETECT = window.PHISHDETECT || {});
  const DATA = window.PHISHDETECT_DATA || {};
  const SCORES_KEY = "quiz_scores";
  const ANSWERS = [
    { value: "legitimate", label: "Légitime" },
    { value: "suspicious", label: "Suspect" },
    { value: "malicious", label: "Phishing" }
  ];

  let questions = [];
  let currentIndex = 0;
  let correctCount = 0;
  let answered = false;
  let finished = false;
  let chart = null;
  let container = null;

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

  function normalizeExpected(value) {
    const normalized = String(value || "").toLowerCase();
    if (normalized === "legitimate" || normalized === "légitime") return "legitimate";
    if (normalized === "suspicious" || normalized === "suspect") return "suspicious";
    return "malicious";
  }

  function labelFor(value) {
    const labels = {
      legitimate: "Légitime",
      suspicious: "Suspect",
      malicious: "Phishing"
    };
    return labels[normalizeExpected(value)];
  }

  function getScores() {
    const storage = NS.storage;
    const scores = storage && typeof storage.get === "function"
      ? storage.get(SCORES_KEY, [])
      : [];
    return Array.isArray(scores) ? scores : [];
  }

  function saveScore(score, total) {
    const scores = getScores();
    scores.unshift({
      score: score,
      total: total,
      date: new Date().toISOString()
    });
    if (scores.length > 50) scores.length = 50;

    if (NS.storage && typeof NS.storage.set === "function") {
      NS.storage.set(SCORES_KEY, scores);
    }
  }

  function getQuestions() {
    const emails = Array.isArray(DATA.emails) ? DATA.emails : [];
    return emails.slice(0, Math.max(5, Math.min(10, emails.length)));
  }

  function render() {
    const view = document.getElementById("view-training");
    if (!view) return;

    container = view;
    questions = getQuestions();
    currentIndex = 0;
    correctCount = 0;
    answered = false;
    finished = false;

    if (chart) {
      chart.destroy();
      chart = null;
    }

    view.innerHTML =
      '<div class="quiz-module">' +
        '<div class="quiz-heading">' +
          '<div><h2>Entraînement à la détection</h2>' +
          '<p class="muted">Classez chaque courriel en vous appuyant sur ses indices.</p></div>' +
        '</div>' +
        '<div class="card quiz-content" data-quiz-content></div>' +
        '<section class="card quiz-history">' +
          '<h3>Historique des scores</h3>' +
          '<div class="quiz-chart-wrap"><canvas data-quiz-chart aria-label="Graphique des scores précédents" role="img"></canvas></div>' +
          '<p class="muted" data-quiz-history-empty hidden>Aucun score enregistré pour le moment.</p>' +
        '</section>' +
      '</div>';

    view.removeEventListener("click", handleClick);
    view.addEventListener("click", handleClick);
    renderQuestion();
    renderChart();
  }

  function renderQuestion() {
    if (!container) return;
    const target = container.querySelector("[data-quiz-content]");
    if (!questions.length) {
      target.innerHTML = '<p>Aucun courriel de démonstration disponible.</p>';
      return;
    }

    if (finished) {
      renderFinal(target);
      return;
    }

    const email = questions[currentIndex];
    const expected = normalizeExpected(email.expected);
    const indicators = Array.isArray(email.indicators) ? email.indicators : [];

    target.innerHTML =
      '<div class="quiz-progress-row">' +
        '<span>Question ' + (currentIndex + 1) + ' sur ' + questions.length + '</span>' +
        '<span>Bonnes réponses : ' + correctCount + '</span>' +
      '</div>' +
      '<div class="quiz-progress-track" role="progressbar" aria-label="Progression du quiz" aria-valuemin="0" aria-valuemax="' + questions.length + '" aria-valuenow="' + currentIndex + '">' +
        '<span style="width:' + Math.round(currentIndex / questions.length * 100) + '%"></span>' +
      '</div>' +
      '<article class="quiz-email">' +
        '<p><strong>De :</strong> ' + escapeHTML(email.sender && (email.sender.name || email.sender.email) || "Expéditeur inconnu") +
          (email.sender && email.sender.email ? ' &lt;' + escapeHTML(email.sender.email) + '&gt;' : '') + '</p>' +
        '<p><strong>Objet :</strong> ' + escapeHTML(email.subject || "Sans objet") + '</p>' +
        '<p><strong>Date :</strong> ' + escapeHTML(email.date || "—") + '</p>' +
        '<div class="quiz-email-body">' + escapeHTML(email.body || "Contenu indisponible.") + '</div>' +
      '</article>' +
      '<fieldset class="quiz-answers" ' + (answered ? "disabled" : "") + '>' +
        '<legend>Votre classification</legend>' +
        ANSWERS.map(function (answer) {
          return '<button type="button" class="btn-ghost quiz-answer" data-answer="' + answer.value + '">' +
            escapeHTML(answer.label) + '</button>';
        }).join("") +
      '</fieldset>' +
      '<div class="quiz-feedback" data-quiz-feedback aria-live="polite"></div>' +
      '<button type="button" class="btn-primary quiz-next" data-quiz-next hidden>' +
        (currentIndex === questions.length - 1 ? "Voir mon résultat" : "Question suivante") +
      '</button>';

    if (answered) showFeedback(email, expected);
  }

  function handleClick(event) {
    const answerButton = event.target.closest("[data-answer]");
    if (answerButton && !answered && !finished) {
      chooseAnswer(answerButton.dataset.answer);
      return;
    }

    if (event.target.closest("[data-quiz-next]")) {
      if (currentIndex < questions.length - 1) {
        currentIndex++;
        answered = false;
        renderQuestion();
      } else {
        finished = true;
        saveScore(correctCount, questions.length);
        renderQuestion();
        renderChart();
      }
      return;
    }

    if (event.target.closest("[data-quiz-restart]")) {
      currentIndex = 0;
      correctCount = 0;
      answered = false;
      finished = false;
      renderQuestion();
    }
  }

function chooseAnswer(value) {
  const email = questions[currentIndex];
  const expected = normalizeExpected(email.expected);
  answered = true;
  email._quizCorrect = value === expected;
  if (email._quizCorrect) correctCount++;
  renderQuestion();
}

  function showFeedback(email, expected) {
    const feedback = container.querySelector("[data-quiz-feedback]");
    const indicators = Array.isArray(email.indicators) ? email.indicators : [];
    const isCorrect = email._quizCorrect === true;

    feedback.className = "quiz-feedback " + (isCorrect ? "is-correct" : "is-incorrect");
    feedback.innerHTML =
      '<p><strong>' + (isCorrect ? "Bonne réponse." : "Ce n’est pas la bonne réponse.") +
      ' Classification : ' + escapeHTML(labelFor(expected)) + '.</strong></p>' +
      '<p>' + escapeHTML(email.reason || email.explanation || "Examinez les indices indiqués ci-dessous pour justifier la classification.") + '</p>' +
      '<p><strong>Indicateurs :</strong></p>' +
      (indicators.length
        ? '<ul>' + indicators.map(function (item) { return "<li>" + escapeHTML(item) + "</li>"; }).join("") + "</ul>"
        : "<p>Aucun indicateur particulier n’est renseigné pour ce courriel de démonstration.</p>");

    container.querySelector("[data-quiz-next]").hidden = false;
  }

  function countCorrectBeforeCurrent() {
    // The current answer is included in correctCount only when it was correct.
    // This value is used only to preserve simple feedback state between renders.
    const prior = questions.slice(0, currentIndex);
    let count = 0;
    prior.forEach(function (email) {
      if (email._quizCorrect === true) count++;
    });
    return count;
  }

  function renderFinal(target) {
    const percentage = questions.length ? Math.round(correctCount / questions.length * 100) : 0;
    target.innerHTML =
      '<div class="quiz-final">' +
        '<h3>Quiz terminé</h3>' +
        '<p class="quiz-final-score">' + correctCount + ' / ' + questions.length + '</p>' +
        '<p>Vous avez obtenu ' + percentage + ' % de bonnes réponses.</p>' +
        '<button type="button" class="btn-primary" data-quiz-restart>Recommencer</button>' +
      '</div>';
  }

  function renderChart() {
    if (!container) return;
    const scores = getScores();
    const empty = container.querySelector("[data-quiz-history-empty]");
    const canvas = container.querySelector("[data-quiz-chart]");
    if (!canvas || !window.Chart) {
      if (empty) empty.hidden = scores.length > 0;
      return;
    }

    if (chart) chart.destroy();

    empty.hidden = scores.length > 0;
    chart = new window.Chart(canvas.getContext("2d"), {
      type: "line",
      data: {
        labels: scores.slice(0, 10).reverse().map(function (item) {
          const date = new Date(item.date);
          return Number.isNaN(date.getTime())
            ? "—"
            : new Intl.DateTimeFormat("fr-FR", { day: "2-digit", month: "2-digit" }).format(date);
        }),
        datasets: [{
          label: "Score (%)",
          data: scores.slice(0, 10).reverse().map(function (item) {
            return item.total ? Math.round(Number(item.score) / Number(item.total) * 100) : 0;
          }),
          borderColor: "#22d3ee",
          backgroundColor: "rgba(34, 211, 238, 0.15)",
          pointBackgroundColor: "#3b82f6",
          fill: true,
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            min: 0,
            max: 100,
            ticks: { color: "#cbd5e1" },
            grid: { color: "rgba(148, 163, 184, 0.15)" }
          },
          x: {
            ticks: { color: "#cbd5e1" },
            grid: { color: "rgba(148, 163, 184, 0.1)" }
          }
        },
        plugins: {
          legend: { labels: { color: "#e2e8f0" } }
        }
      }
    });
  }

  document.addEventListener("view:change", function (event) {
    if (event.detail && event.detail.view === "training") render();
  });

  NS.quiz = { render: render };

  const trainingView = document.getElementById("view-training");
  if (trainingView && trainingView.classList.contains("active")) render();
})();

(function () {
    const VIEW_TITLES = {
        dashboard: "Dashboard",
        analyzer: "Email Analyzer",
        investigation: "Email Investigation",
        incident: "Incident Response",
        training: "Awareness Training",
        reports: "Reports",
        settings: "Settings"
    };

    // Utilitaires de stockage (uniquement pour données non sensibles)
    const Storage = {
        get(key, fallback) {
            try {
                const raw = localStorage.getItem("phishdetect_" + key);
                return raw ? JSON.parse(raw) : fallback;
            } catch (e) { return fallback; }
        },
        set(key, value) {
            localStorage.setItem("phishdetect_" + key, JSON.stringify(value));
        }
    };
    window.PHISHDETECT = window.PHISHDETECT || {};
    window.PHISHDETECT.storage = Storage;

    // Migration one-shot : supprime les clés avec double-préfixe créées par un ancien bug
    (function migrateLegacyKeys() {
        const badKeys = ["phishdetect_phishdetect_history", "phishdetect_phishdetect_incident", "phishdetect_phishdetect_quiz_scores"];
        badKeys.forEach(function (k) { try { localStorage.removeItem(k); } catch (e) {} });
    })();

    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("sidebarOverlay");
    const menuToggle = document.getElementById("menuToggle");
    const pageTitle = document.getElementById("pageTitle");

    function closeSidebar() {
        sidebar.classList.remove("open");
        overlay.classList.remove("open");
    }

    menuToggle.addEventListener("click", () => {
        sidebar.classList.toggle("open");
        overlay.classList.toggle("open");
    });
    overlay.addEventListener("click", closeSidebar);

    function showView(name) {
        if (!VIEW_TITLES[name]) name = "dashboard";

        document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + name));
        document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === name));

        pageTitle.textContent = VIEW_TITLES[name];
        document.title = "PHISHDETECT | " + VIEW_TITLES[name];
        closeSidebar();
        window.scrollTo(0, 0);

        // Hook pour les modules : chaque module peut écouter cet événement
        document.dispatchEvent(new CustomEvent("view:change", { detail: { view: name } }));
    }

    window.addEventListener("hashchange", () => showView(location.hash.replace("#", "")));

    if (window.lucide) lucide.createIcons();
    showView(location.hash.replace("#", "") || "dashboard");
})();

window.PHISHDETECT_DATA = {
    emails: [
        {
            id: "EM-001",
            sender: { name: "RH TECHNOVA", email: "rh@technova-demo.test", replyTo: "rh@technova-demo.test", returnPath: "rh@technova-demo.test" },
            subject: "Mise à jour de votre fiche de paie - novembre",
            date: "2026-11-02 09:14",
            body: "Bonjour, votre bulletin de novembre est disponible dans l'espace RH. Merci de le consulter avant le 15 novembre.",
            urls: ["https://intranet.technova-demo.test/paie"],
            attachments: [],
            auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
            expected: "legitimate",
            indicators: []
        },
        {
            id: "EM-002",
            sender: { name: "Support Microsoft 365", email: "security@m1crosoft-verify.test", replyTo: "collect.sec@mail-relay.test", returnPath: "bounce@mail-relay.test" },
            subject: "URGENT : votre mot de passe expire dans 2 heures",
            date: "2026-11-03 08:02",
            body: "Votre compte sera suspendu. Confirmez immédiatement votre mot de passe et vos identifiants via le lien ci-dessous.",
            urls: ["http://192.168.14.22/login/verify"],
            attachments: [],
            auth: { spf: "fail", dkim: "none", dmarc: "fail" },
            expected: "malicious",
            indicators: ["Urgence", "Menace de suspension", "Demande d'identifiants", "Domaine typosquatté", "Reply-To différent", "IP comme domaine"]
        },
        {
            id: "EM-003",
            sender: { name: "Compta TECHNOVA", email: "compta@technova-demo.test", replyTo: "compta@technova-demo.test", returnPath: "compta@technova-demo.test" },
            subject: "Facture fournisseur F-2026-0412 à valider",
            date: "2026-11-04 10:30",
            body: "Veuillez valider la facture F-2026-0412 dans le portail comptable avant la fin de semaine.",
            urls: ["https://portail.technova-demo.test/factures"],
            attachments: ["F-2026-0412.pdf"],
            auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
            expected: "legitimate",
            indicators: []
        },
        {
            id: "EM-004",
            sender: { name: "Direction Financière", email: "direction.finance@technova-demo.test", replyTo: "direction.finance.urgent@gmail-demo.test", returnPath: "bounce@tn-mailer.test" },
            subject: "Virement urgent - confidentiel",
            date: "2026-11-05 16:45",
            body: "Je suis en réunion. Effectuez un virement de 18 500 € vers le nouveau RIB ci-joint aujourd'hui, sans en parler à personne.",
            urls: [],
            attachments: ["nouveau_RIB.xlsm"],
            auth: { spf: "softfail", dkim: "fail", dmarc: "fail" },
            expected: "malicious",
            indicators: ["Urgence", "Instruction financière inhabituelle", "Paiement suspect", "Pièce jointe au format dangereux (.xlsm)", "Reply-To différent", "Demande de confidentialité"]
        },
        {
            id: "EM-005",
            sender: { name: "Service IT TECHNOVA", email: "it@technova-demo.test", replyTo: "it@technova-demo.test", returnPath: "it@technova-demo.test" },
            subject: "Maintenance programmée du VPN samedi",
            date: "2026-11-06 14:00",
            body: "Le VPN sera indisponible samedi de 22h à 02h pour maintenance. Aucune action requise de votre part.",
            urls: [],
            attachments: [],
            auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
            expected: "legitimate",
            indicators: []
        },
        {
            id: "EM-006",
            sender: { name: "Livraison Colis Express", email: "notif@colis-express-suivi.test", replyTo: "notif@colis-express-suivi.test", returnPath: "notif@colis-express-suivi.test" },
            subject: "Votre colis est en attente de paiement de frais de douane",
            date: "2026-11-07 11:20",
            body: "Un colis est bloqué. Réglez 2,49 € de frais de douane pour le libérer.",
            urls: ["https://bit.ly/3xColisExp", "https://colis-express-suivi.test/payer"],
            attachments: [],
            auth: { spf: "pass", dkim: "none", dmarc: "none" },
            expected: "suspicious",
            indicators: ["Demande de paiement", "URL raccourcie", "Pression temporelle"]
        },
        {
            id: "EM-007",
            sender: { name: "Équipe Projet", email: "projet@technova-demo.test", replyTo: "projet@technova-demo.test", returnPath: "projet@technova-demo.test" },
            subject: "Réunion de revue Q4 - ordre du jour",
            date: "2026-11-08 09:00",
            body: "Vous trouverez l'ordre du jour de la revue Q4 dans l'agenda partagé. Merci de confirmer votre présence.",
            urls: ["https://agenda.technova-demo.test/q4"],
            attachments: [],
            auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
            expected: "legitimate",
            indicators: []
        },
        {
            id: "EM-008",
            sender: { name: "Microsoft Account Team", email: "no-reply@accounts-microsoft-security.test", replyTo: "no-reply@accounts-microsoft-security.test", returnPath: "no-reply@accounts-microsoft-security.test" },
            subject: "Connexion inhabituelle détectée sur votre compte",
            date: "2026-11-09 07:55",
            body: "Une connexion depuis un nouvel appareil a été détectée. Si ce n'était pas vous, vérifiez votre activité dans les 24 heures.",
            urls: ["https://accounts-microsoft-security.test/activity"],
            attachments: [],
            auth: { spf: "neutral", dkim: "pass", dmarc: "none" },
            expected: "suspicious",
            indicators: ["Urgence modérée", "Domaine ressemblant à une marque", "Authentification partielle"]
        },
        {
            id: "EM-009",
            sender: { name: "Ressources Humaines", email: "rh-technova@technova-demo.test", replyTo: "rh-technova@technova-demo.test", returnPath: "rh-technova@technova-demo.test" },
            subject: "Vérification obligatoire de votre mot de passe VPN",
            date: "2026-11-10 13:10",
            body: "Pour des raisons de conformité, saisissez votre mot de passe VPN et votre code MFA sur le formulaire suivant.",
            urls: ["http://technova-vpn-check.test/form"],
            attachments: [],
            auth: { spf: "pass", dkim: "fail", dmarc: "fail" },
            expected: "malicious",
            indicators: ["Demande de mot de passe", "Demande de code MFA", "URL en HTTP non sécurisé", "Domaine imitant l'entreprise"]
        },
        {
            id: "EM-010",
            sender: { name: "Formation TECHNOVA", email: "formation@technova-demo.test", replyTo: "formation@technova-demo.test", returnPath: "formation@technova-demo.test" },
            subject: "Inscription à la session de sensibilisation cyber",
            date: "2026-11-11 15:30",
            body: "Une session de sensibilisation à la sécurité aura lieu jeudi à 10h en salle B. Inscription sur l'intranet.",
            urls: ["https://intranet.technova-demo.test/formations"],
            attachments: [],
            auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
            expected: "legitimate",
            indicators: []
        }
    ]
    
};
window.PHISHDETECT_DATA.scenario = {
  company: "TECHNOVA",
  title: "Campagne de phishing simulée",
  description: "Un employé fictif a saisi des identifiants de démonstration sur une fausse page. Aucun compte, service ou système réel n’est concerné. Les actions sont simulées.",
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


/**
 * Provider adapters for webmail DOM extraction.
 *
 * The phishing engine is provider-agnostic. Each provider adapter is responsible
 * only for locating the current message, extracting sender/link metadata, and
 * returning insertion targets for the inline assessment.
 */

const PhishSentryGmailProvider = {
  id: "gmail",
  label: "Gmail",

  getUnauditedSenderElements() {
    return document.querySelectorAll("span.gD[email]:not([data-phish-sentry-audited])");
  },

  markSenderAudited(senderElement) {
    senderElement.setAttribute("data-phish-sentry-audited", "true");
  },

  extractMessage(senderElement) {
    const email = senderElement.getAttribute("email") || "";
    const displayName = senderElement.textContent || "";
    const fromHeader = displayName ? `"${displayName}" <${email}>` : email;
    const messageWrapper = senderElement.closest(".adn");

    if (!messageWrapper || !email) {
      return null;
    }

    const links = [];
    const bodyContainer = messageWrapper.querySelector(".a3s");
    if (bodyContainer) {
      bodyContainer.querySelectorAll("a[href]").forEach(anchor => {
        links.push({
          href: anchor.getAttribute("href") || "",
          text: anchor.textContent || ""
        });
      });
    }

    return {
      provider: this.id,
      providerLabel: this.label,
      senderEmail: email,
      senderDisplayName: displayName,
      fromHeader,
      links,
      messageWrapper
    };
  },

  getInjectionTargets(messageWrapper) {
    return {
      bodyContainer: messageWrapper.querySelector(".a3s"),
      headerContainer: messageWrapper.querySelector(".gK") || messageWrapper
    };
  }
};

function detectProvider() {
  if (location.hostname === "mail.google.com") {
    return PhishSentryGmailProvider;
  }

  return null;
}

self.PhishSentryProviders = {
  detectProvider,
  providers: [PhishSentryGmailProvider]
};

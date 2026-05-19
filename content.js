/**
 * PhishSentry Webmail Content Script
 * 
 * Provider adapters extract sender/link metadata from supported webmail DOMs.
 * The engine runs locally, then this script injects a compact assessment.
 */

// Active state of last assessed email for Popup query sync
let activeAssessmentState = null;

// Debounce timer for DOM checks
let scanDebounceTimer = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

function normalizeRiskScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) return 0;
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function normalizeStatus(status) {
  const allowedStatuses = new Set(["safe", "unknown", "suspicious", "phishing"]);
  return allowedStatuses.has(status) ? status : "unknown";
}

function getAssessmentPresentation(status, riskScore, assessment) {
  const matchedBrand = assessment.details?.matchedBrand;
  const isWhitelisted = assessment.details?.whitelistMatched;

  if (status === "phishing") {
    return {
      title: "High-risk phishing signals",
      description: "Avoid links and attachments until you verify the sender outside this email.",
      action: "Do not click. Verify the request through a trusted channel.",
      button: "Review signals"
    };
  }

  if (status === "suspicious") {
    return {
      title: "Review before clicking",
      description: "Some sender or link signals need a second look.",
      action: "Inspect the domain and destination links before taking action.",
      button: "Review signals"
    };
  }

  if (status === "safe") {
    return {
      title: isWhitelisted ? "Trusted domain context" : "Known brand domain",
      description: matchedBrand ? `Sender domain matches ${matchedBrand}.` : "Sender domain is in your local trusted list.",
      action: "No high-risk signals were found, but verify unexpected requests.",
      button: "View details"
    };
  }

  return {
    title: "No high-risk signals",
    description: "This sender is not in your known brand list.",
    action: riskScore > 0 ? "Review the signals before clicking." : "Use normal caution for links, invoices, and login requests.",
    button: "View details"
  };
}

function hasCurrentMessageLinkWarnings(assessment) {
  return (assessment.details?.linkMismatches || []).length > 0;
}

function applyTrustedSenderState(badge, senderDomain, assessment) {
  const hasLinkWarnings = hasCurrentMessageLinkWarnings(assessment);
  const title = badge.querySelector(".ps-badge-title");
  const description = badge.querySelector(".ps-desc");
  const compactConfirmation = badge.querySelector(".ps-save-confirmation");
  const detailsConfirmation = badge.querySelector(".ps-feedback");
  const whitelistButton = badge.querySelector(".ps-whitelist-trigger");

  if (whitelistButton) {
    whitelistButton.textContent = "Saved";
    whitelistButton.disabled = true;
  }

  if (!hasLinkWarnings) {
    badge.classList.remove("ps-unknown", "ps-suspicious", "ps-phishing");
    badge.classList.add("ps-safe");
    if (title) title.textContent = "Trusted sender saved";
    if (description) {
      description.textContent = `${senderDomain} is now trusted locally. Future messages from this domain will show trusted context.`;
    }
  } else {
    if (title) title.textContent = "Sender trust saved";
    if (description) {
      description.textContent = "This sender is now trusted locally, but this message still has link warnings.";
    }
  }

  const confirmationText = hasLinkWarnings
    ? `${senderDomain} was added to trusted senders. Link warnings still apply to this message.`
    : `${senderDomain} was added to trusted senders. Link checks will continue to run.`;

  if (compactConfirmation) {
    compactConfirmation.textContent = confirmationText;
    compactConfirmation.classList.add("active");
  }

  if (detailsConfirmation) {
    detailsConfirmation.textContent = confirmationText;
  }
}

/**
 * Initializes the content script.
 */
function init() {
  const provider = self.PhishSentryProviders?.detectProvider();
  if (!provider) return;

  console.log(`PhishSentry active and monitoring ${provider.label}.`);
  
  // Set up mutation observer to monitor when elements are added to DOM
  const observer = new MutationObserver((mutations) => {
    clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(auditCurrentProvider, 500);
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Initial audit
  setTimeout(auditCurrentProvider, 1500);
  
  // Listen for queries from the extension popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "queryActiveEmail") {
      if (activeAssessmentState) {
        sendResponse({ success: true, data: activeAssessmentState });
      } else {
        sendResponse({ success: false });
      }
    }
    return true;
  });
}

/**
 * Scans the active provider DOM to locate opened email frames that have not
 * been audited yet, parses them, and injects safety guidance.
 */
function auditCurrentProvider() {
  const provider = self.PhishSentryProviders?.detectProvider();
  if (!provider) return;

  const senderElements = provider.getUnauditedSenderElements();
  
  if (senderElements.length === 0) return;
  
  chrome.storage.local.get(["customBrands", "whitelist"], (settings) => {
    const customBrands = settings.customBrands || [];
    const whitelist = settings.whitelist || [];
    
    senderElements.forEach((span) => {
      provider.markSenderAudited(span);
      const messageContext = provider.extractMessage(span);
      if (!messageContext) return;
      
      // Execute the security evaluation using our local engine
      const assessment = self.PhishSentryEngine.analyze(messageContext.fromHeader, messageContext.links, customBrands, whitelist);
      
      // Update global active state
      activeAssessmentState = {
        from: messageContext.senderDisplayName ? `"${messageContext.senderDisplayName}" <${messageContext.senderEmail}>` : messageContext.senderEmail,
        provider: messageContext.providerLabel,
        assessment
      };
      
      // Log only minimal, non-content scan metadata to persistent extension storage.
      chrome.runtime.sendMessage({
        action: "logScan",
        data: {
          senderDomain: assessment.details?.parsedSender?.domain || "",
          matchedBrand: assessment.details?.matchedBrand || null,
          status: assessment.status,
          riskScore: assessment.riskScore,
          reasons: assessment.reasons
        }
      });
      
      // Inject visual security badge above the email body container
      injectSafetyBadge(provider, messageContext.messageWrapper, assessment, messageContext.senderEmail);
    });
  });
}

/**
 * Injects the safety badge inside the provider message container.
 */
function injectSafetyBadge(provider, messageWrapper, assessment, senderEmail) {
  const { bodyContainer, headerContainer } = provider.getInjectionTargets(messageWrapper);
  const status = normalizeStatus(assessment.status);
  const riskScore = normalizeRiskScore(assessment.riskScore);
  const reasons = Array.isArray(assessment.reasons) ? assessment.reasons : [];
  const senderDomain = assessment.details?.parsedSender?.domain || "unknown-domain";
  const presentation = getAssessmentPresentation(status, riskScore, assessment);
  
  // Check if we already injected our badge inside this email wrapper
  if (messageWrapper.querySelector(".phish-sentry-injected-badge")) return;
  
  // Create beautiful, responsive glassmorphic element
  const badge = document.createElement("div");
  badge.className = `phish-sentry-injected-badge ps-${status}`;
  
  let iconSvg = "";
  let statusTitle = presentation.title;
  let descriptionText = presentation.description;
  let auditLabelText = presentation.button;
  
  // Elegant SVGs with glow and stroke effects
  if (status === "safe") {
    iconSvg = `
      <svg class="ps-icon svg-safe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M9 11L11 13L15 9" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
  } else if (status === "phishing") {
    iconSvg = `
      <svg class="ps-icon svg-phishing" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="8" x2="12" y2="13"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `;
  } else if (status === "suspicious") {
    iconSvg = `
      <svg class="ps-icon svg-suspicious" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="15" x2="12.01" y2="15"/>
      </svg>
    `;
  } else {
    iconSvg = `
      <svg class="ps-icon svg-unknown" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="12" cy="12" r="10"/>
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    `;
  }
  
  // Custom checklist audit lines
  const reasonsListHTML = reasons.map(r => `
    <li class="ps-audit-item">
      <svg class="ps-bullet" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
      <span>${escapeHtml(r)}</span>
    </li>
  `).join("");
  
  badge.innerHTML = `
    <style>
      .phish-sentry-injected-badge {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 16px 24px 16px 24px;
        padding: 16px 18px;
        border-radius: 18px;
        background: rgba(248, 249, 251, 0.78);
        border: 1px solid rgba(255, 255, 255, 0.82);
        box-shadow: 0 18px 44px rgba(15, 23, 42, 0.14), inset 0 1px 0 rgba(255,255,255,0.9), inset 0 -1px 0 rgba(15,23,42,0.04);
        backdrop-filter: blur(24px) saturate(170%);
        -webkit-backdrop-filter: blur(24px) saturate(170%);
        display: flex;
        flex-direction: column;
        gap: 10px;
        font-size: 13px;
        color: #1D1D1F;
        animation: ps-slide-down 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        max-width: 680px;
        z-index: 10;
        position: relative;
      }
      @keyframes ps-slide-down {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      
      /* Color Borders & Glows */
      .ps-safe {
        border-left: 4px solid #3A7D58;
        border-color: rgba(255,255,255,0.82) rgba(255,255,255,0.82) rgba(255,255,255,0.82) #3A7D58;
      }
      .ps-phishing {
        border-left: 4px solid #B42318;
        border-color: rgba(255,255,255,0.82) rgba(255,255,255,0.82) rgba(255,255,255,0.82) #B42318;
        box-shadow: 0 20px 48px rgba(180, 35, 24, 0.14), inset 0 1px 0 rgba(255,255,255,0.9);
      }
      .ps-suspicious {
        border-left: 4px solid #A15C07;
        border-color: rgba(255,255,255,0.82) rgba(255,255,255,0.82) rgba(255,255,255,0.82) #A15C07;
      }
      .ps-unknown {
        border-left: 4px solid #6E6E73;
        border-color: rgba(255,255,255,0.82) rgba(255,255,255,0.82) rgba(255,255,255,0.82) #6E6E73;
      }
      
      .ps-row { display: flex; align-items: center; justify-content: space-between; width: 100%; gap: 12px; }
      .ps-left { display: flex; align-items: center; gap: 12px; }
      
      .ps-icon { width: 22px; height: 22px; flex-shrink: 0; }
      .svg-safe { color: #3A7D58; }
      .svg-phishing { color: #B42318; }
      .svg-suspicious { color: #A15C07; }
      .svg-unknown { color: #6E6E73; }
      
      .ps-badge-title {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-weight: 700;
        font-size: 12px;
        letter-spacing: 0.2px;
      }
      .ps-safe .ps-badge-title { color: #2F684A; }
      .ps-phishing .ps-badge-title { color: #912018; }
      .ps-suspicious .ps-badge-title { color: #7A4305; }
      .ps-unknown .ps-badge-title { color: #515154; }
      
      .ps-desc { font-size: 11.5px; color: #515154; margin-top: 2px; font-weight: 400; line-height: 1.4; }
      
      .ps-action-group { display: flex; align-items: center; gap: 8px; }
      
      .ps-btn {
        background: rgba(255,255,255,0.62);
        border: 1px solid rgba(0,0,0,0.08);
        color: #1D1D1F;
        padding: 7px 11px;
        border-radius: 10px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: background 0.2s, border-color 0.2s, transform 0.2s;
        outline: none;
      }
      .ps-btn:hover { background: rgba(255,255,255,0.88); border-color: rgba(0,0,0,0.14); transform: translateY(-1px); }
      .ps-btn:active { transform: translateY(0); }
      .ps-btn:disabled { opacity: 0.62; cursor: default; transform: none; }
      
      .ps-btn-whitelist {
        background: rgba(29,29,31,0.88);
        border: 1px solid rgba(29,29,31,0.12);
        color: #FFFFFF;
      }
      .ps-btn-whitelist:hover {
        background: rgba(29,29,31,0.96);
        border-color: rgba(29,29,31,0.2);
      }
      
      /* Collapsible Panel */
      .ps-expanded-panel {
        display: none;
        margin-top: 8px;
        border-top: 1px solid rgba(0,0,0,0.06);
        padding-top: 10px;
        color: #515154;
        font-size: 11.5px;
        animation: ps-slide-up 0.25s ease-out;
      }
      @keyframes ps-slide-up {
        from { opacity: 0; transform: translateY(-4px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .ps-expanded-panel.active { display: block; }
      
      /* Progress bar styling in content */
      .ps-progress-container {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 8px;
      }
      .ps-progress-bar {
        flex: 1;
        height: 6px;
        background: rgba(0,0,0,0.06);
        border-radius: 4px;
        overflow: hidden;
      }
      .ps-progress-fill {
        height: 100%;
        border-radius: 4px;
        width: 0%;
        transition: width 0.6s ease;
      }
      .ps-progress-fill.safe { background: #3A7D58; }
      .ps-progress-fill.phishing { background: #B42318; }
      .ps-progress-fill.suspicious { background: #A15C07; }
      .ps-progress-fill.unknown { background: #8E8E93; }
      .safe-color { color: #3A7D58; }
      .phishing-color { color: #B42318; }
      .suspicious-color { color: #A15C07; }
      .unknown-color { color: #6E6E73; }
      .ps-context-line {
        display: flex;
        flex-wrap: wrap;
        gap: 6px 12px;
        margin-bottom: 8px;
        color: #515154;
      }
      .ps-context-line strong,
      .ps-recommendation strong { color: #1D1D1F; }
      .ps-recommendation {
        background: rgba(255,255,255,0.62);
        border: 1px solid rgba(0,0,0,0.06);
        border-radius: 12px;
        padding: 8px 10px;
        margin-bottom: 8px;
        color: #3A3A3C;
      }
      
      .ps-reasons-list { list-style: none; padding: 0; margin: 4px 0 0 0; display: flex; flex-direction: column; gap: 5px; }
      .ps-audit-item { display: flex; align-items: flex-start; gap: 8px; line-height: 1.4; }
      
      .ps-bullet { width: 12px; height: 12px; flex-shrink: 0; margin-top: 2px; }
      .ps-feedback {
        min-height: 14px;
        color: #3A7D58;
        font-size: 11px;
      }
      .ps-save-confirmation {
        display: none;
        margin-top: -2px;
        padding: 8px 10px;
        border-radius: 12px;
        background: rgba(58, 125, 88, 0.08);
        border: 1px solid rgba(58, 125, 88, 0.14);
        color: #2F684A;
        font-size: 11.5px;
        line-height: 1.35;
        animation: ps-slide-up 0.25s ease-out;
      }
      .ps-save-confirmation.active {
        display: block;
      }
      .ps-safe .ps-bullet { color: #3A7D58; }
      .ps-phishing .ps-bullet { color: #B42318; }
      .ps-suspicious .ps-bullet { color: #A15C07; }
      .ps-unknown .ps-bullet { color: #6E6E73; }
    </style>
    
    <div class="ps-row">
      <div class="ps-left">
          ${iconSvg}
        <div>
          <div class="ps-badge-title">${statusTitle}</div>
          <div class="ps-desc">${escapeHtml(descriptionText)}</div>
        </div>
      </div>
      <div class="ps-action-group">
        <button class="ps-btn ps-toggle-details">${auditLabelText}</button>
        ${
          status !== "safe" ? 
          `<button class="ps-btn ps-btn-whitelist ps-whitelist-trigger">Trust Sender</button>` : ""
        }
      </div>
    </div>

    <div class="ps-save-confirmation" aria-live="polite"></div>
    
    <div class="ps-expanded-panel">
      <div class="ps-progress-container">
        <span style="font-weight:600; color:#1D1D1F; min-width: 90px;">Risk score</span>
        <div class="ps-progress-bar">
          <div class="ps-progress-fill ${status}" style="width: ${riskScore || 5}%"></div>
        </div>
        <span style="font-weight:700;" class="${status}-color">${riskScore}%</span>
      </div>
      <div class="ps-context-line">
        <span><strong>Sender domain:</strong> ${escapeHtml(senderDomain)}</span>
        <span><strong>Provider:</strong> ${escapeHtml(provider.label)}</span>
      </div>
      <div class="ps-recommendation"><strong>Recommended action:</strong> ${escapeHtml(presentation.action)}</div>
      <div style="font-weight:600; color:#1D1D1F; margin-bottom: 4px; font-size:11px;">Signals</div>
      <ul class="ps-reasons-list">
        ${reasonsListHTML}
      </ul>
      <div class="ps-feedback" aria-live="polite"></div>
    </div>
  `;
  
  // Attach Detail Toggle behavior
  const toggleBtn = badge.querySelector(".ps-toggle-details");
  const detailsPanel = badge.querySelector(".ps-expanded-panel");
  if (toggleBtn && detailsPanel) {
    toggleBtn.addEventListener("click", () => {
      detailsPanel.classList.toggle("active");
    });
  }
  
  // Attach Whitelist trigger behavior
  const whitelistBtn = badge.querySelector(".ps-whitelist-trigger");
  if (whitelistBtn) {
    whitelistBtn.addEventListener("click", () => {
      const parts = senderEmail.split("@");
      if (parts.length < 2) return;
      const senderDomain = parts[1].toLowerCase();
      
      chrome.storage.local.get("whitelist", (settings) => {
        const whitelist = settings.whitelist || [];
        if (!whitelist.includes(senderDomain)) {
          whitelist.push(senderDomain);
          chrome.storage.local.set({ whitelist }, () => {
            applyTrustedSenderState(badge, senderDomain, assessment);
          });
        } else {
          applyTrustedSenderState(badge, senderDomain, assessment);
        }
      });
    });
  }
  
  // Inject right above the email body when the provider exposes that target.
  if (bodyContainer) {
    bodyContainer.parentNode.insertBefore(badge, bodyContainer);
  } else {
    headerContainer.appendChild(badge);
  }
}

// Start Content Monitoring
init();

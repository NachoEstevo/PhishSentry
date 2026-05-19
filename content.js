/**
 * PhishSentry Gmail Content Script (Redesigned Premium UI)
 * 
 * Injected into Gmail (https://mail.google.com/*).
 * Listens for open emails, extracts sender metadata and hyperlinks,
 * executes local threat analyses, and injects visual safety badges.
 * 
 * Target position: Injected directly above the email body (.a3s)
 * to avoid overlap with Gmail's native warning blocks and spam containers.
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

/**
 * Initializes the content script.
 */
function init() {
  console.log("PhishSentry active and monitoring Gmail thread DOM.");
  
  // Set up mutation observer to monitor when elements are added to DOM
  const observer = new MutationObserver((mutations) => {
    clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(auditGmailThreads, 500);
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Initial audit
  setTimeout(auditGmailThreads, 1500);
  
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
 * Scans the active Gmail DOM to locate opened email conversation frames
 * that have not been audited yet, parses them, and injects safety shields.
 */
function auditGmailThreads() {
  const senderElements = document.querySelectorAll("span.gD[email]:not([data-phish-sentry-audited])");
  
  if (senderElements.length === 0) return;
  
  chrome.storage.local.get(["customBrands", "whitelist"], (settings) => {
    const customBrands = settings.customBrands || [];
    const whitelist = settings.whitelist || [];
    
    senderElements.forEach((span) => {
      // Mark as audited to prevent multiple scans
      span.setAttribute("data-phish-sentry-audited", "true");
      
      const email = span.getAttribute("email");
      const name = span.textContent || "";
      const fromHeader = `"${name}" <${email}>`;
      
      // Locate the message wrapper
      const messageWrapper = span.closest(".adn");
      if (!messageWrapper) return;
      
      // Extract all links inside this specific email body (.a3s)
      const links = [];
      const bodyContainer = messageWrapper.querySelector(".a3s");
      if (bodyContainer) {
        const anchors = bodyContainer.querySelectorAll("a[href]");
        anchors.forEach(a => {
          links.push({
            href: a.getAttribute("href") || "",
            text: a.textContent || ""
          });
        });
      }
      
      // Execute the security evaluation using our local engine
      const assessment = self.PhishSentryEngine.analyze(fromHeader, links, customBrands, whitelist);
      
      // Update global active state
      activeAssessmentState = {
        from: name ? `"${name}" <${email}>` : email,
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
      injectSafetyBadge(messageWrapper, assessment, email);
    });
  });
}

/**
 * Injects the safety badge inside the Gmail email container DOM.
 * Redesigned to sit right above the email body (.a3s) to prevent overlap.
 */
function injectSafetyBadge(messageWrapper, assessment, senderEmail) {
  const bodyContainer = messageWrapper.querySelector(".a3s");
  const headerContainer = messageWrapper.querySelector(".gK") || messageWrapper;
  const status = normalizeStatus(assessment.status);
  const riskScore = normalizeRiskScore(assessment.riskScore);
  const reasons = Array.isArray(assessment.reasons) ? assessment.reasons : [];
  
  // Check if we already injected our badge inside this email wrapper
  if (messageWrapper.querySelector(".phish-sentry-injected-badge")) return;
  
  // Create beautiful, responsive glassmorphic element
  const badge = document.createElement("div");
  badge.className = `phish-sentry-injected-badge ps-${status}`;
  
  let iconSvg = "";
  let statusTitle = "";
  let descriptionText = "";
  let auditLabelText = "Examine Security Audit";
  
  // Elegant SVGs with glow and stroke effects
  if (status === "safe") {
    iconSvg = `
      <svg class="ps-icon svg-safe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M9 11L11 13L15 9" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
    statusTitle = "VERIFIED SAFE SENDER";
    descriptionText = reasons[0] || "Sender domain is trusted.";
  } else if (status === "phishing") {
    iconSvg = `
      <svg class="ps-icon svg-phishing" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="8" x2="12" y2="13"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `;
    statusTitle = "CRITICAL PHISHING ALERT";
    descriptionText = "Danger: Severe security anomalies detected. Do not click links or download files.";
    auditLabelText = "Review Phishing Flags";
  } else if (status === "suspicious") {
    iconSvg = `
      <svg class="ps-icon svg-suspicious" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="15" x2="12.01" y2="15"/>
      </svg>
    `;
    statusTitle = "SUSPICIOUS THREAT INDICATOR";
    descriptionText = "Warning: Some elements of this email appear deceptive. Exercise caution.";
  } else {
    iconSvg = `
      <svg class="ps-icon svg-unknown" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="12" cy="12" r="10"/>
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    `;
    statusTitle = "UNVERIFIED SENDER";
    descriptionText = "This domain is not in our verified brands database. Standard caution advised.";
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
        padding: 14px 18px;
        border-radius: 12px;
        background: rgba(13, 17, 28, 0.96);
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255,255,255,0.05);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
        gap: 8px;
        font-size: 13px;
        color: #E5E7EB;
        animation: ps-slide-down 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        max-width: 620px;
        z-index: 10;
        position: relative;
      }
      @keyframes ps-slide-down {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      
      /* Color Borders & Glows */
      .ps-safe {
        border-left: 4px solid #10B981;
        border-color: rgba(16,185,129,0.15) rgba(16,185,129,0.15) rgba(16,185,129,0.15) #10B981;
      }
      .ps-phishing {
        border-left: 4px solid #EF4444;
        border-color: rgba(239,68,68,0.15) rgba(239,68,68,0.15) rgba(239,68,68,0.15) #EF4444;
        box-shadow: 0 12px 36px rgba(239, 68, 68, 0.08), 0 0 1px rgba(239, 68, 68, 0.3);
      }
      .ps-suspicious {
        border-left: 4px solid #F59E0B;
        border-color: rgba(245,158,11,0.15) rgba(245,158,11,0.15) rgba(245,158,11,0.15) #F59E0B;
      }
      .ps-unknown {
        border-left: 4px solid #8B5CF6;
        border-color: rgba(139,92,246,0.15) rgba(139,92,246,0.15) rgba(139,92,246,0.15) #8B5CF6;
      }
      
      .ps-row { display: flex; align-items: center; justify-content: space-between; width: 100%; gap: 12px; }
      .ps-left { display: flex; align-items: center; gap: 12px; }
      
      .ps-icon { width: 22px; height: 22px; flex-shrink: 0; }
      .svg-safe { color: #10B981; filter: drop-shadow(0 0 4px rgba(16, 185, 129, 0.3)); }
      .svg-phishing { color: #EF4444; filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.4)); }
      .svg-suspicious { color: #F59E0B; filter: drop-shadow(0 0 4px rgba(245, 158, 11, 0.3)); }
      .svg-unknown { color: #8B5CF6; filter: drop-shadow(0 0 4px rgba(139, 92, 246, 0.3)); }
      
      .ps-badge-title {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-weight: 700;
        font-size: 12px;
        letter-spacing: 0.8px;
        text-transform: uppercase;
      }
      .ps-safe .ps-badge-title { color: #10B981; }
      .ps-phishing .ps-badge-title { color: #EF4444; }
      .ps-suspicious .ps-badge-title { color: #F59E0B; }
      .ps-unknown .ps-badge-title { color: #8B5CF6; }
      
      .ps-desc { font-size: 11px; color: #9CA3AF; margin-top: 2px; font-weight: 400; line-height: 1.35; }
      
      .ps-action-group { display: flex; align-items: center; gap: 8px; }
      
      .ps-btn {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        color: #F3F4F6;
        padding: 5px 10px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: all 0.2s;
        outline: none;
      }
      .ps-btn:hover { background: rgba(255,255,255,0.08); border-color: rgba(255,255,255,0.18); }
      
      .ps-btn-whitelist {
        background: rgba(16,185,129,0.08);
        border: 1px solid rgba(16,185,129,0.2);
        color: #10B981;
      }
      .ps-btn-whitelist:hover {
        background: rgba(16,185,129,0.15);
        border-color: rgba(16,185,129,0.35);
        box-shadow: 0 0 8px rgba(16,185,129,0.1);
      }
      
      /* Collapsible Panel */
      .ps-expanded-panel {
        display: none;
        margin-top: 8px;
        border-top: 1px solid rgba(255,255,255,0.06);
        padding-top: 8px;
        color: #9CA3AF;
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
        background: rgba(255,255,255,0.05);
        border-radius: 4px;
        overflow: hidden;
      }
      .ps-progress-fill {
        height: 100%;
        border-radius: 4px;
        width: 0%;
        transition: width 0.6s ease;
      }
      .ps-progress-fill.safe { background: #10B981; }
      .ps-progress-fill.phishing { background: #EF4444; }
      .ps-progress-fill.suspicious { background: #F59E0B; }
      .ps-progress-fill.unknown { background: #8B5CF6; }
      
      .ps-reasons-list { list-style: none; padding: 0; margin: 4px 0 0 0; display: flex; flex-direction: column; gap: 5px; }
      .ps-audit-item { display: flex; align-items: flex-start; gap: 8px; line-height: 1.4; }
      
      .ps-bullet { width: 12px; height: 12px; flex-shrink: 0; margin-top: 2px; }
      .ps-safe .ps-bullet { color: #10B981; }
      .ps-phishing .ps-bullet { color: #EF4444; }
      .ps-suspicious .ps-bullet { color: #F59E0B; }
      .ps-unknown .ps-bullet { color: #8B5CF6; }
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
    
    <div class="ps-expanded-panel">
      <div class="ps-progress-container">
        <span style="font-weight:600; color:#F3F4F6; min-width: 90px;">PhishSentry Score:</span>
        <div class="ps-progress-bar">
          <div class="ps-progress-fill ${status}" style="width: ${riskScore || 5}%"></div>
        </div>
        <span style="font-weight:700;" class="${status}-color">${riskScore}% Threat</span>
      </div>
      <div style="font-weight:600; color:#F3F4F6; margin-bottom: 4px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">Audit Details:</div>
      <ul class="ps-reasons-list">
        ${reasonsListHTML}
      </ul>
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
            alert(`Domain "${senderDomain}" added to trusted whitelist. Re-open this email to refresh protection status.`);
            badge.remove();
          });
        }
      });
    });
  }
  
  // Inject right above the email body element (.a3s) so it sits elegantly
  // below the native Gmail warnings/spam popups and is 100% visible!
  if (bodyContainer) {
    bodyContainer.parentNode.insertBefore(badge, bodyContainer);
  } else {
    headerContainer.appendChild(badge);
  }
}

// Start Content Monitoring
init();

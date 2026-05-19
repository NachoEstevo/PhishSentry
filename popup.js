/**
 * PhishSentry Extension Popup Controller
 * 
 * Controls UI tabs, handles real-time statistics binding, retrieves and renders
 * scan history logs with toggleable detail blocks, queries active Gmail tabs
 * for real-time evaluations, and binds settings forms.
 */

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

function normalizeStatus(status) {
  const allowedStatuses = new Set(["safe", "unknown", "suspicious", "phishing"]);
  return allowedStatuses.has(status) ? status : "unknown";
}

function normalizeRiskScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) return 0;
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function normalizeDomainInput(value) {
  const rawValue = String(value || "").trim().toLowerCase();
  if (!rawValue) return "";

  try {
    const parsed = new URL(rawValue.includes("://") ? rawValue : `https://${rawValue}`);
    return parsed.hostname.replace(/^www\./, "");
  } catch (error) {
    return rawValue
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .replace(/^www\./, "")
      .replace(/[^a-z0-9.-]/g, "");
  }
}

function getAssessmentPresentation(status, riskScore, assessment = {}) {
  const matchedBrand = assessment.details?.matchedBrand;
  const isWhitelisted = assessment.details?.whitelistMatched;

  if (status === "phishing") {
    return {
      label: "High risk",
      action: "Do not click. Verify the request outside this email.",
      tone: "Critical signals"
    };
  }

  if (status === "suspicious") {
    return {
      label: "Review",
      action: "Inspect the sender domain and destination links before acting.",
      tone: "Signals found"
    };
  }

  if (status === "safe") {
    return {
      label: isWhitelisted ? "Trusted context" : "Known domain",
      action: matchedBrand ? `Domain matches ${matchedBrand}. Stay cautious with unexpected requests.` : "Trusted locally. Link checks still run.",
      tone: "No high-risk signals"
    };
  }

  return {
    label: "No high-risk signals",
    action: riskScore > 0 ? "Review the listed signal before clicking." : "Use normal caution with links, invoices, and login requests.",
    tone: "Unverified sender"
  };
}

if (!globalThis.chrome?.storage?.local) {
  const previewState = {
    stats: { totalScanned: 0, safe: 0, suspicious: 0, phishing: 0 },
    history: [],
    customBrands: [],
    whitelist: ["google.com", "gmail.com", "microsoft.com"]
  };

  globalThis.chrome = {
    runtime: {
      lastError: null,
      sendMessage(message, callback) {
        if (message?.action === "clearAllLogs") {
          previewState.stats = { totalScanned: 0, safe: 0, suspicious: 0, phishing: 0 };
          previewState.history = [];
        }
        if (callback) callback({ success: true });
      }
    },
    storage: {
      local: {
        get(keys, callback) {
          if (Array.isArray(keys)) {
            callback(Object.fromEntries(keys.map(key => [key, previewState[key]])));
            return;
          }

          if (typeof keys === "string") {
            callback({ [keys]: previewState[keys] });
            return;
          }

          callback({ ...previewState });
        },
        set(update, callback) {
          Object.assign(previewState, update);
          if (callback) callback();
        }
      }
    },
    tabs: {
      query(_queryInfo, callback) {
        callback([]);
      },
      sendMessage(_tabId, _message, callback) {
        if (callback) callback({ success: false });
      }
    }
  };
}

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs Controller
  const tabs = document.querySelectorAll(".nav-tab");
  const panels = document.querySelectorAll(".content-panel");
  
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.target;
      
      // Update active nav state
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      
      // Toggle panel visibility
      panels.forEach(panel => {
        if (panel.id === target) {
          panel.classList.add("active");
        } else {
          panel.classList.remove("active");
        }
      });
      
      // Special action on panel display
      if (target === "history") {
        renderHistoryList();
      } else if (target === "settings") {
        renderSettingsLists();
      }
    });
  });
  
  // Initialize dynamic data
  bindStatistics();
  bindActiveEmailScan();
  bindSettingsActions();
  
  // Set up Clear Logs listener
  const btnClearLogs = document.getElementById("btn-clear-logs");
  if (btnClearLogs) {
    btnClearLogs.addEventListener("click", () => {
      if (confirm("Are you sure you want to clear your threat history and stats? This action is permanent.")) {
        chrome.runtime.sendMessage({ action: "clearAllLogs" }, (response) => {
          if (response && response.success) {
            animateValue("stat-total", 0);
            animateValue("stat-safe", 0);
            animateValue("stat-phishing", 0);
            renderHistoryList();
          }
        });
      }
    });
  }
});

/**
 * Retrieves storage metrics and binds them to the stats panel.
 * Uses an animated numerical incrementer to look professional.
 */
function bindStatistics() {
  chrome.storage.local.get("stats", (result) => {
    const stats = result.stats || { totalScanned: 0, safe: 0, suspicious: 0, phishing: 0 };
    
    // Bind with soft counting animation
    animateValue("stat-total", stats.totalScanned);
    animateValue("stat-safe", stats.safe);
    animateValue("stat-phishing", stats.phishing);
  });
}

/**
 * Increments numerical elements smoothly.
 */
function animateValue(id, endValue) {
  const obj = document.getElementById(id);
  if (!obj) return;
  
  const startValue = parseInt(obj.textContent) || 0;
  if (startValue === endValue) {
    obj.textContent = endValue;
    return;
  }
  
  const duration = 400; // ms
  const startTime = performance.now();
  
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Cubic easeOut progression
    const easeProgress = 1 - Math.pow(1 - progress, 3);
    const currentValue = Math.floor(startValue + easeProgress * (endValue - startValue));
    
    obj.textContent = currentValue;
    
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      obj.textContent = endValue;
    }
  }
  
  requestAnimationFrame(update);
}

/**
 * Checks if the user is on a Gmail conversation thread tab.
 * If so, queries the active tab content script for current assessment metrics.
 */
function bindActiveEmailScan() {
  const container = document.getElementById("active-email-info");
  if (!container) return;
  
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) return;
    
    const activeTab = tabs[0];
    const isGmail = activeTab.url && activeTab.url.includes("mail.google.com");
    
    if (!isGmail) {
      // Default non-Gmail view is already in HTML, do nothing
      return;
    }
    
    // User is on Gmail. Send message to content script to inspect active email DOM
    chrome.tabs.sendMessage(activeTab.id, { action: "queryActiveEmail" }, (response) => {
      // If content script is sleeping, offline, or hasn't open an email, render loading/waiting
      if (chrome.runtime.lastError || !response || !response.success) {
        container.innerHTML = `
          <div class="inactive-state">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="rgba(29,29,31,0.38)" stroke-width="1.5" class="glowing-logo"><path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 8V12"/><path d="M12 16H12.01"/></svg>
            <p>Gmail active.</p>
            <span class="help-label">Select or open a message inside Gmail to view safety audits in real-time.</span>
          </div>
        `;
        return;
      }
      
      // We have a successful scan! Render details.
      const { assessment } = response.data;
      const parsedFrom = assessment.details?.parsedSender || {};
      const displayLabel = parsedFrom.displayName || parsedFrom.email;
      const badgeClass = normalizeStatus(assessment.status);
      const riskScore = normalizeRiskScore(assessment.riskScore);
      const presentation = getAssessmentPresentation(badgeClass, riskScore, assessment);
      
      let reasonsHTML = "";
      if (assessment.reasons && assessment.reasons.length > 0) {
        reasonsHTML = `
          <ul class="scan-reasons-list">
            ${assessment.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}
          </ul>
        `;
      }
      
      container.innerHTML = `
        <div class="scan-result-wrapper">
          <div class="assessment-header">
            <span class="risk-label-badge ${badgeClass}">${escapeHtml(presentation.label)}</span>
            <div style="font-family: var(--font-title); font-weight:700;">
              Risk <span class="${badgeClass}-color">${riskScore}%</span>
            </div>
          </div>
          
          <div class="risk-progress-bar">
            <div class="progress-fill ${badgeClass}" style="width: ${riskScore || 5}%"></div>
          </div>
          
          <div class="scan-details-section" style="margin-top: 6px;">
            <div class="scan-meta"><strong>Sender:</strong> ${escapeHtml(displayLabel || "Unknown sender")}</div>
            <div class="scan-meta" style="font-size:11px; color:var(--text-muted);"><strong>Domain:</strong> ${escapeHtml(parsedFrom.domain || "unknown-domain")}</div>
            <div class="recommendation-box"><strong>${escapeHtml(presentation.tone)}.</strong> ${escapeHtml(presentation.action)}</div>
            
            ${reasonsHTML}
          </div>
        </div>
      `;
    });
  });
}

/**
 * Renders the logged list of scanned emails.
 */
function renderHistoryList() {
  const container = document.getElementById("logs-list");
  if (!container) return;
  
  chrome.storage.local.get("history", (result) => {
    const history = result.history || [];
    
    if (history.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p>No logged emails. All quiet on the threat front.</p>
        </div>
      `;
      return;
    }
    
    let logsHTML = "";
    history.forEach(log => {
      const date = new Date(log.timestamp);
      const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " " + date.toLocaleDateString([], { month: 'short', day: 'numeric' });
      const status = normalizeStatus(log.status);
      const riskScore = normalizeRiskScore(log.riskScore);
      const senderDomain = log.senderDomain || normalizeDomainInput(log.from) || "unknown-domain";
      const matchedBrand = typeof log.matchedBrand === "string" ? log.matchedBrand : "";
      const logLabel = matchedBrand ? `${matchedBrand} - ${senderDomain}` : senderDomain;
      const logId = escapeHtml(log.id || `${log.timestamp}-${senderDomain}`);
      
      let badgeLabel = status.toUpperCase();
      if (status === "safe") badgeLabel = "KNOWN";
      if (status === "unknown") badgeLabel = "QUIET";
      if (status === "phishing") badgeLabel = "HIGH";
      if (status === "suspicious") badgeLabel = "REVIEW";
      
      let reasonsHTML = "";
      if (log.reasons && log.reasons.length > 0) {
        reasonsHTML = `
          <ul class="log-reasons-list">
            ${log.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}
          </ul>
        `;
      }
      
      logsHTML += `
        <div class="log-card" data-id="${logId}">
          <div class="log-card-header">
            <span class="log-sender">${escapeHtml(logLabel)}</span>
            <span class="log-badge ${status}">${badgeLabel}</span>
          </div>
          <div class="log-subject">Privacy log: sender address and subject are not stored.</div>
          <div class="log-time">${timeStr}</div>
          
          <div class="log-expanded-details" id="details-${logId}">
            <div style="font-weight:600; margin-bottom: 4px;">Audit Path:</div>
            <div>Risk Score: <strong>${riskScore}%</strong></div>
            ${reasonsHTML}
          </div>
        </div>
      `;
    });
    
    container.innerHTML = logsHTML;
    
    // Attach click listeners to cards to toggle detail expansion
    const cards = container.querySelectorAll(".log-card");
    cards.forEach(card => {
      card.addEventListener("click", () => {
        const id = card.dataset.id;
        const details = document.getElementById(`details-${id}`);
        if (details) {
          details.classList.toggle("active");
        }
      });
    });
  });
}

/**
 * Dynamic list binding for Whitelist and Custom Brands forms
 */
function bindSettingsActions() {
  // Custom Brand form submit
  const formCustomBrand = document.getElementById("form-custom-brand");
  if (formCustomBrand) {
    formCustomBrand.addEventListener("submit", (e) => {
      e.preventDefault();
      
      const nameInput = document.getElementById("input-brand-name");
      const domainInput = document.getElementById("input-brand-domain");
      
      if (!nameInput || !domainInput) return;
      
      const name = nameInput.value.trim();
      const domain = normalizeDomainInput(domainInput.value);
      if (!name || !domain) return;
      
      chrome.storage.local.get("customBrands", (result) => {
        const customBrands = result.customBrands || [];
        
        // Add item
        customBrands.push({
          name,
          keywords: [name.toLowerCase()],
          domains: [domain]
        });
        
        chrome.storage.local.set({ customBrands }, () => {
          nameInput.value = "";
          domainInput.value = "";
          renderSettingsLists();
        });
      });
    });
  }
  
  // Whitelist form submit
  const formWhitelist = document.getElementById("form-whitelist");
  if (formWhitelist) {
    formWhitelist.addEventListener("submit", (e) => {
      e.preventDefault();
      
      const domainInput = document.getElementById("input-whitelist-domain");
      if (!domainInput) return;
      
      const domain = normalizeDomainInput(domainInput.value);
      if (!domain) return;
      
      chrome.storage.local.get("whitelist", (result) => {
        const whitelist = result.whitelist || [];
        
        if (!whitelist.includes(domain)) {
          whitelist.push(domain);
        }
        
        chrome.storage.local.set({ whitelist }, () => {
          domainInput.value = "";
          renderSettingsLists();
        });
      });
    });
  }
}

/**
 * Renders lists in Settings panel (Custom Brands and Whitelist)
 */
function renderSettingsLists() {
  const brandList = document.getElementById("custom-brands-list");
  const whitelistList = document.getElementById("whitelist-list");
  
  if (brandList) {
    chrome.storage.local.get("customBrands", (result) => {
      const customBrands = result.customBrands || [];
      
      if (customBrands.length === 0) {
        brandList.innerHTML = `<li style="color:var(--text-muted); justify-content:center;">No custom brands configured.</li>`;
        return;
      }
      
      brandList.innerHTML = customBrands.map((brand, idx) => `
        <li>
          <div>
            <span class="entry-name">${escapeHtml(brand.name)}</span>
            <span class="entry-domain">&lt;${escapeHtml(brand.domains[0])}&gt;</span>
          </div>
          <button class="delete-entry-btn" data-type="brand" data-index="${idx}">×</button>
        </li>
      `).join("");
      
      // Bind delete events
      brandList.querySelectorAll(".delete-entry-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          const index = parseInt(btn.dataset.index);
          deleteSettingItem("customBrands", index);
        });
      });
    });
  }
  
  if (whitelistList) {
    chrome.storage.local.get("whitelist", (result) => {
      const whitelist = result.whitelist || [];
      
      if (whitelist.length === 0) {
        whitelistList.innerHTML = `<li style="color:var(--text-muted); justify-content:center;">Whitelist is empty.</li>`;
        return;
      }
      
      whitelistList.innerHTML = whitelist.map((domain, idx) => `
        <li>
          <span class="entry-name">${escapeHtml(domain)}</span>
          <button class="delete-entry-btn" data-type="whitelist" data-index="${idx}">×</button>
        </li>
      `).join("");
      
      // Bind delete events
      whitelistList.querySelectorAll(".delete-entry-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          const index = parseInt(btn.dataset.index);
          deleteSettingItem("whitelist", index);
        });
      });
    });
  }
}

/**
 * Removes an item from customBrands or whitelist arrays
 */
function deleteSettingItem(storageKey, index) {
  chrome.storage.local.get(storageKey, (result) => {
    const list = result[storageKey] || [];
    list.splice(index, 1);
    
    const updateObj = {};
    updateObj[storageKey] = list;
    
    chrome.storage.local.set(updateObj, () => {
      renderSettingsLists();
    });
  });
}

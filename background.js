/**
 * PhishSentry Chrome Extension Background Service Worker
 * (Manifest V3 Compliance)
 * 
 * Manages central persistent state (history, counters, whitelists, custom brands)
 * and processes incoming message events from content scripts and popup UI.
 */

const DEFAULT_STATS = {
  totalScanned: 0,
  safe: 0,
  suspicious: 0,
  phishing: 0
};

function normalizeStatus(status) {
  const allowedStatuses = new Set(["safe", "unknown", "suspicious", "phishing"]);
  return allowedStatuses.has(status) ? status : "unknown";
}

function normalizeRiskScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) return 0;
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function sanitizeDomain(domain) {
  return String(domain || "")
    .toLowerCase()
    .trim()
    .replace(/^[^@]*@/, "")
    .replace(/[^a-z0-9.-]/g, "")
    .slice(0, 253);
}

function summarizeReasons(reasons) {
  if (!Array.isArray(reasons)) return ["No detailed signals were stored."];

  const summaries = [];
  const add = (summary) => {
    if (!summaries.includes(summary)) summaries.push(summary);
  };

  reasons.forEach((reason) => {
    const text = String(reason || "");
    if (text.includes("Brand Claim Abuse")) add("Brand claim from a free webmail domain.");
    else if (text.includes("Brand Domain Mismatch")) add("Brand name did not match the sender domain.");
    else if (text.includes("Lookalike Domain Detected")) add("Sender domain resembled a known brand domain.");
    else if (text.includes("Deceptive Subdomain/Brand Inclusion")) add("Sender domain included a brand name suspiciously.");
    else if (text.includes("Link spoofing")) add("Visible link text redirected to a different domain.");
    else if (text.includes("Link redirect typosquatting")) add("A link pointed to a lookalike domain.");
    else if (text.includes("Internationalized Domain")) add("Sender domain used internationalized or mixed-script characters.");
    else if (text.includes("Internationalized link")) add("A link pointed to an internationalized or mixed-script domain.");
    else if (text.includes("Could not extract")) add("Sender domain could not be extracted.");
    else if (text.includes("Verified official email")) add("Sender matched a known official brand domain.");
    else if (text.toLowerCase().includes("whitelist")) add("Sender domain was trusted by the user.");
    else if (text.includes("No immediate phishing indicators")) add("No immediate phishing indicators were found.");
  });

  return summaries.length > 0 ? summaries.slice(0, 5) : ["No detailed signals were stored."];
}

function redactLegacyLog(log) {
  return {
    id: String(log.id || Date.now().toString(36)),
    timestamp: log.timestamp || new Date().toISOString(),
    senderDomain: sanitizeDomain(log.senderDomain || log.from || ""),
    matchedBrand: typeof log.matchedBrand === "string" ? log.matchedBrand.slice(0, 80) : null,
    status: normalizeStatus(log.status),
    riskScore: normalizeRiskScore(log.riskScore),
    reasons: summarizeReasons(log.reasons)
  };
}

// Initialize default settings upon extension installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["stats", "history", "customBrands", "whitelist"], (result) => {
    const updates = {};
    
    if (!result.stats) {
      updates.stats = DEFAULT_STATS;
    }
    
    if (!result.history) {
      updates.history = [];
    } else if (Array.isArray(result.history)) {
      const redactedHistory = result.history.map(redactLegacyLog);
      const historyChanged = JSON.stringify(redactedHistory) !== JSON.stringify(result.history);
      if (historyChanged) {
        updates.history = redactedHistory;
      }
    }
    
    if (!result.customBrands) {
      updates.customBrands = [];
    }
    
    if (!result.whitelist) {
      updates.whitelist = [
        "google.com",
        "gmail.com",
        "outlook.com",
        "microsoft.com"
      ];
    }
    
    if (Object.keys(updates).length > 0) {
      chrome.storage.local.set(updates, () => {
        console.log("PhishSentry initialized with default parameters.");
      });
    }
  });
});

// Update the extension badge dynamically based on scanned counts or threats
function updateActionBadge(stats) {
  if (!stats) return;
  
  const blockedPhishCount = stats.phishing || 0;
  if (blockedPhishCount > 0) {
    chrome.action.setBadgeText({ text: String(blockedPhishCount) });
    chrome.action.setBadgeBackgroundColor({ color: "#FF3B30" }); // Deep Crimson Red
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
}

// Keep the badge in sync with statistics
chrome.storage.local.get("stats", (result) => {
  if (result.stats) {
    updateActionBadge(result.stats);
  }
});

// Handle incoming messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "logScan") {
    const scanData = message.data || {};
    const status = normalizeStatus(scanData.status);
    
    chrome.storage.local.get(["stats", "history"], (result) => {
      const stats = result.stats || { ...DEFAULT_STATS };
      const history = result.history || [];
      
      // Update statistics
      stats.totalScanned += 1;
      if (status === "safe") {
        stats.safe += 1;
      } else if (status === "phishing") {
        stats.phishing += 1;
      } else if (status === "suspicious") {
        stats.suspicious += 1;
      }
      
      // Prepend privacy-preserving history (keep last 100 entries).
      // Do not persist sender addresses, subject lines, body text, or raw links.
      const newScanLog = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        timestamp: new Date().toISOString(),
        senderDomain: sanitizeDomain(scanData.senderDomain) || "unknown-domain",
        matchedBrand: typeof scanData.matchedBrand === "string" ? scanData.matchedBrand.slice(0, 80) : null,
        status,
        riskScore: normalizeRiskScore(scanData.riskScore),
        reasons: summarizeReasons(scanData.reasons)
      };
      
      history.unshift(newScanLog);
      if (history.length > 100) {
        history.pop();
      }
      
      chrome.storage.local.set({ stats, history }, () => {
        updateActionBadge(stats);
        sendResponse({ success: true, log: newScanLog });
      });
    });
    
    return true; // Keeps the sendResponse channel open for async execution
  }
  
  if (message.action === "clearAllLogs") {
    chrome.storage.local.set({
      stats: { ...DEFAULT_STATS },
      history: []
    }, () => {
      chrome.action.setBadgeText({ text: "" });
      sendResponse({ success: true });
    });
    return true;
  }
});

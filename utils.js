/**
 * PhishSentry Utility Helpers
 * 
 * Includes email sender header parsing, second-level domain (SLD) extraction
 * with support for country code TLDs, and Levenshtein edit distance calculations.
 * 
 * Dual-compatible: Runs natively in Node.js (CommonJS) and browser/extension contexts.
 */

/**
 * Parses a standard email "From" header value.
 * Supports:
 * - "Brand Name" <sender@domain.com>
 * - Brand Name <sender@domain.com>
 * - sender@domain.com
 * - <sender@domain.com>
 * 
 * @param {string} fromHeader The raw From header text
 * @returns {{displayName: string, email: string, domain: string}}
 */
function parseSender(fromHeader) {
  if (!fromHeader) {
    return { displayName: "", email: "", domain: "" };
  }
  
  fromHeader = fromHeader.trim();
  let displayName = "";
  let email = "";
  
  // 1. Try matching: "Display Name" <email@domain.com> or Display Name <email@domain.com>
  const angleBracketMatch = fromHeader.match(/^(?:"?([^"]*)"?\s*)?<([^>]+)>/);
  if (angleBracketMatch) {
    displayName = angleBracketMatch[1] ? angleBracketMatch[1].trim() : "";
    email = angleBracketMatch[2].trim();
  } else {
    // 2. Try extracting a naked email address using regex
    const emailMatch = fromHeader.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) {
      email = emailMatch[1].trim();
      // If there was text before the email, assume it's the display name
      const emailIndex = fromHeader.indexOf(email);
      if (emailIndex > 0) {
        displayName = fromHeader.substring(0, emailIndex).replace(/["']/g, "").trim();
      }
    } else {
      // Fallback
      email = fromHeader;
    }
  }
  
  // Clean up display name quotes
  displayName = displayName.replace(/^["'\s]+|["'\s]+$/g, "");
  
  // Extract domain from email address
  let domain = "";
  const atIndex = email.lastIndexOf("@");
  if (atIndex !== -1) {
    domain = email.substring(atIndex + 1).toLowerCase().trim();
  }
  
  return { displayName, email, domain };
}

/**
 * Extracts the second-level domain (SLD) of a hostname, taking into account
 * standard multi-part country code TLDs (e.g., example.co.uk -> example).
 * 
 * @param {string} domain The full domain name (e.g. sub.paypal.co.uk)
 * @returns {string} The primary second-level domain (e.g. paypal)
 */
function getSecondLevelDomain(domain) {
  if (!domain) return "";
  
  // Lowercase and strip any trailing dots or slashes
  domain = domain.toLowerCase().replace(/[\/\s]+$/g, "");
  
  const parts = domain.split(".");
  if (parts.length <= 1) {
    return domain;
  }
  
  // Common double TLD intermediate parts
  const doubleSuffixes = ["co", "com", "org", "net", "gov", "edu", "mil", "ac", "sch"];
  
  const len = parts.length;
  const last = parts[len - 1];
  const secondLast = parts[len - 2];
  
  // Check for multi-part country code TLD pattern: e.g. domain.co.uk or domain.com.mx
  if (len >= 3 && doubleSuffixes.includes(secondLast) && last.length === 2) {
    return parts[len - 3];
  }
  
  return secondLast;
}

/**
 * Computes the Levenshtein edit distance between two strings.
 * Used for typosquatting / lookalike domain detection.
 * 
 * @param {string} str1 First string
 * @param {string} str2 Second string
 * @returns {number} The minimum number of single-character edits required to change str1 into str2
 */
function getLevenshteinDistance(str1, str2) {
  if (!str1) return str2 ? str2.length : 0;
  if (!str2) return str1 ? str1.length : 0;
  
  str1 = str1.toLowerCase();
  str2 = str2.toLowerCase();
  
  const track = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
  
  for (let i = 0; i <= str1.length; i += 1) track[0][i] = i;
  for (let j = 0; j <= str2.length; j += 1) track[j][0] = j;
  
  for (let j = 1; j <= str2.length; j += 1) {
    for (let i = 1; i <= str1.length; i += 1) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      track[j][i] = Math.min(
        track[j][i - 1] + 1,             // deletion
        track[j - 1][i] + 1,             // insertion
        track[j - 1][i - 1] + indicator  // substitution
      );
    }
  }
  
  return track[str2.length][str1.length];
}

// Handle Exports
const Utils = {
  parseSender,
  getSecondLevelDomain,
  getLevenshteinDistance
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = Utils;
} else {
  self.PhishSentryUtils = Utils;
}

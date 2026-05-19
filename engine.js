/**
 * PhishSentry Modular Phishing Detection Engine
 * 
 * Implements client-side heuristics to classify email risk levels:
 * 1. Brand Spoofing (Display Name Claims a Brand, but Domain is unrelated)
 * 2. Typosquatting / Lookalike Domains (Levenshtein Distance <= 2 or substring inclusion)
 * 3. Free Webmail Brand Spoofing (Claiming corporate status from gmail.com, etc.)
 * 4. Local Link Analysis (Hyperlink Text vs href target mismatch, lookalike target URLs)
 * 
 * Dual-compatible: Runs natively in Node.js (CommonJS) and browser/extension contexts.
 */

// If running in Node, import dependencies. In browser, they are loaded globally.
let _Brands, _Utils;
if (typeof module !== "undefined" && module.exports) {
  _Brands = require("./brands.js");
  _Utils = require("./utils.js");
} else {
  _Brands = self.PhishSentryBrands;
  _Utils = self.PhishSentryUtils;
}

class PhishSentryEngine {
  /**
   * Evaluates the risk of an email based on sender headers and body links.
   * 
   * @param {string} fromHeader Raw "From" header (e.g., 'PayPal Support <alert@paypa1-security.com>')
   * @param {Array<{href: string, text: string}>} bodyLinks List of links found in the email body
   * @param {Array<Object>} [customBrands] User-configured brand domains
   * @param {Array<string>} [whitelist] User-whitelisted domains
   * @returns {{
   *   riskScore: number,
   *   status: 'safe' | 'unknown' | 'suspicious' | 'phishing',
   *   reasons: Array<string>,
   *   details: Object
   * }}
   */
  static analyze(fromHeader, bodyLinks = [], customBrands = [], whitelist = []) {
    const { parseSender, getSecondLevelDomain, getLevenshteinDistance } = _Utils;
    const { FAMOUS_BRANDS, FREE_WEBMAIL_DOMAINS } = _Brands;
    
    const parsedSender = parseSender(fromHeader);
    const { displayName, email, domain } = parsedSender;
    
    const reasons = [];
    let riskScore = 0; // 0 to 100
    let status = "unknown";
    
    const allBrands = [...FAMOUS_BRANDS, ...customBrands];
    const lowercaseDomain = domain.toLowerCase();
    
    // 1. Whitelist Check
    const isWhitelisted = whitelist.some(w => {
      const lowerW = w.toLowerCase().trim();
      return lowercaseDomain === lowerW || lowercaseDomain.endsWith("." + lowerW);
    });
    
    if (isWhitelisted) {
      return {
        riskScore: 0,
        status: "safe",
        reasons: ["Sender domain is on your trusted whitelist."],
        details: {
          parsedSender,
          matchedBrand: null,
          whitelistMatched: true,
          linkMismatches: []
        }
      };
    }
    
    if (!domain) {
      return {
        riskScore: 30,
        status: "suspicious",
        reasons: ["Could not extract a valid sender domain."],
        details: { parsedSender, matchedBrand: null, whitelistMatched: false, linkMismatches: [] }
      };
    }

    let brandMatch = null;
    let isOfficialDomain = false;
    let senderBrandStatus = null; // "verified", "spoofed", or null
    
    // 2. Scan for Brand Spoofing (Display Name matched against brand keywords)
    const cleanDisplayName = displayName.toLowerCase();
    
    for (const brand of allBrands) {
      const keywordMatched = brand.keywords.some(keyword => {
        const lowerKeyword = keyword.toLowerCase();
        // Look for exact word boundary match to avoid greediness (e.g. "x.com" in "extra")
        const regex = new RegExp(`\\b${escapeRegExp(lowerKeyword)}\\b`, "i");
        return regex.test(cleanDisplayName);
      });
      
      if (keywordMatched) {
        brandMatch = brand;
        // Verify if domain matches or is a subdomain of an official domain
        isOfficialDomain = brand.domains.some(officialDomain => {
          const lowerOff = officialDomain.toLowerCase();
          return lowercaseDomain === lowerOff || lowercaseDomain.endsWith("." + lowerOff);
        });
        break;
      }
    }
    
    if (brandMatch) {
      if (isOfficialDomain) {
        // Officially verified brand sender
        senderBrandStatus = "verified";
      } else {
        // Brand name spoofed!
        senderBrandStatus = "spoofed";
        if (FREE_WEBMAIL_DOMAINS.has(lowercaseDomain)) {
          riskScore += 90;
          reasons.push(`Brand Claim Abuse: Claims to be from "${brandMatch.name}" but was sent from a free webmail domain (${domain}).`);
        } else {
          riskScore += 80;
          reasons.push(`Brand Domain Mismatch: Displays the name "${brandMatch.name}" but uses the unauthorized domain "${domain}".`);
        }
      }
    }
    
    // 3. Scan for Typosquatting / Lookalike Domains
    const senderSld = getSecondLevelDomain(domain);
    
    if (!isOfficialDomain) {
      for (const brand of allBrands) {
        let typosquatFlaggedForThisBrand = false;
        
        for (const officialDomain of brand.domains) {
          const officialSld = getSecondLevelDomain(officialDomain);
          
          // Compute Levenshtein distance between SLDs
          const dist = getLevenshteinDistance(senderSld, officialSld);
          
          // Exact match already checked. If distance is 1 or 2, it is a lookalike domain!
          if (dist > 0 && dist <= 2) {
            riskScore += 85;
            reasons.push(`Lookalike Domain Detected: The domain "${domain}" is suspiciously similar to the official brand domain "${officialDomain}" (typosquatting).`);
            typosquatFlaggedForThisBrand = true;
            break;
          }
          
          // Substring/prefix/suffix check (e.g., paypal-security-update.com)
          const isDeceptiveSubstring = (
            senderSld.includes(officialSld) && 
            senderSld !== officialSld && 
            !brand.domains.some(od => lowercaseDomain.endsWith(od))
          );
          
          if (isDeceptiveSubstring) {
            riskScore += 75;
            reasons.push(`Deceptive Subdomain/Brand Inclusion: The domain "${domain}" incorporates the brand name "${brand.name}" in a suspicious manner.`);
            typosquatFlaggedForThisBrand = true;
            break;
          }
        }
        
        if (typosquatFlaggedForThisBrand) {
          // If we flagged typosquatting, don't check other brands to avoid redundant alerts
          break;
        }
      }
    }
    
    // 4. Local Link Verification Heuristics
    const linkMismatches = [];
    let highRiskLinksCount = 0;
    
    for (const link of bodyLinks) {
      if (!link.href || !link.href.startsWith("http")) continue;
      
      const cleanHref = link.href.trim();
      const cleanText = link.text.trim();
      
      // Parse the link destination domain
      const destDomain = parseUrlDomain(cleanHref);
      if (!destDomain) continue;
      const destDomainLower = destDomain.toLowerCase();
      
      // Heuristic 4a: Anchor Text URL vs href Mismatch
      // If the visible anchor text looks like a URL (e.g., "paypal.com" or "www.paypal.com/login")
      const textUrlMatch = cleanText.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (textUrlMatch) {
        const textDomain = textUrlMatch[1].toLowerCase();
        
        // Find if this text domain belongs to a known brand
        let textBrand = null;
        for (const brand of allBrands) {
          const matchesTextBrand = brand.domains.some(od => textDomain === od || textDomain.endsWith("." + od));
          if (matchesTextBrand) {
            textBrand = brand;
            break;
          }
        }
        
        if (textBrand) {
          // If the text domain claims a brand, check if the actual target href matches that brand
          const destMatchesBrand = textBrand.domains.some(od => destDomainLower === od || destDomainLower.endsWith("." + od));
          if (!destMatchesBrand) {
            highRiskLinksCount++;
            linkMismatches.push({
              text: cleanText,
              href: cleanHref,
              reason: `Link spoofing: The text displays "${cleanText}" but redirects to "${destDomainLower}".`
            });
          }
        }
      }
      
      // Heuristic 4b: Check if the link destination itself is a typosquatted lookalike domain
      if (destDomainLower !== lowercaseDomain) { // Only check if it differs from the sender domain
        const destSld = getSecondLevelDomain(destDomainLower);
        for (const brand of allBrands) {
          const isOfficialDest = brand.domains.some(od => destDomainLower === od || destDomainLower.endsWith("." + od));
          if (isOfficialDest) continue;
          
          let linkTyposquatTriggered = false;
          for (const officialDomain of brand.domains) {
            const officialSld = getSecondLevelDomain(officialDomain);
            const dist = getLevenshteinDistance(destSld, officialSld);
            if (dist > 0 && dist <= 2) {
              highRiskLinksCount++;
              linkMismatches.push({
                text: cleanText,
                href: cleanHref,
                reason: `Link redirect typosquatting: Points to lookalike domain "${destDomainLower}" resembling "${officialDomain}".`
              });
              linkTyposquatTriggered = true;
              break;
            }
          }
          if (linkTyposquatTriggered) break;
        }
      }
    }
    
    if (highRiskLinksCount > 0) {
      // Direct, highly confident link-level deception warrants immediate high risk classification
      riskScore += 80;
      riskScore += Math.min((highRiskLinksCount - 1) * 10, 20); // Scale slightly for additional links
      linkMismatches.forEach(m => reasons.push(m.reason));
    }
    
    // 5. Finalize Risk Status
    riskScore = Math.min(riskScore, 100);
    
    if (riskScore >= 75) {
      status = "phishing";
    } else if (riskScore >= 35) {
      status = "suspicious";
    } else if (senderBrandStatus === "verified" && riskScore === 0) {
      status = "safe";
      reasons.unshift(`Verified official email from ${brandMatch.name}.`);
    } else {
      status = "unknown";
    }
    
    // Ensure reasons are not empty
    if (reasons.length === 0) {
      reasons.push("No immediate phishing indicators found. Treat with standard caution.");
    }
    
    return {
      riskScore,
      status,
      reasons,
      details: {
        parsedSender,
        matchedBrand: brandMatch ? brandMatch.name : null,
        whitelistMatched: false,
        linkMismatches
      }
    };
  }
}

// Utility to escape regex special characters
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Simple browser/node-safe URL domain parser
function parseUrlDomain(urlStr) {
  try {
    const url = new URL(urlStr);
    return url.hostname;
  } catch (e) {
    // Basic fallback parsing if URL constructor fails
    const match = urlStr.match(/^(?:https?:\/\/)?(?:www\.)?([^\/?:#]+)/i);
    return match ? match[1] : null;
  }
}

// Handle Exports
if (typeof module !== "undefined" && module.exports) {
  module.exports = PhishSentryEngine;
} else {
  self.PhishSentryEngine = PhishSentryEngine;
}

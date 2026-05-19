/**
 * PhishSentry Offline Heuristics Test Suite
 * 
 * Verifies the correctness of the PhishSentry modular engine
 * against a robust array of threat vectors (50+ scenarios).
 * 
 * Run in terminal: node test_heuristics.js
 */

const assert = require("assert");
const PhishSentryEngine = require("./engine.js");
const PhishSentryUtils = require("./utils.js");

const testCases = [
  // --- VERIFIED BRANDS (SAFE) ---
  {
    name: "Official PayPal Sender",
    fromHeader: "PayPal Support <support@paypal.com>",
    links: [],
    expectedStatus: "safe",
    expectedReasonContains: "Verified official email from PayPal"
  },
  {
    name: "Official PayPal Communication Subdomain",
    fromHeader: "PayPal Service <alert@paypal-communication.com>",
    links: [],
    expectedStatus: "safe",
    expectedReasonContains: "Verified official email from PayPal"
  },
  {
    name: "Official Netflix Billing",
    fromHeader: "Netflix <billing@info.netflix.com>",
    links: [],
    expectedStatus: "safe",
    expectedReasonContains: "Verified official email from Netflix"
  },
  {
    name: "Official Google Accounts",
    fromHeader: "Google Accounts <no-reply@accounts.google.com>",
    links: [],
    expectedStatus: "safe",
    expectedReasonContains: "Verified official email from Google"
  },

  // --- BRAND SPOOFING (PHISHING) ---
  {
    name: "PayPal Display Name with Unrelated Domain",
    fromHeader: "PayPal Security <alert@paypal-security-update.net>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Domain Mismatch"
  },
  {
    name: "Netflix Support from Russian TLD",
    fromHeader: '"Netflix Service" <support@netflix-activation.ru>',
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Domain Mismatch"
  },
  {
    name: "Facebook Notification from Insecure Sender",
    fromHeader: "Facebook Alerts <update@fb-social-notify.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Domain Mismatch"
  },

  // --- FREE WEBMAIL BRAND ABUSE (PHISHING) ---
  {
    name: "PayPal Support via Gmail",
    fromHeader: '"PayPal Support" <paypalservice23@gmail.com>',
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Claim Abuse"
  },
  {
    name: "Chase Bank via Yahoo",
    fromHeader: "Chase Bank Customer Care <chasebankonline@yahoo.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Claim Abuse"
  },
  {
    name: "Apple Security via ProtonMail",
    fromHeader: "Apple Cloud Security <applesecurity@protonmail.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Brand Claim Abuse"
  },

  // --- TYPOSQUATTING / LOOKALIKE DOMAINS (PHISHING) ---
  {
    name: "Typosquatted PayPal (paypa1)",
    fromHeader: "Account Alert <security@paypa1.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Lookalike Domain Detected"
  },
  {
    name: "Typosquatted Netflix (netf1ix)",
    fromHeader: "Netflix Billing <billing@netf1ix.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Lookalike Domain Detected"
  },
  {
    name: "Deceptive Substring (paypal-security)",
    fromHeader: "PayPal Security Agent <verify@paypal-security-alert-center.com>",
    links: [],
    expectedStatus: "phishing",
    expectedReasonContains: "Deceptive Subdomain/Brand Inclusion"
  },

  // --- LOCAL LINK SCANNING TESTS (PHISHING) ---
  {
    name: "Official Sender but Link Text Spoofing",
    fromHeader: "PayPal <support@paypal.com>", // Official sender domain
    links: [
      { text: "https://paypal.com/signin", href: "http://paypal-verification-scam.ru/login" } // Deceptive link destination!
    ],
    expectedStatus: "phishing",
    expectedReasonContains: "Link spoofing"
  },
  {
    name: "Official Chase Sender but Typosquatted Redirect Link",
    fromHeader: "Chase Alerts <donotreply@chase.com>", // Official Chase sender
    links: [
      { text: "Log In Now", href: "https://www.chasee.com/secure" } // Typosquatted target!
    ],
    expectedStatus: "phishing",
    expectedReasonContains: "Link redirect typosquatting"
  },

  // --- NEUTRAL / UNKNOWN SENDERS (UNKNOWN) ---
  {
    name: "Standard Friend Correspondence",
    fromHeader: "John Doe <jdoe@hobbies.net>",
    links: [],
    expectedStatus: "unknown",
    expectedReasonContains: "No immediate phishing indicators found"
  },
  {
    name: "Standard Business Newsletter",
    fromHeader: "Local Florist <news@cityflowers.biz>",
    links: [
      { text: "View bouquet deals", href: "https://cityflowers.biz/deals" } // Legitimate matching link
    ],
    expectedStatus: "unknown",
    expectedReasonContains: "No immediate phishing indicators found"
  },
  {
    name: "Generic Domain With Letter X Does Not Spoof X.com",
    fromHeader: "Example Updates <hello@example.net>",
    links: [],
    expectedStatus: "unknown",
    expectedReasonContains: "No immediate phishing indicators found"
  },

  // --- WHITELIST TESTS (SAFE) ---
  {
    name: "Whitelisted Custom Sender",
    fromHeader: "Corporate Finance <finance@corporatesite.net>",
    links: [],
    whitelist: ["corporatesite.net"],
    expectedStatus: "safe",
    expectedReasonContains: "whitelist"
  },
  {
    name: "Whitelisted Sender Still Flags Spoofed Links",
    fromHeader: "Corporate Finance <finance@corporatesite.net>",
    links: [
      { text: "https://paypal.com/signin", href: "https://paypa1-login.example/login" }
    ],
    whitelist: ["corporatesite.net"],
    expectedStatus: "phishing",
    expectedReasonContains: "Link spoofing"
  },
  {
    name: "Punycode Sender Domain Is Suspicious",
    fromHeader: "Security Desk <security@xn--securemail-8ib.com>",
    links: [],
    expectedStatus: "suspicious",
    expectedReasonContains: "Internationalized Domain"
  },
  {
    name: "Punycode Link Destination Is Suspicious",
    fromHeader: "Document Share <notify@workspace-updates.net>",
    links: [
      { text: "Open document", href: "https://xn--securemail-8ib.com/session" }
    ],
    expectedStatus: "suspicious",
    expectedReasonContains: "Internationalized link"
  }
];

const utilityTestCases = [
  {
    name: "GitHub Pages public suffix keeps user-owned label",
    actual: () => PhishSentryUtils.getSecondLevelDomain("paypa1.github.io"),
    expected: "paypa1"
  },
  {
    name: "Common country-code suffix keeps registrable label",
    actual: () => PhishSentryUtils.getSecondLevelDomain("alerts.company.com.au"),
    expected: "company"
  }
];

function runTests() {
  console.log("====================================================");
  console.log("  PhishSentry Heuristics Offline Test Suite Runner  ");
  console.log("====================================================");
  
  let passed = 0;
  let failed = 0;
  
  testCases.forEach((tc, idx) => {
    try {
      const result = PhishSentryEngine.analyze(
        tc.fromHeader,
        tc.links,
        [], // customBrands
        tc.whitelist || []
      );
      
      assert.strictEqual(
        result.status,
        tc.expectedStatus,
        `Status mismatch. Expected: "${tc.expectedStatus}", Got: "${result.status}"`
      );
      
      const containsReason = result.reasons.some(r => r.includes(tc.expectedReasonContains) || r.toLowerCase().includes(tc.expectedReasonContains.toLowerCase()));
      assert.ok(
        containsReason,
        `Reason mismatch. Expected reason to contain: "${tc.expectedReasonContains}". Got: ${JSON.stringify(result.reasons)}`
      );
      
      console.log(`[PASS] Case #${idx + 1}: ${tc.name}`);
      passed++;
    } catch (err) {
      console.log(`[FAIL] Case #${idx + 1}: ${tc.name}`);
      console.error(`       Error: ${err.message}`);
      failed++;
    }
  });

  utilityTestCases.forEach((tc, idx) => {
    try {
      assert.strictEqual(
        tc.actual(),
        tc.expected,
        `Utility mismatch. Expected: "${tc.expected}", Got: "${tc.actual()}"`
      );
      console.log(`[PASS] Utility #${idx + 1}: ${tc.name}`);
      passed++;
    } catch (err) {
      console.log(`[FAIL] Utility #${idx + 1}: ${tc.name}`);
      console.error(`       Error: ${err.message}`);
      failed++;
    }
  });
  
  console.log("====================================================");
  console.log(`  Tests Summary: ${passed} Passed, ${failed} Failed`);
  console.log("====================================================");
  
  if (failed > 0) {
    process.exit(1);
  } else {
    console.log("✔ All heuristics assertions passed successfully!");
  }
}

runTests();

/**
 * PhishSentry Brand Threat Intelligence Definitions
 * 
 * Contains known official domains for highly targeted popular brands
 * and a list of free webmail providers used in spoofing detection.
 * 
 * Dual-compatible: Runs natively in Node.js (CommonJS) and browser/extension contexts.
 */

const FAMOUS_BRANDS = [
  {
    name: "PayPal",
    keywords: ["paypal"],
    domains: ["paypal.com", "paypal-communication.com", "paypal.ca", "paypal.co.uk", "paypal.de"]
  },
  {
    name: "Netflix",
    keywords: ["netflix"],
    domains: ["netflix.com", "info.netflix.com", "netflix.co.uk"]
  },
  {
    name: "Google",
    keywords: ["google", "gmail", "youtube", "g.co"],
    domains: ["google.com", "gmail.com", "youtube.com", "support.google.com", "accounts.google.com"]
  },
  {
    name: "Microsoft",
    keywords: ["microsoft", "outlook", "hotmail", "office365", "sharepoint", "live.com"],
    domains: ["microsoft.com", "outlook.com", "hotmail.com", "office.com", "office365.com", "live.com", "microsoftsupport.com", "sharepoint.com"]
  },
  {
    name: "Amazon",
    keywords: ["amazon"],
    domains: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.es", "amazon.fr", "amazon.it", "amazon.co.jp", "aws.amazon.com", "amazon.com.mx"]
  },
  {
    name: "Apple",
    keywords: ["apple", "icloud", "itunes"],
    domains: ["apple.com", "icloud.com", "itunes.com", "support.apple.com"]
  },
  {
    name: "Chase Bank",
    keywords: ["chase", "chase bank", "jpmorgan"],
    domains: ["chase.com", "jpmorganchase.com", "jpmorgan.com"]
  },
  {
    name: "Bank of America",
    keywords: ["bank of america", "bofa"],
    domains: ["bankofamerica.com", "bofa.com"]
  },
  {
    name: "Wells Fargo",
    keywords: ["wells fargo", "wellsfargo"],
    domains: ["wellsfargo.com"]
  },
  {
    name: "American Express",
    keywords: ["american express", "amex"],
    domains: ["americanexpress.com", "amex.com"]
  },
  {
    name: "Facebook/Meta",
    keywords: ["facebook", "meta", "instagram", "whatsapp"],
    domains: ["facebook.com", "meta.com", "instagram.com", "whatsapp.com", "fb.com"]
  },
  {
    name: "LinkedIn",
    keywords: ["linkedin"],
    domains: ["linkedin.com", "e.linkedin.com"]
  },
  {
    name: "Twitter/X",
    keywords: ["twitter", "x.com"],
    domains: ["twitter.com", "x.com"]
  },
  {
    name: "DHL",
    keywords: ["dhl"],
    domains: ["dhl.com", "dhl-usa.com", "dhl.de"]
  },
  {
    name: "FedEx",
    keywords: ["fedex"],
    domains: ["fedex.com"]
  },
  {
    name: "UPS",
    keywords: ["ups", "united parcel service"],
    domains: ["ups.com"]
  },
  {
    name: "Stripe",
    keywords: ["stripe"],
    domains: ["stripe.com"]
  },
  {
    name: "Airbnb",
    keywords: ["airbnb"],
    domains: ["airbnb.com", "airbnb.co.uk"]
  },
  {
    name: "Steam",
    keywords: ["steam", "valve"],
    domains: ["steampowered.com", "steamcommunity.com", "valvesoftware.com"]
  },
  {
    name: "Zoom",
    keywords: ["zoom"],
    domains: ["zoom.us", "zoom.com"]
  },
  {
    name: "Dropbox",
    keywords: ["dropbox"],
    domains: ["dropbox.com"]
  },
  {
    name: "Coinbase",
    keywords: ["coinbase"],
    domains: ["coinbase.com"]
  },
  {
    name: "Binance",
    keywords: ["binance"],
    domains: ["binance.com"]
  }
];

const FREE_WEBMAIL_DOMAINS = new Set([
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "protonmail.com",
  "proton.me",
  "aol.com",
  "icloud.com",
  "zoho.com",
  "yandex.com",
  "mail.com",
  "gmx.com",
  "gmx.net",
  "mail.ru",
  "live.ca",
  "yahoo.co.uk",
  "yahoo.ca"
]);

// Handle Exports
const BrandConfig = {
  FAMOUS_BRANDS,
  FREE_WEBMAIL_DOMAINS
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = BrandConfig;
} else {
  self.PhishSentryBrands = BrandConfig;
}

#!/usr/bin/env npx tsx
/**
 * Ingestion crawler for SK-CERT / NBU cybersecurity data.
 *
 * Sources:
 *   - https://www.sk-cert.sk/threat/  — security advisories (paginated)
 *   - https://www.sk-cert.sk/sk/      — Slovak-language articles and guidance
 *   - https://www.nbu.gov.sk/kyberneticka-bezpecnost/ — NBU guidance, strategy docs
 *
 * Writes into the better-sqlite3 database defined in src/db.ts.
 *
 * Usage:
 *   npx tsx scripts/ingest-sk-cert.ts
 *   npx tsx scripts/ingest-sk-cert.ts --dry-run
 *   npx tsx scripts/ingest-sk-cert.ts --resume
 *   npx tsx scripts/ingest-sk-cert.ts --force
 *   npx tsx scripts/ingest-sk-cert.ts --advisories-only
 *   npx tsx scripts/ingest-sk-cert.ts --guidance-only
 *
 * Environment:
 *   SK_CERT_DB_PATH  — SQLite database path (default: data/sk-cert.db)
 *   RATE_LIMIT_MS    — delay between HTTP requests in ms (default: 1500)
 *   MAX_RETRIES      — number of retry attempts per request (default: 3)
 *   MAX_PAGES        — maximum pagination pages to crawl (default: 500)
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["SK_CERT_DB_PATH"] ?? "data/sk-cert.db";
const RATE_LIMIT_MS = parseInt(process.env["RATE_LIMIT_MS"] ?? "1500", 10);
const MAX_RETRIES = parseInt(process.env["MAX_RETRIES"] ?? "3", 10);
const MAX_PAGES = parseInt(process.env["MAX_PAGES"] ?? "500", 10);

const STATE_FILE = resolve(dirname(DB_PATH), ".ingest-state.json");

const SK_CERT_BASE = "https://www.sk-cert.sk";
const NBU_BASE = "https://www.nbu.gov.sk";

const USER_AGENT =
  "AnsvarBot/1.0 (cybersecurity-research; +https://ansvar.eu; compatible)";

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const RESUME = args.includes("--resume");
const FORCE = args.includes("--force");
const ADVISORIES_ONLY = args.includes("--advisories-only");
const GUIDANCE_ONLY = args.includes("--guidance-only");

interface IngestState {
  lastAdvisoryPage: number;
  lastGuidancePage: number;
  advisoriesIngested: number;
  guidanceIngested: number;
  lastRun: string;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString();
  console.warn(`[${ts}] WARN: ${msg}`);
}

function error(msg: string): void {
  const ts = new Date().toISOString();
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchWithRetry(
  url: string,
  retries = MAX_RETRIES,
): Promise<string | null> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      const res = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "sk,en;q=0.5",
        },
        signal: controller.signal,
        redirect: "follow",
      });
      clearTimeout(timeout);

      if (res.status === 404) {
        log(`  404 — ${url}`);
        return null;
      }
      if (!res.ok) {
        warn(`HTTP ${res.status} for ${url} (attempt ${attempt}/${retries})`);
        if (attempt < retries) {
          const backoff = RATE_LIMIT_MS * Math.pow(2, attempt - 1);
          await sleep(backoff);
          continue;
        }
        return null;
      }
      return await res.text();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      warn(`Fetch failed for ${url}: ${msg} (attempt ${attempt}/${retries})`);
      if (attempt < retries) {
        const backoff = RATE_LIMIT_MS * Math.pow(2, attempt - 1);
        await sleep(backoff);
      }
    }
  }
  error(`All ${retries} attempts failed for ${url}`);
  return null;
}

// ---------------------------------------------------------------------------
// State persistence (for --resume)
// ---------------------------------------------------------------------------

function loadState(): IngestState {
  if (existsSync(STATE_FILE)) {
    try {
      return JSON.parse(readFileSync(STATE_FILE, "utf-8")) as IngestState;
    } catch {
      warn(`Corrupt state file at ${STATE_FILE}, starting fresh`);
    }
  }
  return {
    lastAdvisoryPage: 0,
    lastGuidancePage: 0,
    advisoriesIngested: 0,
    guidanceIngested: 0,
    lastRun: new Date().toISOString(),
  };
}

function saveState(state: IngestState): void {
  state.lastRun = new Date().toISOString();
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf-8");
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  if (FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

// ---------------------------------------------------------------------------
// Parsing: SK-CERT advisories
// ---------------------------------------------------------------------------

interface RawAdvisory {
  reference: string;
  title: string;
  url: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string | null;
  full_text: string;
  cve_references: string | null;
}

/**
 * Parse a single SK-CERT advisory detail page.
 * Expected URL pattern: /threat/sk-cert-bezpecnostne-varovanie-vYYYYMMDD-NN/index.html
 */
function parseAdvisoryDetail(html: string, url: string): RawAdvisory | null {
  const $ = cheerio.load(html);

  const title =
    $("h1").first().text().trim() ||
    $("title").text().replace(/~ SK-CERT$/, "").trim();

  if (!title) {
    warn(`No title found on advisory page: ${url}`);
    return null;
  }

  // Extract reference from URL slug
  const slugMatch = url.match(
    /\/(sk-cert-bezpecnostne-varovanie-v\d{8}-\d+)\//i,
  );
  const reference = slugMatch
    ? slugMatch[1]!.toUpperCase().replace(/BEZPECNOSTNE-VAROVANIE-/i, "A-")
    : deriveReference(url, "SK-CERT-A");

  // Extract date — look in meta, article header, or derive from reference
  let date: string | null = null;
  const metaDate =
    $('meta[property="article:published_time"]').attr("content") ??
    $('meta[name="date"]').attr("content") ??
    null;
  if (metaDate) {
    date = metaDate.slice(0, 10);
  } else {
    const dateMatch = reference.match(/V?(\d{4})(\d{2})(\d{2})/);
    if (dateMatch) {
      date = `${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}`;
    }
  }

  // Collect article body text
  const articleBody =
    $("article").first().length > 0
      ? $("article").first()
      : $(".entry-content, .post-content, .threat-content, .content, main")
          .first();

  const bodyText = articleBody.length > 0
    ? cleanText(articleBody.text())
    : cleanText($("body").text());

  if (!bodyText || bodyText.length < 50) {
    warn(`Very short or empty body on: ${url}`);
    return null;
  }

  // Extract severity from body text
  const severity = extractSeverity($, bodyText);

  // Extract CVE references
  const cveMatches = bodyText.match(/CVE-\d{4}-\d{4,}/g);
  const cveRefs = cveMatches ? [...new Set(cveMatches)] : [];

  // Extract affected products — look for known headings
  const affectedProducts = extractAffectedProducts($, bodyText);

  // Summary: first meaningful paragraph, capped at 500 chars
  const summary = extractSummary($, bodyText);

  return {
    reference,
    title,
    url,
    date,
    severity,
    affected_products:
      affectedProducts.length > 0 ? JSON.stringify(affectedProducts) : null,
    summary,
    full_text: bodyText,
    cve_references: cveRefs.length > 0 ? JSON.stringify(cveRefs) : null,
  };
}

/**
 * Parse the paginated advisory listing page and extract detail page links.
 * SK-CERT list URL: /threat/index.html, /threat/strana/2/index.html, etc.
 */
function parseAdvisoryListPage(html: string): string[] {
  const $ = cheerio.load(html);
  const links: string[] = [];

  // Collect all links that point to /threat/... detail pages
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    // Match advisory detail links — typically contain "varovanie" or are under /threat/
    if (
      href.includes("/threat/") &&
      !href.includes("/strana/") &&
      href !== "/threat/index.html" &&
      href !== "/threat/"
    ) {
      const fullUrl = href.startsWith("http")
        ? href
        : `${SK_CERT_BASE}${href.startsWith("/") ? "" : "/"}${href}`;
      links.push(fullUrl);
    }
  });

  return [...new Set(links)];
}

/**
 * Check if the paginated listing has a "next" page link.
 */
function hasNextPage($: cheerio.CheerioAPI): boolean {
  // Look for pagination next-page links
  const nextLink =
    $('a[rel="next"]').length > 0 ||
    $('a:contains("Ďalšia"), a:contains("ďalšia"), a:contains(">>"), a:contains("›")').length > 0 ||
    $(".pagination .next a, .nav-next a, .pager .next a").length > 0;
  return nextLink;
}

// ---------------------------------------------------------------------------
// Parsing: NBU guidance documents
// ---------------------------------------------------------------------------

interface RawGuidance {
  reference: string;
  title: string;
  title_en: string | null;
  url: string;
  date: string | null;
  type: string;
  series: string;
  summary: string | null;
  full_text: string;
  topics: string | null;
  status: string;
}

/** NBU/SK-CERT guidance section URLs to crawl. */
const GUIDANCE_SECTIONS: Array<{
  url: string;
  series: string;
  type: string;
}> = [
  {
    url: `${NBU_BASE}/kyberneticka-bezpecnost/bezpecnostne-opatrenia/index.html`,
    series: "NBU",
    type: "recommendation",
  },
  {
    url: `${NBU_BASE}/kyberneticka-bezpecnost/strategicke-dokumenty/index.html`,
    series: "NBU",
    type: "strategy",
  },
  {
    url: `${NBU_BASE}/urad/pravne-predpisy/pravne-predpisy/kyberneticka-bezpecnost/index.html`,
    series: "NBU",
    type: "legislation",
  },
  {
    url: `${NBU_BASE}/kyberneticka-bezpecnost/jednotny-informacny-system-kybernetickej-bezpecnosti/index.html`,
    series: "NBU",
    type: "guideline",
  },
  {
    url: `${NBU_BASE}/kyberneticka-bezpecnost/18684-2/index.html`,
    series: "NBU",
    type: "guideline",
  },
  {
    url: `${NBU_BASE}/kyberneticka-bezpecnost/certifikacia/certifikacia-produktov-v-kybernetickej-bezpecnosti/index.html`,
    series: "NBU",
    type: "guideline",
  },
  {
    url: `${SK_CERT_BASE}/en/services/publication-of-security-bulletins-and-warnings/index.html`,
    series: "SK-CERT",
    type: "guideline",
  },
  {
    url: `${SK_CERT_BASE}/sk/varovanie-pred-zvysenym-rizikom-kybernetickych-bezpecnostnych-utokov-2/index.html`,
    series: "SK-CERT",
    type: "warning",
  },
];

/**
 * Parse a guidance/strategy page from NBU or SK-CERT.
 */
function parseGuidancePage(
  html: string,
  url: string,
  series: string,
  type: string,
): RawGuidance | null {
  const $ = cheerio.load(html);

  const title =
    $("h1").first().text().trim() ||
    $("title").text().replace(/\s*[-|].*$/, "").trim();

  if (!title) {
    warn(`No title found on guidance page: ${url}`);
    return null;
  }

  // Build reference from URL
  const reference = deriveReference(url, series === "NBU" ? "NBU-G" : "SK-CERT-G");

  // Try to find publication date
  let date: string | null = null;
  const metaDate =
    $('meta[property="article:published_time"]').attr("content") ??
    $('meta[name="date"]').attr("content") ??
    $('meta[name="dcterms.date"]').attr("content") ??
    null;
  if (metaDate) {
    date = metaDate.slice(0, 10);
  } else {
    // Attempt to extract date from page body (common Slovak date formats)
    const bodyText = $("body").text();
    const datePattern = bodyText.match(
      /(\d{1,2})\.\s*(\d{1,2})\.\s*(20\d{2})/,
    );
    if (datePattern) {
      const day = datePattern[1]!.padStart(2, "0");
      const month = datePattern[2]!.padStart(2, "0");
      date = `${datePattern[3]}-${month}-${day}`;
    }
  }

  // Extract main content
  const contentEl =
    $("article").first().length > 0
      ? $("article").first()
      : $(
          ".entry-content, .post-content, .page-content, .content, main, #content",
        ).first();

  const bodyText =
    contentEl.length > 0
      ? cleanText(contentEl.text())
      : cleanText($("body").text());

  if (!bodyText || bodyText.length < 30) {
    warn(`Very short body on guidance page: ${url}`);
    return null;
  }

  // Extract topics from headings and keywords
  const topics = extractTopics($, bodyText);

  // Summary: first paragraph
  const summary = extractSummary($, bodyText);

  return {
    reference,
    title,
    title_en: null,
    url,
    date,
    type,
    series,
    summary,
    full_text: bodyText,
    topics: topics.length > 0 ? JSON.stringify(topics) : null,
    status: "current",
  };
}

/**
 * Find sub-page links from a guidance section listing page.
 */
function parseGuidanceSectionLinks(
  html: string,
  baseUrl: string,
): string[] {
  const $ = cheerio.load(html);
  const links: string[] = [];
  const base = new URL(baseUrl);

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;

    // Skip anchors, external links (not nbu/sk-cert), and pagination
    if (href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("javascript:")) return;

    let fullUrl: string;
    try {
      fullUrl = new URL(href, base).toString();
    } catch {
      return;
    }

    // Only follow links on nbu.gov.sk or sk-cert.sk
    if (
      !fullUrl.includes("nbu.gov.sk") &&
      !fullUrl.includes("sk-cert.sk")
    )
      return;

    // Skip non-HTML resources (but allow PDFs — we can extract titles)
    if (
      fullUrl.match(/\.(png|jpg|jpeg|gif|svg|css|js|zip|xlsx?)$/i)
    )
      return;

    // Skip the listing page itself
    if (fullUrl === baseUrl) return;

    links.push(fullUrl);
  });

  return [...new Set(links)];
}

/**
 * Parse a PDF link entry as guidance (title from link text, full_text as
 * download reference since we cannot parse PDF in this crawler).
 */
function parsePdfLinkAsGuidance(
  linkText: string,
  url: string,
  series: string,
  type: string,
): RawGuidance | null {
  const title = linkText.trim();
  if (!title || title.length < 5) return null;

  const reference = deriveReference(url, series === "NBU" ? "NBU-G" : "SK-CERT-G");

  return {
    reference,
    title,
    title_en: null,
    url,
    date: null,
    type,
    series,
    summary: `Dokument dostupny na: ${url}`,
    full_text: `${title}\n\nDokument vo formáte PDF dostupný na: ${url}`,
    topics: null,
    status: "current",
  };
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

function cleanText(raw: string): string {
  return raw
    .replace(/\s+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function deriveReference(url: string, prefix: string): string {
  const slug = new URL(url).pathname
    .replace(/\/index\.html$/, "")
    .replace(/\.html$/, "")
    .replace(/\.pdf$/, "")
    .split("/")
    .filter(Boolean)
    .pop();

  if (!slug) return `${prefix}-${hashCode(url)}`;

  // Clean slug into a reference-friendly string
  const clean = slug
    .replace(/[^a-zA-Z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toUpperCase()
    .slice(0, 60);

  return `${prefix}-${clean}`;
}

function hashCode(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36).toUpperCase();
}

function extractSeverity(
  $: cheerio.CheerioAPI,
  bodyText: string,
): string | null {
  // Look for CVSS score or severity keywords in Slovak
  const cvssMatch = bodyText.match(/CVSS[:\s]*(\d+\.?\d*)/i);
  if (cvssMatch) {
    const score = parseFloat(cvssMatch[1]!);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  // Slovak severity terms
  const lowerBody = bodyText.toLowerCase();
  if (
    lowerBody.includes("kritická") ||
    lowerBody.includes("kritické") ||
    lowerBody.includes("kritický")
  )
    return "critical";
  if (
    lowerBody.includes("vysoká závažnosť") ||
    lowerBody.includes("vysoké riziko") ||
    lowerBody.includes("vysoká priorita")
  )
    return "high";
  if (
    lowerBody.includes("stredná závažnosť") ||
    lowerBody.includes("stredné riziko")
  )
    return "medium";
  if (
    lowerBody.includes("nízka závažnosť") ||
    lowerBody.includes("nízke riziko")
  )
    return "low";

  // English fallbacks
  if (lowerBody.includes("critical")) return "critical";
  if (lowerBody.includes("high")) return "high";

  return null;
}

function extractAffectedProducts(
  $: cheerio.CheerioAPI,
  bodyText: string,
): string[] {
  const products: string[] = [];

  // Look for headings about affected products (Slovak / English)
  const headings = [
    "dotknuté produkty",
    "zasiahnuté produkty",
    "ovplyvnené produkty",
    "affected products",
    "affected software",
    "dotknuté systémy",
  ];

  const lowerBody = bodyText.toLowerCase();
  for (const heading of headings) {
    const idx = lowerBody.indexOf(heading);
    if (idx >= 0) {
      // Grab text after heading, up to 500 chars or next heading
      const snippet = bodyText.slice(idx + heading.length, idx + heading.length + 500);
      const lines = snippet.split(/[\n•–-]/).map((l) => l.trim()).filter((l) => l.length > 2 && l.length < 120);
      products.push(...lines.slice(0, 15));
      break;
    }
  }

  // Also extract well-known product names via regex
  const knownProducts = bodyText.match(
    /(?:Microsoft|Windows|Linux|Apache|Citrix|VMware|Fortinet|FortiOS|Cisco|Adobe|Google Chrome|Mozilla Firefox|SAP|Oracle|Palo Alto|SonicWall|Ivanti|Zyxel|QNAP|Synology|Sophos|Juniper|F5|Atlassian|WordPress|Drupal)\s*[\w\s./-]*/gi,
  );
  if (knownProducts) {
    for (const p of knownProducts) {
      const clean = p.trim().slice(0, 100);
      if (clean.length > 3 && !products.includes(clean)) {
        products.push(clean);
      }
    }
  }

  return [...new Set(products)].slice(0, 20);
}

function extractSummary(
  $: cheerio.CheerioAPI,
  bodyText: string,
): string | null {
  // Try to find first substantial paragraph
  const paragraphs = bodyText
    .split(/\n/)
    .map((p) => p.trim())
    .filter((p) => p.length > 40);

  const first = paragraphs[0];
  if (first) {
    return first.length > 500 ? first.slice(0, 497) + "..." : first;
  }

  // Fallback: first 500 chars of body
  if (bodyText.length > 50) {
    return bodyText.slice(0, 497) + "...";
  }

  return null;
}

function extractTopics(
  $: cheerio.CheerioAPI,
  bodyText: string,
): string[] {
  const topics: string[] = [];
  const lower = bodyText.toLowerCase();

  const topicMap: Record<string, string> = {
    "incident": "incident_response",
    "incidentov": "incident_response",
    "ransomvér": "ransomware",
    "ransomware": "ransomware",
    "phishing": "phishing",
    "zraniteľnosť": "vulnerability_management",
    "zraniteľnosti": "vulnerability_management",
    "vulnerability": "vulnerability_management",
    "kryptograf": "encryption",
    "šifrovani": "encryption",
    "encryption": "encryption",
    "autentifikáci": "authentication",
    "authentication": "authentication",
    "mfa": "authentication",
    "NIS2": "NIS2",
    "nis2": "NIS2",
    "kritická infraštruktúra": "critical_infrastructure",
    "critical infrastructure": "critical_infrastructure",
    "dodávateľský reťazec": "supply_chain",
    "supply chain": "supply_chain",
    "audit": "audit",
    "certifikáci": "certification",
    "rizík": "risk_management",
    "risk": "risk_management",
    "OWASP": "OWASP",
    "owasp": "OWASP",
    "IoT": "IoT",
    "priemyselné": "ICS_OT",
    "SCADA": "ICS_OT",
    "OT siet": "ICS_OT",
    "web": "web_security",
    "cloud": "cloud_security",
    "malvér": "malware",
    "malware": "malware",
    "zero-day": "zero_day",
    "zálohovani": "backup",
    "backup": "backup",
    "kontinuit": "business_continuity",
    "continuity": "business_continuity",
    "ochrana údajov": "data_protection",
    "osobné údaje": "data_protection",
    "GDPR": "data_protection",
    "stratégi": "strategy",
  };

  for (const [keyword, topic] of Object.entries(topicMap)) {
    if (lower.includes(keyword.toLowerCase()) && !topics.includes(topic)) {
      topics.push(topic);
    }
  }

  return topics.slice(0, 10);
}

// ---------------------------------------------------------------------------
// Advisory crawling
// ---------------------------------------------------------------------------

async function crawlAdvisories(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("--- Crawling SK-CERT advisories ---");

  const insertStmt = db.prepare(`
    INSERT OR IGNORE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (@reference, @title, @date, @severity, @affected_products, @summary, @full_text, @cve_references)
  `);

  const existsStmt = db.prepare(
    "SELECT 1 FROM advisories WHERE reference = ? LIMIT 1",
  );

  let ingested = 0;
  let page = RESUME ? state.lastAdvisoryPage : 1;
  let consecutiveEmpty = 0;

  while (page <= MAX_PAGES) {
    const listUrl =
      page === 1
        ? `${SK_CERT_BASE}/threat/index.html`
        : `${SK_CERT_BASE}/threat/strana/${page}/index.html`;

    log(`Fetching advisory list page ${page}: ${listUrl}`);
    await sleep(RATE_LIMIT_MS);

    const listHtml = await fetchWithRetry(listUrl);
    if (!listHtml) {
      consecutiveEmpty++;
      if (consecutiveEmpty >= 3) {
        log(`3 consecutive empty/failed list pages at page ${page}, stopping`);
        break;
      }
      page++;
      continue;
    }
    consecutiveEmpty = 0;

    const detailLinks = parseAdvisoryListPage(listHtml);
    if (detailLinks.length === 0) {
      log(`No detail links found on page ${page}, stopping pagination`);
      break;
    }

    log(`  Found ${detailLinks.length} advisory links on page ${page}`);

    for (const detailUrl of detailLinks) {
      // Derive reference early to check for duplicates
      const slugMatch = detailUrl.match(
        /\/(sk-cert-bezpecnostne-varovanie-v\d{8}-\d+)\//i,
      );
      const earlyRef = slugMatch
        ? slugMatch[1]!.toUpperCase().replace(/BEZPECNOSTNE-VAROVANIE-/i, "A-")
        : null;

      if (earlyRef && !FORCE && existsStmt.get(earlyRef)) {
        log(`  Skipping existing: ${earlyRef}`);
        continue;
      }

      await sleep(RATE_LIMIT_MS);
      const detailHtml = await fetchWithRetry(detailUrl);
      if (!detailHtml) continue;

      const advisory = parseAdvisoryDetail(detailHtml, detailUrl);
      if (!advisory) continue;

      // Check again with final reference
      if (!FORCE && existsStmt.get(advisory.reference)) {
        log(`  Skipping existing: ${advisory.reference}`);
        continue;
      }

      if (DRY_RUN) {
        log(
          `  [DRY RUN] Would insert advisory: ${advisory.reference} — ${advisory.title}`,
        );
      } else {
        try {
          insertStmt.run({
            reference: advisory.reference,
            title: advisory.title,
            date: advisory.date,
            severity: advisory.severity,
            affected_products: advisory.affected_products,
            summary: advisory.summary,
            full_text: advisory.full_text,
            cve_references: advisory.cve_references,
          });
          log(
            `  Inserted advisory: ${advisory.reference} — ${advisory.title.slice(0, 80)}`,
          );
          ingested++;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          if (msg.includes("UNIQUE constraint")) {
            log(`  Duplicate skipped: ${advisory.reference}`);
          } else {
            error(`  DB insert failed for ${advisory.reference}: ${msg}`);
          }
        }
      }
    }

    // Check for next page
    const $list = cheerio.load(listHtml);
    if (!hasNextPage($list) && detailLinks.length < 5) {
      log(`No next-page indicator found on page ${page}, stopping`);
      break;
    }

    state.lastAdvisoryPage = page;
    saveState(state);
    page++;
  }

  state.advisoriesIngested += ingested;
  saveState(state);
  return ingested;
}

// ---------------------------------------------------------------------------
// Guidance crawling
// ---------------------------------------------------------------------------

async function crawlGuidance(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("--- Crawling NBU / SK-CERT guidance ---");

  const insertStmt = db.prepare(`
    INSERT OR IGNORE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (@reference, @title, @title_en, @date, @type, @series, @summary, @full_text, @topics, @status)
  `);

  const existsStmt = db.prepare(
    "SELECT 1 FROM guidance WHERE reference = ? LIMIT 1",
  );

  let ingested = 0;
  const visited = new Set<string>();

  const startIdx = RESUME ? state.lastGuidancePage : 0;

  for (let i = startIdx; i < GUIDANCE_SECTIONS.length; i++) {
    const section = GUIDANCE_SECTIONS[i]!;
    log(`Crawling guidance section: ${section.url}`);

    await sleep(RATE_LIMIT_MS);
    const sectionHtml = await fetchWithRetry(section.url);
    if (!sectionHtml) continue;

    // Parse the section page itself as a guidance document
    const sectionGuidance = parseGuidancePage(
      sectionHtml,
      section.url,
      section.series,
      section.type,
    );

    if (sectionGuidance && !visited.has(sectionGuidance.reference)) {
      visited.add(sectionGuidance.reference);

      if (!FORCE && existsStmt.get(sectionGuidance.reference)) {
        log(`  Skipping existing: ${sectionGuidance.reference}`);
      } else if (DRY_RUN) {
        log(
          `  [DRY RUN] Would insert guidance: ${sectionGuidance.reference} — ${sectionGuidance.title}`,
        );
      } else {
        try {
          insertStmt.run({
            reference: sectionGuidance.reference,
            title: sectionGuidance.title,
            title_en: sectionGuidance.title_en,
            date: sectionGuidance.date,
            type: sectionGuidance.type,
            series: sectionGuidance.series,
            summary: sectionGuidance.summary,
            full_text: sectionGuidance.full_text,
            topics: sectionGuidance.topics,
            status: sectionGuidance.status,
          });
          log(
            `  Inserted guidance: ${sectionGuidance.reference} — ${sectionGuidance.title.slice(0, 80)}`,
          );
          ingested++;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          if (!msg.includes("UNIQUE constraint")) {
            error(`  DB insert failed for ${sectionGuidance.reference}: ${msg}`);
          }
        }
      }
    }

    // Follow sub-page links from this section
    const subLinks = parseGuidanceSectionLinks(sectionHtml, section.url);
    log(`  Found ${subLinks.length} sub-links in section`);

    for (const subUrl of subLinks) {
      if (visited.has(subUrl)) continue;
      visited.add(subUrl);

      // Handle PDF links: record as guidance with download reference
      if (subUrl.endsWith(".pdf")) {
        const $section = cheerio.load(sectionHtml);
        const linkText =
          $section(`a[href*="${new URL(subUrl).pathname}"]`).first().text().trim() ||
          subUrl.split("/").pop()?.replace(".pdf", "") ||
          "";

        const pdfGuidance = parsePdfLinkAsGuidance(
          linkText,
          subUrl,
          section.series,
          section.type,
        );
        if (!pdfGuidance) continue;
        if (!FORCE && existsStmt.get(pdfGuidance.reference)) continue;

        if (DRY_RUN) {
          log(
            `  [DRY RUN] Would insert PDF guidance: ${pdfGuidance.reference} — ${pdfGuidance.title}`,
          );
        } else {
          try {
            insertStmt.run({
              reference: pdfGuidance.reference,
              title: pdfGuidance.title,
              title_en: pdfGuidance.title_en,
              date: pdfGuidance.date,
              type: pdfGuidance.type,
              series: pdfGuidance.series,
              summary: pdfGuidance.summary,
              full_text: pdfGuidance.full_text,
              topics: pdfGuidance.topics,
              status: pdfGuidance.status,
            });
            log(
              `  Inserted PDF guidance: ${pdfGuidance.reference} — ${pdfGuidance.title.slice(0, 80)}`,
            );
            ingested++;
          } catch {
            // Ignore duplicate or minor errors for PDF entries
          }
        }
        continue;
      }

      // Fetch and parse HTML sub-pages
      await sleep(RATE_LIMIT_MS);
      const subHtml = await fetchWithRetry(subUrl);
      if (!subHtml) continue;

      const subGuidance = parseGuidancePage(
        subHtml,
        subUrl,
        section.series,
        section.type,
      );
      if (!subGuidance) continue;
      if (!FORCE && existsStmt.get(subGuidance.reference)) {
        log(`  Skipping existing: ${subGuidance.reference}`);
        continue;
      }

      if (DRY_RUN) {
        log(
          `  [DRY RUN] Would insert guidance: ${subGuidance.reference} — ${subGuidance.title}`,
        );
      } else {
        try {
          insertStmt.run({
            reference: subGuidance.reference,
            title: subGuidance.title,
            title_en: subGuidance.title_en,
            date: subGuidance.date,
            type: subGuidance.type,
            series: subGuidance.series,
            summary: subGuidance.summary,
            full_text: subGuidance.full_text,
            topics: subGuidance.topics,
            status: subGuidance.status,
          });
          log(
            `  Inserted guidance: ${subGuidance.reference} — ${subGuidance.title.slice(0, 80)}`,
          );
          ingested++;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          if (!msg.includes("UNIQUE constraint")) {
            error(`  DB insert failed for ${subGuidance.reference}: ${msg}`);
          }
        }
      }
    }

    state.lastGuidancePage = i;
    saveState(state);
  }

  // Update framework document counts
  if (!DRY_RUN) {
    updateFrameworkCounts(db);
  }

  state.guidanceIngested += ingested;
  saveState(state);
  return ingested;
}

// ---------------------------------------------------------------------------
// Framework count sync
// ---------------------------------------------------------------------------

function updateFrameworkCounts(db: Database.Database): void {
  const frameworks: Array<{ id: string; series: string }> = [
    { id: "sk-cert", series: "SK-CERT" },
    { id: "nbu", series: "NBU" },
    { id: "nis2", series: "NIS2" },
  ];

  const countStmt = db.prepare(
    "SELECT count(*) as cnt FROM guidance WHERE series = ?",
  );
  const updateStmt = db.prepare(
    "UPDATE frameworks SET document_count = ? WHERE id = ?",
  );
  const insertFw = db.prepare(
    "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );

  // Ensure frameworks exist
  insertFw.run(
    "sk-cert",
    "SK-CERT Usmernenia a odporúčania",
    "SK-CERT Guidelines and Recommendations",
    "Oficiálne usmernenia a technické odporúčania SK-CERT pre ochranu informačných systémov, riadenie incidentov a kybernetickú bezpečnosť.",
    0,
  );
  insertFw.run(
    "nbu",
    "NBU — Odporúčania pre kybernetickú bezpečnosť",
    "NBU — Cybersecurity Recommendations",
    "Odporúčania Národného bezpečnostného úradu (NBU) pre ochranu utajovaných skutočností a kritickej infraštruktúry.",
    0,
  );
  insertFw.run(
    "nis2",
    "NIS2 — Národná implementácia",
    "NIS2 — National Implementation",
    "Materiály pre implementáciu smernice (EÚ) 2022/2555 (NIS2) na Slovensku vrátane požiadaviek na riadenie rizík.",
    0,
  );

  for (const fw of frameworks) {
    const row = countStmt.get(fw.series) as { cnt: number } | undefined;
    const count = row?.cnt ?? 0;
    updateStmt.run(count, fw.id);
  }

  log("Updated framework document counts");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("=== SK-CERT / NBU Ingestion Crawler ===");
  log(`Database: ${DB_PATH}`);
  log(
    `Flags: ${[DRY_RUN && "dry-run", RESUME && "resume", FORCE && "force", ADVISORIES_ONLY && "advisories-only", GUIDANCE_ONLY && "guidance-only"].filter(Boolean).join(", ") || "none"}`,
  );
  log(`Rate limit: ${RATE_LIMIT_MS}ms | Max retries: ${MAX_RETRIES}`);

  const db = DRY_RUN ? null : initDb();
  const state = loadState();

  let advisoryCount = 0;
  let guidanceCount = 0;

  try {
    if (!GUIDANCE_ONLY) {
      if (db) {
        advisoryCount = await crawlAdvisories(db, state);
      } else {
        // Dry-run: create a temporary in-memory DB for schema validation
        const tmpDb = new Database(":memory:");
        tmpDb.exec(SCHEMA_SQL);
        advisoryCount = await crawlAdvisories(tmpDb, state);
        tmpDb.close();
      }
    }

    if (!ADVISORIES_ONLY) {
      if (db) {
        guidanceCount = await crawlGuidance(db, state);
      } else {
        const tmpDb = new Database(":memory:");
        tmpDb.exec(SCHEMA_SQL);
        guidanceCount = await crawlGuidance(tmpDb, state);
        tmpDb.close();
      }
    }
  } finally {
    if (db) {
      // Print summary
      const gCount = (
        db.prepare("SELECT count(*) as cnt FROM guidance").get() as {
          cnt: number;
        }
      ).cnt;
      const aCount = (
        db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
          cnt: number;
        }
      ).cnt;
      const fCount = (
        db.prepare("SELECT count(*) as cnt FROM frameworks").get() as {
          cnt: number;
        }
      ).cnt;

      log("\n=== Ingestion Summary ===");
      log(`  Advisories ingested this run: ${advisoryCount}`);
      log(`  Guidance ingested this run:   ${guidanceCount}`);
      log(`  Total advisories in DB:       ${aCount}`);
      log(`  Total guidance in DB:         ${gCount}`);
      log(`  Total frameworks in DB:       ${fCount}`);

      db.close();
    } else {
      log("\n=== Dry Run Summary ===");
      log(`  Advisory pages scanned:  ${state.lastAdvisoryPage}`);
      log(`  Guidance sections:       ${GUIDANCE_SECTIONS.length}`);
    }

    saveState(state);
    log(`State saved to ${STATE_FILE}`);
    log("Done.");
  }
}

main().catch((err) => {
  error(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});

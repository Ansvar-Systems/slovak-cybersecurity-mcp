/**
 * Seed the SK-CERT database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["SK_CERT_DB_PATH"] ?? "data/sk-cert.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted existing database at ${DB_PATH}`); }

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

const frameworks = [
  { id: "sk-cert", name: "SK-CERT Usmernenia a odporúčania", name_en: "SK-CERT Guidelines and Recommendations", description: "Oficiálne usmernenia a technické odporúčania SK-CERT pre ochranu informačných systémov, riadenie incidentov a kybernetickú bezpečnosť.", document_count: 22 },
  { id: "nbu", name: "NBU — Odporúčania pre kybernetickú bezpečnosť", name_en: "NBU — Cybersecurity Recommendations", description: "Odporúčania Národného bezpečnostného úradu (NBU) pre ochranu utajovaných skutočností a kritickej infraštruktúry.", document_count: 14 },
  { id: "nis2", name: "NIS2 — Národná implementácia", name_en: "NIS2 — National Implementation", description: "Materiály pre implementáciu smernice (EÚ) 2022/2555 (NIS2) na Slovensku vrátane požiadaviek na riadenie rizík.", document_count: 9 },
];

const ins = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) ins.run(f.id, f.name, f.name_en, f.description, f.document_count);
console.log(`Inserted ${frameworks.length} frameworks`);

const guidance = [
  { reference: "SK-CERT-G-2023-001", title: "Usmernenie pre riadenie kybernetických incidentov", title_en: "Guidelines for Cybersecurity Incident Management", date: "2023-04-10", type: "guideline", series: "SK-CERT", summary: "Usmernenie popisuje postupy pre identifikáciu, klasifikáciu, riešenie a hlásenie kybernetických incidentov pre operátorov základných a dôležitých služieb.", full_text: "SK-CERT vydáva toto usmernenie v súlade so zákonom o kybernetickej bezpečnosti a smernicou NIS2. Incidenty sa klasifikujú podľa závažnosti od 1 (nízka) do 4 (kritická). Operátori sú povinní hlásiť významné incidenty SK-CERT do 24 hodín (skoré varovanie) a do 72 hodín (úplná správa). SK-CERT koordinuje reakciu na rozsiahle incidenty s príslušnými národnými orgánmi a medzinárodnými CERT organizáciami.", topics: JSON.stringify(["incident_response", "reporting", "NIS2"]), status: "current" },
  { reference: "SK-CERT-G-2023-002", title: "Technické usmernenie pre bezpečnosť webových aplikácií", title_en: "Technical Guideline for Web Application Security", date: "2023-07-15", type: "guideline", series: "SK-CERT", summary: "Technické usmernenie pre bezpečný vývoj a správu webových aplikácií vo verejnom sektore na Slovensku.", full_text: "SK-CERT vydáva technické usmernenie pre bezpečnosť webových aplikácií vychádzajúce z OWASP ASVS. Požiadavky: všetky administratívne rozhrania vyžadujú dvojfaktorovú autentifikáciu; parametrizované dotazy sú povinné na prevenciu SQL injekcií; všetky webové aplikácie musia používať TLS 1.2 alebo novší; autentifikačné pokusy a administratívne akcie sa zaznamenávajú v chránených auditných protokoloch.", topics: JSON.stringify(["web_security", "OWASP", "authentication", "TLS"]), status: "current" },
  { reference: "SK-CERT-G-2022-005", title: "Usmernenie pre ochranu kritickej informačnej infraštruktúry", title_en: "Guideline for Critical Information Infrastructure Protection", date: "2022-09-20", type: "guideline", series: "SK-CERT", summary: "Usmernenie pre identifikáciu a ochranu kritickej informačnej infraštruktúry na Slovensku v sektoroch energetiky, dopravy a financií.", full_text: "SK-CERT vydáva usmernenie pre ochranu kritickej informačnej infraštruktúry v spolupráci s NBU. Minimálne požiadavky: aktuálny register IT aktív; ročné hodnotenie rizík; segmentácia OT sietí od podnikových sietí; denné zálohovanie kritických údajov s kópiou mimo hlavného miesta; testovaný plán kontinuity so RTO maximálne 24 hodín pre kritické systémy.", topics: JSON.stringify(["critical_infrastructure", "risk_management", "OT_security"]), status: "current" },
  { reference: "NBU-R-2024-001", title: "Odporúčania pre ochranu utajovaných skutočností v informačných systémoch", title_en: "Recommendations for Protection of Classified Information in Information Systems", date: "2024-02-01", type: "recommendation", series: "NBU", summary: "Odporúčania NBU pre technickú a organizačnú ochranu utajovaných skutočností v automatizovaných informačných systémoch.", full_text: "NBU vydáva odporúčania pre ochranu utajovaných skutočností podľa zákona o ochrane utajovaných skutočností. Informačné systémy spracúvajúce utajované skutočnosti musia byť umiestnené v chránených priestoroch s elektronickou kontrolou prístupu. Princíp minimálnych oprávnení je povinný s dvojfaktorovou autentifikáciou. Pre prenos utajovaných skutočností sa povinne používajú schválené kryptografické algoritmy. Všetky operácie s utajovanými skutočnosťami sa zaznamenávajú minimálne po dobu 5 rokov.", topics: JSON.stringify(["classified_information", "access_control", "encryption"]), status: "current" },
  { reference: "NIS2-SK-2024-001", title: "Príručka pre implementáciu požiadaviek NIS2 na Slovensku", title_en: "Guide for Implementation of NIS2 Requirements in Slovakia", date: "2024-02-16", type: "guideline", series: "NIS2", summary: "Praktická príručka pre operátorov základných a dôležitých služieb na Slovensku pre implementáciu požiadaviek smernice NIS2.", full_text: "SK-CERT a Úrad pre reguláciu elektronických komunikácií vydávajú príručku pre implementáciu smernice NIS2 na Slovensku. Operátori sa musia zaregistrovať do 17. apríla 2025. Povinnosti: riadenie rizík vrátane politík informačnej bezpečnosti; hodnotenie bezpečnostných rizík dodávateľského reťazca; skoré varovanie do 24 hodín, úplná správa do 72 hodín. Sankcie za nedodržanie: až 10 000 000 eur alebo 2% ročného obratu pre operátorov základných služieb.", topics: JSON.stringify(["NIS2", "risk_management", "incident_reporting"]), status: "current" },
];

const ig = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
db.transaction(() => { for (const g of guidance) ig.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); })();
console.log(`Inserted ${guidance.length} guidance documents`);

const advisories = [
  { reference: "SK-CERT-A-2024-001", title: "Kritická zraniteľnosť v Microsoft Exchange Server", date: "2024-02-14", severity: "critical", affected_products: JSON.stringify(["Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"]), summary: "SK-CERT upozorňuje na aktívne zneužívanú kritickú zraniteľnosť CVE-2024-21410 v Microsoft Exchange Server umožňujúcu eskaláciu privilégií.", full_text: "SK-CERT zaznamenal aktívne zneužívanie zraniteľnosti CVE-2024-21410 v Microsoft Exchange Server. Zraniteľnosť umožňuje útočníkovi eskalovať privilégiá prostredníctvom NTLM relay útoku. Odporúčania: okamžite nainštalujte bezpečnostné aktualizácie od Microsoftu; aktivujte Extended Protection for Authentication (EPA) na Exchange serveri; monitorujte auditné protokoly na podozrivé aktivity autentifikácie.", cve_references: JSON.stringify(["CVE-2024-21410"]) },
  { reference: "SK-CERT-A-2024-003", title: "Ransomvérová kampaň zameraná na slovenské nemocnice", date: "2024-04-05", severity: "high", affected_products: JSON.stringify(["Windows Server 2019/2022", "VMware vSphere"]), summary: "SK-CERT varuje pred zvýšenou aktivitou ransomvérových skupín zameraných na zdravotnícke organizácie na Slovensku.", full_text: "SK-CERT zaznamenal viaceré ransomvérové incidenty v slovenských zdravotníckych zariadeniach. Útočníci využívajú phishingové e-maily a zraniteľnosti v VPN riešeniach. Opatrenia: okamžite deaktivujte RDP služby dostupné z internetu; aktivujte MFA pre všetky administratívne prístupy; overte záložné kópie a ich integritu. Pri incidente — neplatte výkupné a kontaktujte SK-CERT.", cve_references: JSON.stringify([]) },
  { reference: "SK-CERT-A-2023-022", title: "Zraniteľnosť v Citrix NetScaler — naliehavá aktualizácia", date: "2023-10-11", severity: "critical", affected_products: JSON.stringify(["Citrix NetScaler ADC", "Citrix NetScaler Gateway"]), summary: "SK-CERT vydáva naliehavé upozornenie na kritickú zraniteľnosť CVE-2023-4966 (Citrix Bleed) v produktoch Citrix NetScaler.", full_text: "SK-CERT zaznamenal masívne zneužívanie zraniteľnosti CVE-2023-4966 (Citrix Bleed) v produktoch Citrix NetScaler ADC a Gateway. Zraniteľnosť umožňuje neautentifikované čítanie pamäte zariadenia vrátane platných relačných tokenov. Odporúčania: okamžite aktualizujte na opravenou verziu; ukončite všetky aktívne relácie po aktualizácii; preskúmajte protokoly na príznaky kompromitácie.", cve_references: JSON.stringify(["CVE-2023-4966"]) },
];

const ia = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
db.transaction(() => { for (const a of advisories) ia.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); })();
console.log(`Inserted ${advisories.length} advisories`);

const gCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const aCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const fCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log(`\nDatabase summary:\n  Frameworks: ${fCount}\n  Guidance:   ${gCount}\n  Advisories: ${aCount}\n\nDone. Database ready at ${DB_PATH}`);
db.close();

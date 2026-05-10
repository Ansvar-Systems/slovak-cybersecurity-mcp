#!/usr/bin/env node

/**
 * Slovak Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying SK-CERT (Slovak National Cybersecurity Agency)
 * guidelines, security advisories, and cybersecurity frameworks for Slovakia.
 *
 * Tool prefix: sk_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { searchGuidance, getGuidance, searchAdvisories, getAdvisory, listFrameworks } from "./db.js";
import { buildCitation } from "./utils/citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")) as { version: string };
  pkgVersion = pkg.version;
} catch { /* fallback */ }

const SERVER_NAME = "slovak-cybersecurity-mcp";

const TOOLS = [
  {
    name: "sk_cyber_search_guidance",
    description: "Full-text search across SK-CERT cybersecurity guidelines, recommendations, and national standards. Covers network security, incident response, risk management, and NIS2 implementation guidance for Slovakia. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'kybernetická bezpečnosť', 'riadenie incidentov', 'NIS2', 'sieťová bezpečnosť')" },
        type: { type: "string", enum: ["guideline", "recommendation", "standard", "policy"], description: "Filter by document type. Optional." },
        series: { type: "string", enum: ["SK-CERT", "NBU", "NIS2"], description: "Filter by issuing body or series. Optional." },
        status: { type: "string", enum: ["current", "superseded", "draft"], description: "Filter by document status. Optional." },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "sk_cyber_get_guidance",
    description: "Get a specific SK-CERT guidance document by reference (e.g., 'SK-CERT-G-2023-001', 'NBU-R-2024-01').",
    inputSchema: {
      type: "object" as const,
      properties: { reference: { type: "string", description: "SK-CERT document reference" } },
      required: ["reference"],
    },
  },
  {
    name: "sk_cyber_search_advisories",
    description: "Search SK-CERT security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'kritická zraniteľnosť', 'ransomvér', 'phishing')" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low"], description: "Filter by severity level. Optional." },
        limit: { type: "number", description: "Maximum number of results to return. Defaults to 20." },
      },
      required: ["query"],
    },
  },
  {
    name: "sk_cyber_get_advisory",
    description: "Get a specific SK-CERT security advisory by reference (e.g., 'SK-CERT-A-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: { reference: { type: "string", description: "SK-CERT advisory reference" } },
      required: ["reference"],
    },
  },
  {
    name: "sk_cyber_list_frameworks",
    description: "List all cybersecurity frameworks and standard series covered in this MCP, including SK-CERT guidelines, NBU recommendations, and NIS2 implementation materials for Slovakia.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "sk_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guideline", "recommendation", "standard", "policy"]).optional(),
  series: z.enum(["SK-CERT", "NBU", "NIS2"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});
const GetGuidanceArgs = z.object({ reference: z.string().min(1) });
const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});
const GetAdvisoryArgs = z.object({ reference: z.string().min(1) });

function textContent(data: unknown) { return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] }; }
function errorContent(message: string) { return { content: [{ type: "text" as const, text: message }], isError: true as const }; }

const server = new Server({ name: SERVER_NAME, version: pkgVersion }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    switch (name) {
      case "sk_cyber_search_guidance": { const p = SearchGuidanceArgs.parse(args); return textContent({ results: searchGuidance({ query: p.query, type: p.type, series: p.series, status: p.status, limit: p.limit }), count: searchGuidance({ query: p.query, type: p.type, series: p.series, status: p.status, limit: p.limit }).length }); }
      case "sk_cyber_get_guidance": {
        const p = GetGuidanceArgs.parse(args);
        const doc = getGuidance(p.reference);
        if (!doc) return errorContent(`Guidance document not found: ${p.reference}`);
        const _citation = buildCitation(
          p.reference,
          (doc as unknown as Record<string, unknown>).title as string || p.reference,
          "sk_cyber_get_guidance",
          { reference: p.reference },
        );
        return textContent({ ...doc as unknown as Record<string, unknown>, _citation });
      }
      case "sk_cyber_search_advisories": { const p = SearchAdvisoriesArgs.parse(args); const r = searchAdvisories({ query: p.query, severity: p.severity, limit: p.limit }); return textContent({ results: r, count: r.length }); }
      case "sk_cyber_get_advisory": {
        const p = GetAdvisoryArgs.parse(args);
        const a = getAdvisory(p.reference);
        if (!a) return errorContent(`Advisory not found: ${p.reference}`);
        const _citation = buildCitation(
          p.reference,
          (a as unknown as Record<string, unknown>).title as string || p.reference,
          "sk_cyber_get_advisory",
          { reference: p.reference },
        );
        return textContent({ ...a as unknown as Record<string, unknown>, _citation });
      }
      case "sk_cyber_list_frameworks": { const f = listFrameworks(); return textContent({ frameworks: f, count: f.length }); }
      case "sk_cyber_about": return textContent({ name: SERVER_NAME, version: pkgVersion, description: "SK-CERT (Slovak National Cybersecurity Agency) MCP server. Provides access to Slovak cybersecurity guidelines, security advisories, and NIS2 implementation materials.", data_source: "SK-CERT (https://www.sk-cert.sk/) and National Security Authority — NBU (https://www.nbu.gov.sk/)", coverage: { guidance: "SK-CERT guidelines, NBU recommendations, NIS2 implementation materials for Slovakia", advisories: "SK-CERT security advisories and alerts", frameworks: "National cybersecurity frameworks, NIS2 compliance, critical infrastructure protection" }, tools: TOOLS.map(t => ({ name: t.name, description: t.description })) });
      default: return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) { return errorContent(`Error executing ${name}: ${err instanceof Error ? err.message : String(err)}`); }
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}
main().catch(err => { process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`); process.exit(1); });

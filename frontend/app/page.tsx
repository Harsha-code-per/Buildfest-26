"use client";

import { useState } from "react";
import { RiskItem, scoreCves } from "@/lib/api";
import RiskTable from "@/components/RiskTable";

const EXAMPLE = "CVE-2021-44228\nCVE-2014-0160\nCVE-2019-0708\nCVE-2017-0144";

export default function Home() {
  const [input, setInput] = useState(EXAMPLE);
  const [results, setResults] = useState<RiskItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const cves = input
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      setResults(await scoreCves(cves));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  function exportCsv() {
    const rows = [
      ["cve", "score", "priority", "cvss", "epss", "in_kev", "kev_ransomware"],
      ...results.map((r) => [
        r.cve, r.score, r.priority, r.cvss ?? "", r.epss ?? "", r.in_kev, r.kev_ransomware,
      ]),
    ];
    const csv = rows.map((r) => r.join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "risksense.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="mx-auto max-w-4xl px-4 py-10">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">
          Risk<span className="text-sky-400">Sense</span>
        </h1>
        <p className="mt-1 text-slate-400">
          CVE risk prioritization — blends <b>CVSS</b> severity, <b>EPSS</b> exploit probability,
          and <b>CISA KEV</b> active-exploitation intel into one actionable score.
        </p>
      </header>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={5}
        spellCheck={false}
        className="w-full rounded-lg border border-slate-800 bg-slate-900 p-3 font-mono text-sm outline-none focus:border-sky-500"
        placeholder="Paste CVE IDs, one per line or comma-separated…"
      />

      <div className="mt-3 flex items-center gap-3">
        <button
          onClick={run}
          disabled={loading}
          className="rounded-lg bg-sky-500 px-4 py-2 font-medium text-slate-950 hover:bg-sky-400 disabled:opacity-50"
        >
          {loading ? "Scoring…" : "Prioritize"}
        </button>
        {results.length > 0 && (
          <button
            onClick={exportCsv}
            className="rounded-lg border border-slate-700 px-4 py-2 text-slate-300 hover:bg-slate-900"
          >
            Export CSV
          </button>
        )}
      </div>

      {error && (
        <p className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-red-300">
          {error}
        </p>
      )}

      {results.length > 0 && (
        <div className="mt-6">
          <RiskTable results={results} />
          <p className="mt-2 text-xs text-slate-500">
            Ranked highest-risk first. KEV entries are floored to Critical because active
            exploitation outweighs theoretical severity.
          </p>
        </div>
      )}
    </main>
  );
}

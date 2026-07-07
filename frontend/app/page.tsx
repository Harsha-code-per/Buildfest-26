"use client";

import { useState } from "react";
import { RiskItem, scoreCves } from "@/lib/api";
import RiskTable from "@/components/RiskTable";

const EXAMPLE = "CVE-2021-44228\nCVE-2014-0160\nCVE-2019-0708\nCVE-2017-0144";

const STEPS = [
  {
    k: "01",
    title: "Enrich",
    body: "Every CVE is scored against three live feeds — CVSS severity (NVD), EPSS exploit probability (FIRST), and the CISA KEV active-exploitation catalog.",
  },
  {
    k: "02",
    title: "Decide",
    body: "The same signals drive a transparent SSVC decision — Act, Attend, or Track — not just an opaque 0–100 number. Every call shows its reasoning.",
  },
  {
    k: "03",
    title: "Act",
    body: "Results rank by action tier first, then score. An actively-exploited medium always outranks a theoretical critical. Export and get to work.",
  },
];

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
      ["cve", "action", "score", "priority", "cvss", "epss", "in_kev", "kev_ransomware", "days_overdue"],
      ...results.map((r) => [
        r.cve, r.ssvc?.action ?? "", r.score, r.priority,
        r.cvss ?? "", r.epss ?? "", r.in_kev, r.kev_ransomware, r.days_overdue ?? "",
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
    <main>
      {/* ---- Hero ---- */}
      <section className="relative flex min-h-screen flex-col items-center justify-center px-6 text-center">
        <span className="mb-6 rounded-full border border-sky-400/30 bg-sky-400/5 px-4 py-1.5 text-xs font-medium uppercase tracking-[0.2em] text-sky-300">
          CVE triage, reimagined
        </span>
        <h1 className="max-w-4xl text-5xl leading-[1.05] tracking-tight sm:text-7xl">
          <span className="font-display text-sky-300">Decide.</span>{" "}
          <span className="text-slate-100">Don&rsquo;t just score.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-slate-300/90">
          RiskSense turns a list of CVEs into a transparent{" "}
          <b className="text-slate-100">SSVC decision</b> — Act, Attend, or Track — blending{" "}
          <b className="text-slate-100">CVSS</b> severity, <b className="text-slate-100">EPSS</b>{" "}
          exploit probability, and <b className="text-slate-100">CISA KEV</b> intel. Reasoning
          shown. No agent, no account.
        </p>
        <a
          href="#scan"
          className="mt-10 rounded-full bg-sky-500 px-6 py-3 font-medium text-slate-950 shadow-lg shadow-sky-500/20 transition hover:bg-sky-400"
        >
          Prioritize your CVEs ↓
        </a>
        <div className="pointer-events-none absolute bottom-8 flex flex-col items-center gap-2 text-slate-500">
          <span className="text-xs uppercase tracking-widest">Scroll</span>
          <span className="h-10 w-px animate-pulse bg-gradient-to-b from-sky-400/60 to-transparent" />
        </div>
      </section>

      {/* ---- Scanner ---- */}
      <section id="scan" className="mx-auto max-w-4xl px-6 py-24">
        <div className="glass rounded-2xl p-6 sm:p-8">
          <div className="mb-5">
            <h2 className="text-2xl">
              <span className="font-display text-sky-300">Prioritize</span> a batch
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Paste CVE IDs — one per line or comma-separated.
            </p>
          </div>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={5}
            spellCheck={false}
            className="w-full rounded-xl border border-slate-700/60 bg-slate-950/50 p-4 font-mono text-sm text-slate-100 outline-none transition focus:border-sky-500"
            placeholder="Paste CVE IDs, one per line or comma-separated…"
          />

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={run}
              disabled={loading}
              className="rounded-lg bg-sky-500 px-5 py-2.5 font-medium text-slate-950 shadow-lg shadow-sky-500/20 transition hover:bg-sky-400 disabled:opacity-50"
            >
              {loading ? "Scoring…" : "Prioritize"}
            </button>
            {results.length > 0 && (
              <button
                onClick={exportCsv}
                className="rounded-lg border border-slate-700 px-5 py-2.5 text-slate-300 transition hover:bg-slate-800/50"
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
              <p className="mt-3 text-xs leading-relaxed text-slate-500">
                Ranked by SSVC action (Act → Attend → Track), then score. Hover an{" "}
                <b className="text-slate-400">Action</b> for the reasoning. The
                environmental/mission dimension of full SSVC is omitted (no asset context),
                so decisions stay conservative.
              </p>
            </div>
          )}
        </div>
      </section>

      {/* ---- How it works ---- */}
      <section className="mx-auto max-w-5xl px-6 pb-24">
        <h2 className="mb-10 text-center text-3xl">
          <span className="font-display text-sky-300">Three</span> signals, one decision
        </h2>
        <div className="grid gap-5 sm:grid-cols-3">
          {STEPS.map((s) => (
            <div key={s.k} className="glass rounded-2xl p-6">
              <div className="font-display text-4xl text-sky-400/70">{s.k}</div>
              <h3 className="mt-3 text-xl text-slate-100">{s.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Footer ---- */}
      <footer className="border-t border-slate-800/60 px-6 py-12 text-center text-sm text-slate-500">
        <p>
          Data from{" "}
          <a className="text-slate-400 hover:text-sky-300" href="https://nvd.nist.gov/" target="_blank" rel="noreferrer">NVD</a>,{" "}
          <a className="text-slate-400 hover:text-sky-300" href="https://www.first.org/epss/" target="_blank" rel="noreferrer">FIRST EPSS</a>, and{" "}
          <a className="text-slate-400 hover:text-sky-300" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer">CISA KEV</a>.
        </p>
        <p className="mt-2">
          <a className="text-slate-400 hover:text-sky-300" href="https://github.com/AtharvS7/RiskSense" target="_blank" rel="noreferrer">
            github.com/AtharvS7/RiskSense
          </a>
        </p>
      </footer>
    </main>
  );
}

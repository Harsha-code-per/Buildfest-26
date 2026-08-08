import { RiskItem } from "@/lib/api";

const bandColor: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-300 border-red-500/30",
  High: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  Medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  Low: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

// SSVC action — the decision, not just the number. Bolder than the priority
// band on purpose: it's what the user acts on.
const actionColor: Record<string, string> = {
  Act: "bg-red-500/20 text-red-200 border-red-500/40 font-semibold",
  Attend: "bg-amber-500/20 text-amber-200 border-amber-500/40",
  Track: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

function pct(x: number | null): string {
  return x === null ? "—" : `${(x * 100).toFixed(1)}%`;
}

// CISA binding-deadline clock. Overdue is the loudest signal in the table —
// it's a federally-mandated remediation date that has already passed.
const slaColor: Record<string, string> = {
  overdue: "bg-red-500/20 text-red-200 border-red-500/40 font-semibold",
  due: "bg-amber-500/15 text-amber-200 border-amber-500/30",
  none: "text-slate-600",
};

export default function RiskTable({ results }: { results: RiskItem[] }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-slate-800/80 shadow-2xl bg-slate-950/40 backdrop-blur-xl">
      <table className="w-full text-sm text-left border-collapse">
        <thead className="bg-slate-900/90 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800/80">
          <tr>
            <th className="px-4 py-3.5 font-semibold text-slate-500 w-10">#</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">CVE</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">Action</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">RiskSense</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">Priority</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">CVSS</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">EPSS</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">KEV Intel</th>
            <th className="px-4 py-3.5 font-semibold whitespace-nowrap">CISA Deadline</th>
            <th className="px-4 py-3.5 font-semibold min-w-[320px]">AI Remediation (GPT-4o-mini)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {results.map((r, i) => (
            <tr
              key={r.cve}
              className="transition-all duration-200 hover:bg-sky-500/[0.06] group"
            >
              <td className="px-4 py-3.5 text-slate-600 font-mono text-xs">{i + 1}</td>
              <td className="px-4 py-3.5 font-mono whitespace-nowrap">
                <a
                  className="text-sky-400 font-semibold group-hover:text-sky-300 transition-colors hover:underline"
                  href={`https://nvd.nist.gov/vuln/detail/${r.cve}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {r.cve}
                </a>
              </td>
              <td className="px-4 py-3.5 whitespace-nowrap">
                <span
                  className={`cursor-help rounded-md border px-2.5 py-1 text-xs shadow-sm inline-block ${actionColor[r.ssvc?.action] ?? ""}`}
                  title={r.ssvc?.why ?? "SSVC decision"}
                >
                  {r.ssvc?.action ?? "—"}
                </span>
              </td>
              <td className="px-4 py-3.5 whitespace-nowrap">
                <div className="flex items-center gap-3">
                  <div className="h-2 w-28 overflow-hidden rounded-full bg-slate-800/80 p-0.5 border border-slate-700/50">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-sky-500 via-indigo-400 to-sky-300 shadow-[0_0_8px_rgba(56,189,248,0.5)]"
                      style={{ width: `${r.score}%` }}
                    />
                  </div>
                  <span className="font-bold tabular-nums text-slate-100 text-sm">{r.score}</span>
                </div>
              </td>
              <td className="px-4 py-3.5 whitespace-nowrap">
                <span className={`rounded-md border px-2.5 py-0.5 text-xs font-medium ${bandColor[r.priority] ?? ""}`}>
                  {r.priority}
                </span>
              </td>
              <td className="px-4 py-3.5 tabular-nums text-slate-300 font-mono whitespace-nowrap">{r.cvss ?? "—"}</td>
              <td className="px-4 py-3.5 tabular-nums text-slate-300 font-mono whitespace-nowrap">{pct(r.epss)}</td>
              <td className="px-4 py-3.5 whitespace-nowrap">
                {r.in_kev ? (
                  <span
                    className="inline-flex items-center gap-1.5 rounded-md border border-red-500/30 bg-red-500/10 px-2.5 py-0.5 text-xs text-red-300 font-medium"
                    title={r.kev_ransomware ? "Known ransomware campaign use" : "CISA Known Exploited Vulnerability"}
                  >
                    <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                    {r.kev_ransomware ? "Ransomware" : "KEV"}
                  </span>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
              <td className="px-4 py-3.5 whitespace-nowrap">
                {r.sla?.state && r.sla.state !== "none" ? (
                  <span
                    className={`rounded-md border px-2.5 py-1 text-xs inline-block ${slaColor[r.sla.state] ?? ""}`}
                    title="CISA BOD 22-01 binding remediation deadline"
                  >
                    {r.sla.label}
                  </span>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
              <td className="px-4 py-3.5 text-xs leading-relaxed text-slate-200/90 min-w-[320px] max-w-md">
                {r.ai_remediation ? (
                  <div className="rounded-lg border border-sky-500/20 bg-sky-950/20 p-2.5 text-sky-200/90 shadow-sm backdrop-blur-sm">
                    {r.ai_remediation}
                  </div>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


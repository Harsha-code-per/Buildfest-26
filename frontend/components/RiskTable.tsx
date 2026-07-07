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
    <div className="overflow-x-auto rounded-xl border border-slate-800/70">
      <table className="w-full text-sm">
        <thead className="bg-slate-900/60 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="px-3 py-2.5 text-left font-medium">#</th>
            <th className="px-3 py-2.5 text-left font-medium">CVE</th>
            <th className="px-3 py-2.5 text-left font-medium">Action</th>
            <th className="px-3 py-2.5 text-left font-medium">RiskSense</th>
            <th className="px-3 py-2.5 text-left font-medium">Priority</th>
            <th className="px-3 py-2.5 text-left font-medium">CVSS</th>
            <th className="px-3 py-2.5 text-left font-medium">EPSS</th>
            <th className="px-3 py-2.5 text-left font-medium">KEV</th>
            <th className="px-3 py-2.5 text-left font-medium">Deadline</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => (
            <tr
              key={r.cve}
              className="border-t border-slate-800/60 transition-colors hover:bg-sky-500/[0.04]"
            >
              <td className="px-3 py-2.5 text-slate-600">{i + 1}</td>
              <td className="px-3 py-2.5 font-mono">
                <a
                  className="text-sky-400 hover:underline"
                  href={`https://nvd.nist.gov/vuln/detail/${r.cve}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {r.cve}
                </a>
              </td>
              <td className="px-3 py-2.5">
                <span
                  className={`cursor-help rounded border px-2 py-0.5 text-xs ${actionColor[r.ssvc?.action] ?? ""}`}
                  title={r.ssvc?.why ?? "SSVC decision"}
                >
                  {r.ssvc?.action ?? "—"}
                </span>
              </td>
              <td className="px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-24 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-sky-500 to-sky-300"
                      style={{ width: `${r.score}%` }}
                    />
                  </div>
                  <span className="font-semibold tabular-nums text-slate-200">{r.score}</span>
                </div>
              </td>
              <td className="px-3 py-2.5">
                <span className={`rounded border px-2 py-0.5 text-xs ${bandColor[r.priority] ?? ""}`}>
                  {r.priority}
                </span>
              </td>
              <td className="px-3 py-2.5 tabular-nums text-slate-300">{r.cvss ?? "—"}</td>
              <td className="px-3 py-2.5 tabular-nums text-slate-300">{pct(r.epss)}</td>
              <td className="px-3 py-2.5">
                {r.in_kev ? (
                  <span
                    className="text-red-400"
                    title={r.kev_ransomware ? "Known ransomware campaign use" : "CISA Known Exploited Vulnerability"}
                  >
                    ● {r.kev_ransomware ? "Ransomware" : "KEV"}
                  </span>
                ) : (
                  <span className="text-slate-600">—</span>
                )}
              </td>
              <td className="px-3 py-2.5">
                {r.sla?.state && r.sla.state !== "none" ? (
                  <span
                    className={`rounded border px-2 py-0.5 text-xs ${slaColor[r.sla.state] ?? ""}`}
                    title="CISA BOD 22-01 binding remediation deadline"
                  >
                    {r.sla.label}
                  </span>
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

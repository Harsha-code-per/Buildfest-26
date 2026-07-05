import { RiskItem } from "@/lib/api";

const bandColor: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-300 border-red-500/30",
  High: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  Medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  Low: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

function pct(x: number | null): string {
  return x === null ? "—" : `${(x * 100).toFixed(1)}%`;
}

export default function RiskTable({ results }: { results: RiskItem[] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-slate-400">
          <tr>
            <th className="px-3 py-2 text-left font-medium">#</th>
            <th className="px-3 py-2 text-left font-medium">CVE</th>
            <th className="px-3 py-2 text-left font-medium">RiskSense</th>
            <th className="px-3 py-2 text-left font-medium">Priority</th>
            <th className="px-3 py-2 text-left font-medium">CVSS</th>
            <th className="px-3 py-2 text-left font-medium">EPSS</th>
            <th className="px-3 py-2 text-left font-medium">KEV</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => (
            <tr key={r.cve} className="border-t border-slate-800 hover:bg-slate-900/50">
              <td className="px-3 py-2 text-slate-500">{i + 1}</td>
              <td className="px-3 py-2 font-mono">
                <a
                  className="text-sky-400 hover:underline"
                  href={`https://nvd.nist.gov/vuln/detail/${r.cve}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {r.cve}
                </a>
              </td>
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-24 rounded bg-slate-800">
                    <div className="h-2 rounded bg-sky-500" style={{ width: `${r.score}%` }} />
                  </div>
                  <span className="font-semibold tabular-nums">{r.score}</span>
                </div>
              </td>
              <td className="px-3 py-2">
                <span className={`rounded border px-2 py-0.5 text-xs ${bandColor[r.priority] ?? ""}`}>
                  {r.priority}
                </span>
              </td>
              <td className="px-3 py-2 tabular-nums">{r.cvss ?? "—"}</td>
              <td className="px-3 py-2 tabular-nums">{pct(r.epss)}</td>
              <td className="px-3 py-2">
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

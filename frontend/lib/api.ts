export interface RiskItem {
  cve: string;
  score: number;
  priority: string;
  cvss: number | null;
  epss: number | null;
  percentile: number | null;
  in_kev: boolean;
  kev_ransomware: boolean;
  days_overdue: number | null;
  breakdown: Record<string, unknown>;
  ssvc: {
    action: "Act" | "Attend" | "Track";
    exploitation: string;
    automatable: boolean;
    technical_impact: string;
    why: string;
  };
  sla: {
    state: "overdue" | "due" | "none";
    days_overdue: number | null;
    label: string;
  };
}

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function scoreCves(cves: string[]): Promise<RiskItem[]> {
  const res = await fetch(`${API_URL}/api/score`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cves }),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? `Request failed (${res.status})`);
  }
  const data = await res.json();
  return data.results as RiskItem[];
}

export type Verdict = "Safe" | "Suspicious" | "Malicious";
export type AnalysisStatus = "requested" | "running" | "completed" | "failed";

export interface AnalysisResponse {
  id: string;
  submitted_url: string;
  normalized_url: string | null;
  status: AnalysisStatus;
  verdict: Verdict | null;
  risk_score: number | null;
  explanation: string | null;
  evidence: Record<string, unknown>;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

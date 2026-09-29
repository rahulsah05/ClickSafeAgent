export interface User {
  name: string;
  mobile: string;
}

export interface PredictResponse {
  url: string;
  label: "safe" | "scam";
  confidence: number;
  rules: string[];
  explanation: string[];
}

export interface ReportResponse {
  ok: boolean;
  id: string;
}

export interface ReportRequest {
  url: string;
  reporter: string;
  notes?: string;
}

export interface HistoryItem {
  id: string;
  url: string;
  label: "safe" | "scam";
  confidence: number;
  timestamp: number;
}

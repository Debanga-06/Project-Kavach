import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export const api = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  headers: { "Content-Type": "application/json" },
});

export interface UserOut {
  id: string;
  name: string;
  email: string;
  role: "user" | "security_analyst" | "administrator";
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export async function registerUser(name: string, email: string, password: string): Promise<UserOut> {
  const { data } = await api.post<UserOut>("/auth/register", { name, email, password });
  return data;
}

export async function loginUser(email: string, password: string): Promise<TokenPair> {
  const { data } = await api.post<TokenPair>("/auth/login", { email, password });
  return data;
}

export async function fetchMe(accessToken: string): Promise<UserOut> {
  const { data } = await api.get<UserOut>("/auth/me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return data;
}

export interface EvidenceItem {
  signal: string;
  description: string;
  weight: number;
}

export interface ScanResult {
  scan_id: string;
  scan_type: string;
  target: string;
  risk_score: number;
  severity: "SAFE" | "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL";
  classification: string;
  confidence: number;
  status: string;
  evidence: EvidenceItem[];
  recommendations: string[];
  ai_summary: string | null;
  ai_explanation: string[];
  ai_model: string | null;
  created_at: string;
}

export async function scanUrl(accessToken: string, url: string): Promise<ScanResult> {
  const { data } = await api.post<ScanResult>(
    "/scan/url",
    { url },
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  return data;
}

export async function scanEmail(
  accessToken: string,
  sender: string,
  subject: string,
  body: string
): Promise<ScanResult> {
  const { data } = await api.post<ScanResult>(
    "/scan/email",
    { sender, subject, body },
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  return data;
}

export interface ScanSummary {
  scan_id: string;
  scan_type: string;
  target: string;
  risk_score: number;
  severity: string;
  classification: string;
  created_at: string;
}

export async function listScans(accessToken: string): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>("/scans", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return data;
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface RecentScan {
  scan_id: string;
  scan_type: string;
  target: string;
  risk_score: number;
  severity: string;
  created_at: string;
}

export interface TrendPoint {
  date: string;
  avg_risk_score: number;
  scan_count: number;
}

export interface DashboardStats {
  total_scans: number;
  threats_detected: number;
  critical_threats: number;
  safe_scans: number;
  severity_distribution: SeverityCount[];
  recent_scans: RecentScan[];
  risk_trend: TrendPoint[];
}

export async function fetchDashboardStats(accessToken: string): Promise<DashboardStats> {
  const { data } = await api.get<DashboardStats>("/dashboard/stats", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return data;
}

/** Extracts a human-readable message from a FastAPI error response. */
export function apiErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg as string;
    if (err.code === "ERR_NETWORK") return "Can't reach the KavachAI backend. Is it running on :8000?";
  }
  return "Something went wrong. Try again.";
}

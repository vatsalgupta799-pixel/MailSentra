export type RiskTier = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'PENDING';
export type ScanStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'OPEN' | 'IN_TRIAGE' | 'RESOLVED' | 'FALSE_POSITIVE';
export type UserRole = 'SUPER_ADMIN' | 'SOC_ANALYST' | 'AUDITOR' | 'SYSTEM_AGENT';

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
  database_connected: boolean;
}

export interface ScanIncident {
  id: number;
  scan_uuid: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  status: ScanStatus;
  risk_score: number;
  risk_tier: RiskTier;
  verdict_summary: string | null;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_scanned: number;
  clean_count: number;
  suspicious_count: number;
  malicious_count: number;
  high_risk_findings_count: number;
  threat_detection_rate: number;
  active_alerts_count: number;
}

export interface ScanDetail extends ScanIncident {
  telemetry: Record<string, any>;
}

export interface SecurityAlert {
  id: number;
  scan_id: number | null;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  description: string;
  indicators: Record<string, unknown>;
  created_at: string;
}

export interface AuditRecord {
  id: number;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  status: string;
  ip_address: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface EmailAddress {
  raw: string;
  display_name: string | null;
  address: string;
  domain: string;
}

export interface LinkConsequences {
  threat_category: string;
  category_title: string;
  risk_summary: string;
  what_could_happen: string[];
  risk_distinctions: string[];
}

export interface PostClickGuidance {
  scenario: string;
  scenario_label: string;
  recommended_actions: string[];
  urgency_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface ExtractedUrl {
  original_url: string;
  normalized_url: string;
  defanged_url: string;
  visible_text: string | null;
  source_location: string;
  is_duplicate: boolean;
  occurrence_count: number;
  finding?: {
    severity: string;
    reason: string;
    is_ip_host?: boolean;
    is_suspicious_tld?: boolean;
    is_open_redirect?: boolean;
  } | null;
  consequences?: LinkConsequences | null;
  post_click_guidance?: PostClickGuidance[] | null;
}

export interface AttachmentMetadata {
  filename: string;
  original_filename: string;
  content_type: string;
  file_extension: string;
  is_double_extension: boolean;
  size_bytes: number;
  sha256_hash: string;
  content_disposition: string;
  content_id: string | null;
  is_inline: boolean;
}

export interface ReceivedHop {
  hop_number: number;
  raw: string;
  by: string | null;
  from_host: string | null;
  ip: string | null;
  protocol: string | null;
  date: string | null;
}

export interface ParsedEmail {
  message_id: string | null;
  subject: string | null;
  date_raw: string | null;
  date_utc: string | null;
  processing_timestamp: string;
  from_sender: EmailAddress | null;
  reply_to: EmailAddress | null;
  return_path: string | null;
  to_recipients: EmailAddress[];
  cc_recipients: EmailAddress[];
  bcc_recipients: EmailAddress[];
  received_hops: ReceivedHop[];
  body_plain: string | null;
  body_html: string | null;
  body_extracted_text: string | null;
  urls: ExtractedUrl[];
  attachments: AttachmentMetadata[];
  parsing_warnings: string[];
}

export interface EmailParseResponse {
  scan_id: number;
  scan_uuid: string;
  status: ScanStatus;
  parsed_email: ParsedEmail;
  created_at: string;
}

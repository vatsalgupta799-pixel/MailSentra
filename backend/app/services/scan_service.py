"""Scan orchestration service for ingestion, parsing, and telemetry persistence."""

import uuid
from typing import Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.audit import AuditLogger
from app.core.logging import logger
from app.models.scan import RiskTier, ScanIncident, ScanStatus
from app.models.user import User
from app.modules.contracts import IngestionSource, ParsedEmail, RawEmailPayload
from app.modules.ingestion.service import EmailIngestionService
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.parser.parser import EmailParser
from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.attachment_analysis.analyzer import AttachmentAnalyzer
from app.modules.risk_engine.engine import RiskEngine
from app.modules.contracts import TrustedSMTPMetadata


class ScanService:
    """Coordinates email ingestion, normalization, and relational incident storage."""

    def __init__(self):
        self.ingestion_service = EmailIngestionService()
        self.parser = EmailParser()
        self.identity_analyzer = SenderIdentityAnalyzer()
        self.auth_analyzer = AuthProtocolsAnalyzer()
        self.url_analyzer = UrlAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.risk_engine = RiskEngine()

    async def shutdown(self):
        """Closes all owned subsystem resources cleanly."""
        try:
            await self.auth_analyzer.shutdown()
        except Exception as e:
            logger.error(f"Error during AuthProtocolsAnalyzer shutdown: {e}")
        try:
            await self.url_analyzer.shutdown()
        except Exception as e:
            logger.error(f"Error during UrlAnalyzer shutdown: {e}")

    async def ingest_and_parse(
        self,
        raw_bytes: bytes,
        filename: Optional[str] = None,
        source: IngestionSource = IngestionSource.DIRECT_UPLOAD,
        source_ip: Optional[str] = None,
        tenant_id: str = "default",
        db: Optional[AsyncSession] = None,
        actor: Optional[User] = None,
        trusted_smtp_metadata: Optional[TrustedSMTPMetadata] = None,
    ) -> Tuple[ScanIncident, ParsedEmail]:
        """Ingests raw bytes, parses RFC 5322 data into ParsedEmail, and persists ScanIncident record."""
        # 1. Ingest & Validate
        raw_payload = self.ingestion_service.ingest(
            raw_bytes=raw_bytes,
            filename=filename,
            source=source,
            source_ip=source_ip,
            tenant_id=tenant_id,
        )

        # 2. Parse & Normalize
        parsed_email = self.parser.parse(raw_payload)

        # 3. Duplicate Message-ID Detection
        is_duplicate = False
        duplicate_ref_id = None
        if db and parsed_email.message_id:
            from sqlalchemy import select
            stmt = select(ScanIncident).where(ScanIncident.message_id == parsed_email.message_id).order_by(ScanIncident.id.asc())
            result = await db.execute(stmt)
            existing_incident = result.scalars().first()
            if existing_incident:
                is_duplicate = True
                duplicate_ref_id = existing_incident.id
                parsed_email.parsing_warnings.append(
                    f"Duplicate Message-ID detected: matches previous scan incident #{existing_incident.id} (UUID: {existing_incident.scan_uuid})"
                )

        # 4. Create Scan Incident Record (with column-bounded attributes to prevent DB truncate errors)
        scan_uuid = str(uuid.uuid4())
        sender_addr = parsed_email.from_sender.address if parsed_email.from_sender else None
        recipient_addr = (
            parsed_email.to_recipients[0].address if parsed_email.to_recipients else None
        )

        sender_col = sender_addr[:255] if sender_addr else None
        recipient_col = recipient_addr[:255] if recipient_addr else None
        subject_col = parsed_email.subject[:500] if parsed_email.subject else None
        message_id_col = parsed_email.message_id[:255] if parsed_email.message_id else None

        verdict_summary = "Email ingested and normalized successfully. Ready for threat analysis pipeline."
        if is_duplicate:
            verdict_summary += f" [DUPLICATE: Matches prior scan incident #{duplicate_ref_id}]"

        incident_telemetry = parsed_email.model_dump(mode="json")
        incident_telemetry["is_duplicate_message_id"] = is_duplicate
        incident_telemetry["duplicate_reference_scan_id"] = duplicate_ref_id

        # 4. Execute Sender Identity Analysis (Module 3)
        try:
            identity_result = await self.identity_analyzer.analyze(parsed_email)
            incident_telemetry["identity_analysis"] = identity_result.model_dump(mode="json")
        except Exception as e_ident:
            logger.error(f"Error during sender identity analysis: {str(e_ident)}", exc_info=True)
            incident_telemetry["identity_analysis"] = {
                "analysis_status": "FAILED",
                "error": "Sender identity analysis encountered an internal error and could not complete.",
                "envelope_header_match": None,
                "display_name_spoofed": False,
                "typosquatting_detected": False,
                "punycode_homoglyph_detected": False,
                "punycode_detected": False,
                "homoglyph_detected": False,
                "failed_rules": ["identity_analyzer"],
                "findings": [],
            }

        # 5. Execute Authentication Protocols Analysis (Module 4 / Step 3.7.3C)
        auth_result = None
        try:
            auth_result = await self.auth_analyzer.analyze(
                raw_payload=raw_payload,
                parsed_email=parsed_email,
                trusted_smtp_metadata=trusted_smtp_metadata,
                tenant_id=tenant_id,
                db=db,
            )
            incident_telemetry["auth_protocols"] = auth_result.model_dump(mode="json")
        except Exception as e_auth:
            logger.error(f"Error during authentication protocols analysis: {str(e_auth)}", exc_info=True)
            incident_telemetry["auth_protocols"] = {
                "analysis_status": "FAILED",
                "error": f"Authentication protocols analysis encountered an internal error: {str(e_auth)}",
                "spf_status": "NOT_EVALUATED",
                "dkim_status": "NONE",
                "dmarc_status": "NOT_EVALUATED",
                "failed_evaluators": ["auth_protocols_analyzer"],
            }

        # 6. Execute URL Security Analysis (Module 5 / Step 4.2)
        url_result = None
        try:
            url_result = await self.url_analyzer.analyze(parsed_email)
            incident_telemetry["url_analysis"] = url_result.model_dump(mode="json")

            # Map findings and consequence analysis back onto parsed_email.urls so the upload response and frontend have direct access
            if url_result and url_result.findings and parsed_email.urls:
                findings_by_url = {f.url: f for f in url_result.findings}
                for u in parsed_email.urls:
                    finding_match = findings_by_url.get(u.original_url) or findings_by_url.get(u.normalized_url)
                    if finding_match:
                        u.finding = finding_match.model_dump(mode="json")
                        u.consequences = finding_match.consequences
                        u.post_click_guidance = finding_match.post_click_guidance
                incident_telemetry["urls"] = [u.model_dump(mode="json") for u in parsed_email.urls]
        except Exception as e_url:
            logger.error(f"Error during URL security analysis: {str(e_url)}", exc_info=True)
            incident_telemetry["url_analysis"] = {
                "analysis_status": "FAILED",
                "error": f"URL analysis encountered an internal error: {str(e_url)}",
                "total_urls_scanned": 0,
                "highest_severity": "SAFE",
                "findings": [],
            }

        # 7. Execute Attachment Forensic Analysis (Module 6)
        attachment_result = None
        try:
            attachment_result = await self.attachment_analyzer.analyze(parsed_email, raw_payload=raw_payload)
            incident_telemetry["attachment_analysis"] = attachment_result.model_dump(mode="json")
        except Exception as e_att:
            logger.error(f"Error during attachment forensic analysis: {str(e_att)}", exc_info=True)
            incident_telemetry["attachment_analysis"] = {
                "analysis_status": "FAILED",
                "error": f"Attachment analysis encountered an internal error: {str(e_att)}",
                "total_attachments": len(parsed_email.attachments),
                "suspicious_count": 0,
                "malicious_count": 0,
                "highest_severity": "SAFE",
                "findings": [],
            }

        # 8. Risk Aggregation & Threat Classification (Risk Engine)
        risk_score, risk_tier, verdict_summary, risk_assessment = self.risk_engine.evaluate(
            identity_result=identity_result if 'identity_result' in locals() and hasattr(identity_result, 'findings') else None,
            auth_result=auth_result,
            url_result=url_result,
            attachment_result=attachment_result,
        )
        if is_duplicate:
            verdict_summary += f" [DUPLICATE: Matches prior scan incident #{duplicate_ref_id}]"
        incident_telemetry["risk_assessment"] = risk_assessment

        creator_user_id = getattr(getattr(actor, "user", None), "id", None) if actor else None
        incident = ScanIncident(
            scan_uuid=scan_uuid,
            sender=sender_col,
            recipient=recipient_col,
            subject=subject_col,
            message_id=message_id_col,
            status=ScanStatus.COMPLETED,
            tenant_id=tenant_id or "default",
            created_by_user_id=creator_user_id,
            risk_score=risk_score,
            risk_tier=risk_tier,
            verdict_summary=verdict_summary,
            telemetry=incident_telemetry,
        )

        if db:
            try:
                db.add(incident)
                await db.commit()
                await db.refresh(incident)
            except Exception as e:
                await db.rollback()
                logger.error(f"Database error while saving scan incident: {str(e)}")
                raise

            # Audit Trail (masking sensitive PII to prevent credential/data leaks)
            actor_id = getattr(actor, "identity", None) or getattr(actor, "email", None) or (source_ip or "system")
            audit_details = {
                "scan_uuid": scan_uuid,
                "filename": filename,
                "subject": (parsed_email.subject[:80] + "...") if parsed_email.subject and len(parsed_email.subject) > 80 else parsed_email.subject,
                "attachments_count": len(parsed_email.attachments),
                "urls_count": len(parsed_email.urls),
                "risk_tier": risk_tier.value,
                "risk_score": risk_score,
            }
            if "auth_protocols" in incident_telemetry:
                ap = incident_telemetry["auth_protocols"]
                audit_details["auth_spf"] = ap.get("spf_status")
                audit_details["auth_dkim"] = ap.get("dkim_status")
                audit_details["auth_dmarc"] = ap.get("dmarc_status")
                if isinstance(ap.get("dmarc_enforcement"), dict):
                    audit_details["dmarc_disposition"] = ap["dmarc_enforcement"].get("disposition")
            AuditLogger.log_event(
                actor_id=actor_id,
                action="EMAIL_INGESTED_AND_PARSED",
                resource_type="scan_incident",
                resource_id=str(incident.id),
                status="SUCCESS",
                ip_address=source_ip,
                details=audit_details,
            )

            # Persist immutable AuditRecord entity to database for compliance queries
            try:
                from app.models.audit import AuditRecord
                audit_record = AuditRecord(
                    actor_id=actor_id,
                    action="EMAIL_INGESTED_AND_PARSED",
                    resource_type="scan_incident",
                    resource_id=str(incident.id),
                    status="SUCCESS",
                    ip_address=source_ip,
                    details=audit_details,
                )
                db.add(audit_record)
                await db.commit()
            except Exception as e:
                logger.error(f"Failed to persist audit record to database: {str(e)}")

            # Generate security alert for qualifying findings (MALICIOUS or high-confidence threat signals)
            if risk_tier == RiskTier.MALICIOUS or risk_score >= 70.0:
                try:
                    from app.models.alert import Alert, AlertSeverity, AlertStatus
                    alert_severity = AlertSeverity.CRITICAL if risk_score >= 85.0 else AlertSeverity.HIGH
                    alert_title = f"High-Risk Email Threat Detected: {parsed_email.subject or 'Untitled'}"[:255]
                    alert_desc = f"Scan #{incident.id} flagged as {risk_tier.value} with Risk Score {risk_score}. {verdict_summary}"
                    alert_obj = Alert(
                        scan_id=incident.id,
                        title=alert_title,
                        severity=alert_severity,
                        status=AlertStatus.OPEN,
                        description=alert_desc,
                        indicators={
                            "scan_uuid": scan_uuid,
                            "sender": sender_col,
                            "risk_tier": risk_tier.value,
                            "risk_score": risk_score,
                            "signals": risk_assessment.get("contributing_signals", []) if isinstance(risk_assessment, dict) else [],
                        },
                    )
                    db.add(alert_obj)
                    await db.commit()
                except Exception as e_alert:
                    logger.error(f"Failed to create security alert for scan #{incident.id}: {str(e_alert)}")

        subj_len = len(parsed_email.subject) if parsed_email.subject else 0
        logger.info(
            f"Email parsed successfully (UUID: {scan_uuid}, SubjectLen: {subj_len}, Attachments: {len(parsed_email.attachments)}, URLs: {len(parsed_email.urls)})"
        )

        return incident, parsed_email

    async def shutdown(self) -> None:
        """Cleanly releases underlying resources for authentication analyzer and threat modules."""
        if hasattr(self, "auth_analyzer") and self.auth_analyzer:
            await self.auth_analyzer.shutdown()


scan_service = ScanService()

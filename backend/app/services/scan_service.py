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


class ScanService:
    """Coordinates email ingestion, normalization, and relational incident storage."""

    def __init__(self):
        self.ingestion_service = EmailIngestionService()
        self.parser = EmailParser()
        self.identity_analyzer = SenderIdentityAnalyzer()

    async def ingest_and_parse(
        self,
        raw_bytes: bytes,
        filename: Optional[str] = None,
        source: IngestionSource = IngestionSource.DIRECT_UPLOAD,
        source_ip: Optional[str] = None,
        tenant_id: str = "default",
        db: Optional[AsyncSession] = None,
        actor: Optional[User] = None,
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
            risk_score=0.0,
            risk_tier=RiskTier.PENDING,
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
            }
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

        subj_len = len(parsed_email.subject) if parsed_email.subject else 0
        logger.info(
            f"Email parsed successfully (UUID: {scan_uuid}, SubjectLen: {subj_len}, Attachments: {len(parsed_email.attachments)}, URLs: {len(parsed_email.urls)})"
        )

        return incident, parsed_email


scan_service = ScanService()

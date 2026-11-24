"""Audit logging helper for security and operational compliance."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.core.logging import logger


class AuditLogger:
    """Emits structured, append-only security audit log events."""

    @staticmethod
    def log_event(
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        status: str = "SUCCESS",
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "ip_address": ip_address or "internal",
            "details": details or {},
        }
        logger.info(f"AUDIT_EVENT: {json.dumps(event)}")
        return event

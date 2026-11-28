"""Acquisition module for authentic external dataset archives in MailSentra."""

import os
import ssl
import json
import hashlib
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class DatasetAcquisitionError(Exception):
    """Raised when an external dataset download or checksum verification fails."""
    pass


def download_file_with_checksum(
    url: str,
    target_path: str,
    user_agent: str = "MailSentra-DatasetAcquisition/1.0",
    expected_sha256: Optional[str] = None,
    timeout: int = 60
) -> Dict[str, Any]:
    """Downloads a file over HTTPS, streams directly to disk, computes SHA-256,
    and returns comprehensive download and verification metadata.
    """
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    temp_target = target_path + ".download.tmp"

    ssl_context = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": user_agent}
    )

    retrieval_timestamp = datetime.now(timezone.utc).isoformat()
    hasher = hashlib.sha256()
    total_bytes = 0

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
            http_status = response.status
            content_length_header = response.headers.get("Content-Length")
            expected_length = int(content_length_header) if content_length_header else None
            content_type = response.headers.get("Content-Type", "application/octet-stream")

            with open(temp_target, "wb") as f_out:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    hasher.update(chunk)
                    total_bytes += len(chunk)

        # Integrity verification
        if expected_length is not None and total_bytes != expected_length:
            if os.path.exists(temp_target):
                os.remove(temp_target)
            raise DatasetAcquisitionError(
                f"Byte count mismatch: received {total_bytes} bytes, expected {expected_length} bytes."
            )

        calculated_sha256 = hasher.hexdigest()
        if expected_sha256 and calculated_sha256.lower() != expected_sha256.lower():
            if os.path.exists(temp_target):
                os.remove(temp_target)
            raise DatasetAcquisitionError(
                f"SHA-256 mismatch for {url}: got {calculated_sha256}, expected {expected_sha256}"
            )

        # Atomically replace final file
        if os.path.exists(target_path):
            os.remove(target_path)
        os.rename(temp_target, target_path)

        metadata = {
            "source_url": url,
            "target_path": os.path.abspath(target_path),
            "retrieval_timestamp": retrieval_timestamp,
            "http_status": http_status,
            "content_type": content_type,
            "file_size_bytes": total_bytes,
            "sha256": calculated_sha256,
        }
        return metadata

    except Exception as e:
        if os.path.exists(temp_target):
            os.remove(temp_target)
        raise DatasetAcquisitionError(f"Failed to acquire {url}: {str(e)}") from e

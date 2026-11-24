"""Live API end-to-end verification script.

Tests:
1. GET /api/v1/health -> HTTP 200 & defensive security headers
2. POST /api/v1/scans/upload with a realistic synthetic fixture .eml
3. GET /api/v1/scans/{id} to retrieve persisted telemetry
4. Error handling: upload executable disguised as .eml -> HTTP 422
5. Error handling: invalid pagination query -> HTTP 422
"""

import asyncio
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpx import ASGITransport, AsyncClient
from main import app


async def main():
    print("=== MAILSENTRA LIVE END-TO-END VERIFICATION ===")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # 1. Health check & security headers
        print("\n[Step 1] Checking /api/v1/health and response security headers...")
        res = await client.get("/api/v1/health")
        print(f"Health Status Code: {res.status_code}")
        print(f"Health Response JSON: {res.json()}")
        print(f"Security Headers: X-Content-Type-Options={res.headers.get('x-content-type-options')}, X-Frame-Options={res.headers.get('x-frame-options')}")
        assert res.status_code == 200
        assert res.headers.get("x-content-type-options") == "nosniff"

        # 2. Upload realistic fixture .eml
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "real_world_emails", "normal", "01_university_announcement.eml"
        )
        print(f"\n[Step 2] Uploading realistic .eml fixture: {os.path.basename(fixture_path)}...")
        with open(fixture_path, "rb") as f:
            file_bytes = f.read()

        upload_res = await client.post(
            "/api/v1/scans/upload",
            files={"file": ("university_announcement.eml", file_bytes, "message/rfc822")},
        )
        print(f"Upload Status Code: {upload_res.status_code}")
        data = upload_res.json()
        scan_id = data["scan_id"]
        scan_uuid = data["scan_uuid"]
        parsed = data["parsed_email"]
        print(f"Scan Created: ID=#{scan_id}, UUID={scan_uuid}")
        print(f"Parsed Subject: '{parsed['subject']}'")
        print(f"Parsed Sender: {parsed['from_sender']['display_name']} <{parsed['from_sender']['address']}>")
        print(f"Received Hops Count: {len(parsed['received_hops'])}")
        print(f"Extracted URLs Count: {len(parsed['urls'])}")
        print(f"Attachments Count: {len(parsed['attachments'])}")
        assert upload_res.status_code == 201

        # 3. Retrieve persisted scan incident
        print(f"\n[Step 3] Retrieving persisted scan incident #{scan_id}...")
        get_res = await client.get(f"/api/v1/scans/{scan_id}")
        print(f"Get Status Code: {get_res.status_code}")
        scan_detail = get_res.json()
        print(f"Retrieved Scan: Subject='{scan_detail['subject']}', Status={scan_detail['status']}")
        assert get_res.status_code == 200
        assert scan_detail["id"] == scan_id

        # 4. Error Handling: Executable disguised as .eml
        print("\n[Step 4] Testing rejection of executable disguised as .eml...")
        fake_exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200
        err_res = await client.post(
            "/api/v1/scans/upload",
            files={"file": ("trojan.eml", fake_exe, "message/rfc822")},
        )
        print(f"Executable Upload Status Code: {err_res.status_code} (Expected: 422)")
        print(f"Rejection Detail: {err_res.json()['detail']}")
        assert err_res.status_code == 422

        # 5. Error Handling: Invalid pagination boundary
        print("\n[Step 5] Testing API query parameter boundary validation...")
        pag_res = await client.get("/api/v1/scans?limit=500")
        print(f"Excessive Limit Status Code: {pag_res.status_code} (Expected: 422)")
        assert pag_res.status_code == 422

    print("\n=== ALL LIVE END-TO-END VERIFICATION CHECKS PASSED SUCCESSFULLY ===")


if __name__ == "__main__":
    asyncio.run(main())

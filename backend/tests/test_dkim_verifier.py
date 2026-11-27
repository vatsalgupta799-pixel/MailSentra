"""Targeted tests for DKIM Verifier Service, cryptographic algorithms, and standards compliance.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Standards: RFC 6376, RFC 8301, RFC 8463
"""

import asyncio
import base64
from typing import Tuple
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import dkim
import nacl.signing

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import (
    DNSErrorType,
    DNSQueryType,
    DNSResponseStatus,
    MockDNSResolver,
)
from app.modules.auth_protocols.evaluators.dkim import DKIMVerifier
from app.modules.auth_protocols.executor import DKIMCapacityExhaustedError, DKIMExecutor
from app.modules.contracts import ProtocolStatus


def _generate_rsa_keypair(key_size: int = 1024) -> Tuple[bytes, str, str]:
    """Generates an RSA private key (PEM bytes), base64 public key, and DNS TXT record string."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    txt_record = f"v=DKIM1; k=rsa; p={pub_b64}"
    return priv_pem, pub_b64, txt_record


def _generate_512_rsa_pubkey() -> Tuple[str, str]:
    """Generates an invalid (sub-1024-bit) 512-bit RSA public key record."""
    pn = rsa.RSAPublicNumbers(65537, 2**511 + 1)
    pub = pn.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    txt_record = f"v=DKIM1; k=rsa; p={pub_b64}"
    return pub_b64, txt_record


def _generate_ed25519_keypair() -> Tuple[bytes, str, str]:
    """Generates an Ed25519 private key (b64 bytes), base64 public key, and DNS TXT record."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    priv_b64 = base64.b64encode(signing_key.encode())
    pub_b64 = base64.b64encode(verify_key.encode()).decode("ascii")
    txt_record = f"v=DKIM1; k=ed25519; p={pub_b64}"
    return priv_b64, pub_b64, txt_record


def _sign_message(
    message: bytes,
    selector: str,
    domain: str,
    privkey: bytes,
    signature_algorithm: bytes = b"rsa-sha256",
    canonicalize: Tuple[bytes, bytes] = (b"relaxed", b"relaxed"),
) -> bytes:
    """Signs an RFC 5322 message with dkimpy and prepends the DKIM-Signature header."""
    sig = dkim.dkim_sign(
        message=message,
        selector=selector.encode("ascii"),
        domain=domain.encode("ascii"),
        privkey=privkey,
        signature_algorithm=signature_algorithm,
        canonicalize=canonicalize,
    )
    return sig + message


@pytest.mark.asyncio
async def test_dkim_valid_rsa_1024_signature():
    """Verify standard RFC 6376 / RFC 8301 compliant RSA-1024 signature passes."""
    priv_pem, _, txt = _generate_rsa_keypair(1024)
    msg = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nTest body\r\n"
    signed_msg = _sign_message(msg, "s1024", "example.com", priv_pem, b"rsa-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("s1024._domainkey.example.com", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_msg, from_domain="example.com")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PASS
        assert res.algorithm == "rsa-sha256"
        assert res.domain == "example.com"
        assert res.selector == "s1024"
        assert res.key_size_bits == 1024
        assert res.is_aligned_with_from is True
        assert res.aligned_strict is True
        assert res.aligned_relaxed is True
        assert res.error_reason is None


@pytest.mark.asyncio
async def test_dkim_valid_rsa_2048_signature():
    """Verify RSA-2048 signature passes and records 2048 key size."""
    priv_pem, _, txt = _generate_rsa_keypair(2048)
    msg = b"From: sender@sub.corp.com\r\nTo: user@target.com\r\nSubject: Notice\r\n\r\nImportant message\r\n"
    signed_msg = _sign_message(msg, "k2048", "sub.corp.com", priv_pem, b"rsa-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("k2048._domainkey.sub.corp.com", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_msg, from_domain="sub.corp.com")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PASS
        assert res.key_size_bits == 2048
        assert res.is_aligned_with_from is True


@pytest.mark.asyncio
async def test_dkim_invalid_rsa_signature_tampered_body():
    """Verify body tampering after signing causes cryptographic verification to FAIL."""
    priv_pem, _, txt = _generate_rsa_keypair(1024)
    msg = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nOriginal body\r\n"
    signed_msg = _sign_message(msg, "s1", "example.com", priv_pem, b"rsa-sha256")

    # Tamper with the body
    tampered_msg = signed_msg.replace(b"Original body", b"Tampered body")

    resolver = MockDNSResolver()
    resolver.add_txt("s1._domainkey.example.com", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(tampered_msg, from_domain="example.com")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.FAIL
        assert "cryptographic signature verification failed" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_rsa_key_below_1024_bits_rejected():
    """Verify sub-1024-bit RSA key (RFC 8301 Section 3.2) is rejected with PERMERROR."""
    _, txt_512 = _generate_512_rsa_pubkey()
    priv_pem, _, _ = _generate_rsa_keypair(1024)
    msg = b"From: victim@target.com\r\nTo: attacker@evil.com\r\n\r\nTest\r\n"
    signed_msg = _sign_message(msg, "weak", "target.com", priv_pem, b"rsa-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("weak._domainkey.target.com", [txt_512])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_msg, from_domain="target.com")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PERMERROR
        assert res.key_size_bits == 512
        assert "minimum is 1024 bits" in res.error_reason


@pytest.mark.asyncio
async def test_dkim_valid_ed25519_signature():
    """Verify Ed25519 signature (RFC 8463) passes with key_size 256."""
    priv_b64, _, txt = _generate_ed25519_keypair()
    msg = b"From: modern@domain.org\r\nTo: dest@domain.org\r\nSubject: Ed25519\r\n\r\nEd25519 body\r\n"
    signed_msg = _sign_message(msg, "ed2026", "domain.org", priv_b64, b"ed25519-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("ed2026._domainkey.domain.org", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_msg, from_domain="domain.org")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PASS
        assert res.algorithm == "ed25519-sha256"
        assert res.key_size_bits == 256
        assert res.error_reason is None


@pytest.mark.asyncio
async def test_dkim_invalid_ed25519_signature_tampered():
    """Verify modified Ed25519 signature fails cryptographic verification."""
    priv_b64, _, txt = _generate_ed25519_keypair()
    msg = b"From: modern@domain.org\r\nTo: dest@domain.org\r\n\r\nOriginal content\r\n"
    signed_msg = _sign_message(msg, "ed2026", "domain.org", priv_b64, b"ed25519-sha256")

    tampered_msg = signed_msg.replace(b"Original content", b"Forged content")

    resolver = MockDNSResolver()
    resolver.add_txt("ed2026._domainkey.domain.org", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(tampered_msg, from_domain="domain.org")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.FAIL


@pytest.mark.asyncio
async def test_dkim_sha1_rejection():
    """Verify rsa-sha1 algorithm is rejected with PERMERROR per RFC 8301 Section 3.1."""
    priv_pem, _, txt = _generate_rsa_keypair(1024)
    msg = b"From: legacy@old.org\r\nTo: target@old.org\r\n\r\nLegacy message\r\n"
    signed_msg = _sign_message(msg, "sha1sel", "old.org", priv_pem, b"rsa-sha1")

    resolver = MockDNSResolver()
    resolver.add_txt("sha1sel._domainkey.old.org", [txt])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_msg, from_domain="old.org")

        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PERMERROR
        assert "rsa-sha1 disallowed by rfc 8301" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_canonicalization_combinations():
    """Verify simple/simple, relaxed/relaxed, and mixed canonicalization modes."""
    priv_pem, _, txt = _generate_rsa_keypair(1024)
    resolver = MockDNSResolver()
    resolver.add_txt("c._domainkey.example.com", [txt])

    modes = [
        ((b"simple", b"simple"), "simple/simple"),
        ((b"relaxed", b"relaxed"), "relaxed/relaxed"),
        ((b"relaxed", b"simple"), "relaxed/simple"),
        ((b"simple", b"relaxed"), "simple/relaxed"),
    ]

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        for (h_c, b_c), expected_canon in modes:
            msg = b"From: c@example.com\r\nTo: d@example.com\r\nSubject: Test\r\n\r\nCanon body\r\n"
            signed = _sign_message(
                msg,
                "c",
                "example.com",
                priv_pem,
                b"rsa-sha256",
                canonicalize=(h_c, b_c),
            )
            results = await verifier.verify(signed, from_domain="example.com")

            assert len(results) == 1
            assert results[0].status == ProtocolStatus.PASS
            assert results[0].canonicalization == expected_canon


@pytest.mark.asyncio
async def test_dkim_missing_signature_header():
    """Verify messages lacking DKIM-Signature headers return an empty list."""
    msg = b"From: nosig@domain.com\r\nTo: dest@domain.com\r\n\r\nPlain message without DKIM\r\n"
    resolver = MockDNSResolver()

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(msg, from_domain="domain.com")
        assert results == []

        proto_res = await verifier.evaluate_auth_protocol(msg, from_domain="domain.com")
        assert proto_res.dkim_status == ProtocolStatus.NONE
        assert proto_res.dkim_signatures == []


@pytest.mark.asyncio
async def test_dkim_malformed_signature_header():
    """Verify malformed DKIM-Signature header returns PERMERROR."""
    msg = (
        b"DKIM-Signature: malformed-tag-value;\r\n"
        b"From: mal@domain.com\r\n"
        b"To: dest@domain.com\r\n\r\n"
        b"Content\r\n"
    )
    resolver = MockDNSResolver()

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(msg, from_domain="domain.com")
        assert len(results) == 1
        assert results[0].status == ProtocolStatus.PERMERROR
        assert "malformed" in results[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_missing_public_key_record_nxdomain():
    """Verify NXDOMAIN on selector query maps to PERMERROR (RFC 6376 Section 6.1.4)."""
    priv_pem, _, _ = _generate_rsa_keypair(1024)
    msg = b"From: a@missing.com\r\nTo: b@missing.com\r\n\r\nBody\r\n"
    signed = _sign_message(msg, "absent", "missing.com", priv_pem, b"rsa-sha256")

    # No records in resolver => NXDOMAIN
    resolver = MockDNSResolver()

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed, from_domain="missing.com")
        assert len(results) == 1
        assert results[0].status == ProtocolStatus.PERMERROR
        assert "not found" in results[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_malformed_public_key_record():
    """Verify corrupted public key record returns PERMERROR."""
    priv_pem, _, _ = _generate_rsa_keypair(1024)
    msg = b"From: a@corrupt.com\r\nTo: b@corrupt.com\r\n\r\nBody\r\n"
    signed = _sign_message(msg, "s1", "corrupt.com", priv_pem, b"rsa-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("s1._domainkey.corrupt.com", ["v=DKIM1; k=rsa; p=NOT_VALID_BASE_64!@#$"])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed, from_domain="corrupt.com")
        assert len(results) == 1
        assert results[0].status == ProtocolStatus.PERMERROR
        assert "malformed" in results[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_multiple_public_key_records_rejected():
    """Verify multiple TXT records for one selector treated as invalid (RFC 6376 Section 3.6.2.2)."""
    priv_pem, _, txt1 = _generate_rsa_keypair(1024)
    _, _, txt2 = _generate_rsa_keypair(1024)
    msg = b"From: a@multikeys.com\r\nTo: b@multikeys.com\r\n\r\nBody\r\n"
    signed = _sign_message(msg, "multi", "multikeys.com", priv_pem, b"rsa-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("multi._domainkey.multikeys.com", [txt1, txt2])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed, from_domain="multikeys.com")
        assert len(results) == 1
        assert results[0].status == ProtocolStatus.PERMERROR
        assert "multiple dkim key records" in results[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_dns_transient_error_timeout_and_servfail():
    """Verify DNS timeout and SERVFAIL map to TEMPERROR without confusing cryptographic failure."""
    priv_pem, _, _ = _generate_rsa_keypair(1024)
    msg = b"From: a@timeout.com\r\nTo: b@timeout.com\r\n\r\nBody\r\n"
    signed = _sign_message(msg, "s1", "timeout.com", priv_pem, b"rsa-sha256")

    # 1. Timeout
    resolver = MockDNSResolver()
    resolver.set_error(
        "s1._domainkey.timeout.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
        message="DNS query timed out",
    )

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        res_timeout = await verifier.verify(signed, from_domain="timeout.com")
        assert len(res_timeout) == 1
        assert res_timeout[0].status == ProtocolStatus.TEMPERROR
        assert "dns transient error" in res_timeout[0].error_reason.lower()

    # 2. SERVFAIL
    resolver.set_error(
        "s1._domainkey.timeout.com",
        status=DNSResponseStatus.SERVFAIL,
        error_type=DNSErrorType.SERVFAIL,
        query_type=DNSQueryType.TXT,
        message="Server failure",
    )

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        res_servfail = await verifier.verify(signed, from_domain="timeout.com")
        assert len(res_servfail) == 1
        assert res_servfail[0].status == ProtocolStatus.TEMPERROR
        assert "dns transient error" in res_servfail[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_multiple_signatures_both_valid():
    """Verify multiple valid DKIM signatures on one message are independently evaluated and PASS."""
    priv1, _, txt1 = _generate_rsa_keypair(1024)
    priv2, _, txt2 = _generate_ed25519_keypair()

    msg = b"From: sender@example.com\r\nTo: user@target.com\r\nSubject: Multi\r\n\r\nBody text\r\n"
    sig1_msg = _sign_message(msg, "s_rsa", "example.com", priv1, b"rsa-sha256")
    sig12_msg = _sign_message(sig1_msg, "s_ed", "mailservice.net", priv2, b"ed25519-sha256")

    resolver = MockDNSResolver()
    resolver.add_txt("s_rsa._domainkey.example.com", [txt1])
    resolver.add_txt("s_ed._domainkey.mailservice.net", [txt2])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(sig12_msg, from_domain="example.com")
        assert len(results) == 2

        algos = {r.algorithm for r in results}
        assert algos == {"rsa-sha256", "ed25519-sha256"}
        assert all(r.status == ProtocolStatus.PASS for r in results)

        proto_res = await verifier.evaluate_auth_protocol(sig12_msg, from_domain="example.com")
        assert proto_res.dkim_status == ProtocolStatus.PASS
        assert proto_res.dmarc_aligned_dkim is True


@pytest.mark.asyncio
async def test_dkim_multiple_signatures_one_fails_one_passes():
    """Verify one signature failing does not prevent another valid signature from passing."""
    priv1, _, txt1 = _generate_rsa_keypair(1024)
    priv2, _, txt2 = _generate_ed25519_keypair()

    msg = b"From: sender@example.com\r\nTo: user@target.com\r\n\r\nContent\r\n"
    signed_rsa = _sign_message(msg, "s_rsa", "example.com", priv1, b"rsa-sha256")
    signed_both = _sign_message(signed_rsa, "s_ed", "attacker.com", priv2, b"ed25519-sha256")

    # attacker.com gets invalid key, example.com gets valid key
    resolver = MockDNSResolver()
    resolver.add_txt("s_rsa._domainkey.example.com", [txt1])
    resolver.add_txt("s_ed._domainkey.attacker.com", ["v=DKIM1; k=ed25519; p=INVALID_ED25519_KEY"])

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed_both, from_domain="example.com")
        assert len(results) == 2

        statuses = {r.domain: r.status for r in results}
        assert statuses["example.com"] == ProtocolStatus.PASS
        assert statuses["attacker.com"] == ProtocolStatus.PERMERROR

        proto_res = await verifier.evaluate_auth_protocol(signed_both, from_domain="example.com")
        assert proto_res.dkim_status == ProtocolStatus.PASS
        assert proto_res.dkim_domain == "example.com"
        assert proto_res.dmarc_aligned_dkim is True


@pytest.mark.asyncio
async def test_dkim_missing_raw_message_bytes():
    """Verify missing raw message bytes returns PERMERROR without attempting reconstructed parsing."""
    resolver = MockDNSResolver()

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        res_none = await verifier.verify(None)
        assert len(res_none) == 1
        assert res_none[0].status == ProtocolStatus.PERMERROR
        assert "missing original raw message bytes" in res_none[0].error_reason.lower()

        res_empty = await verifier.verify(b"")
        assert len(res_empty) == 1
        assert res_empty[0].status == ProtocolStatus.PERMERROR
        assert "missing original raw message bytes" in res_empty[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_alignment_relaxed_and_strict():
    """Verify strict vs relaxed alignment rules between d= tag and From header."""
    priv, _, txt = _generate_rsa_keypair(1024)
    resolver = MockDNSResolver()
    resolver.add_txt("s._domainkey.example.com", [txt])

    msg = b"From: user@sub.example.com\r\nTo: dest@target.com\r\n\r\nAlignment test\r\n"
    signed = _sign_message(msg, "s", "example.com", priv, b"rsa-sha256")

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        results = await verifier.verify(signed, from_domain="sub.example.com")
        assert len(results) == 1
        res = results[0]
        assert res.status == ProtocolStatus.PASS
        assert res.aligned_strict is False
        assert res.aligned_relaxed is True
        assert res.is_aligned_with_from is True


@pytest.mark.asyncio
async def test_dkim_concurrent_verifications_state_isolation():
    """Verify concurrent verifications do not share mutable state or cross-contaminate."""
    priv1, _, txt1 = _generate_rsa_keypair(1024)
    priv2, _, txt2 = _generate_ed25519_keypair()

    resolver = MockDNSResolver()
    resolver.add_txt("s1._domainkey.site1.com", [txt1])
    resolver.add_txt("s2._domainkey.site2.org", [txt2])

    msg1 = _sign_message(b"From: a@site1.com\r\n\r\nBody 1\r\n", "s1", "site1.com", priv1, b"rsa-sha256")
    msg2 = _sign_message(b"From: b@site2.org\r\n\r\nBody 2\r\n", "s2", "site2.org", priv2, b"ed25519-sha256")

    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        tasks = []
        for i in range(10):
            if i % 2 == 0:
                tasks.append(verifier.verify(msg1, from_domain="site1.com"))
            else:
                tasks.append(verifier.verify(msg2, from_domain="site2.org"))

        results = await asyncio.gather(*tasks)
        for i, res_list in enumerate(results):
            assert len(res_list) == 1
            res = res_list[0]
            assert res.status == ProtocolStatus.PASS
            if i % 2 == 0:
                assert res.domain == "site1.com"
                assert res.algorithm == "rsa-sha256"
            else:
                assert res.domain == "site2.org"
                assert res.algorithm == "ed25519-sha256"


@pytest.mark.asyncio
async def test_dkim_executor_exhaustion_maps_to_temperror():
    """Verify executor capacity exhaustion maps to TEMPERROR without crash."""
    priv, _, txt = _generate_rsa_keypair(1024)
    resolver = MockDNSResolver()
    resolver.add_txt("s._domainkey.example.com", [txt])
    msg = _sign_message(b"From: a@example.com\r\n\r\nBody\r\n", "s", "example.com", priv, b"rsa-sha256")

    # Mock executor with 0 capacity so submit always raises DKIMCapacityExhaustedError
    class _ExhaustedExecutor:
        async def submit(self, *args, **kwargs):
            raise DKIMCapacityExhaustedError("Capacity 0 exhausted")

    verifier = DKIMVerifier(dns_resolver=resolver, executor=_ExhaustedExecutor())
    results = await verifier.verify(msg, from_domain="example.com")

    assert len(results) == 1
    assert results[0].status == ProtocolStatus.TEMPERROR
    assert "unavailable or timed out" in results[0].error_reason.lower()


@pytest.mark.asyncio
async def test_dkim_unexpected_worker_exception_returns_indeterminate_not_fail():
    """Step 3.7.3B: Unexpected software errors in DKIM verification never become cryptographic FAIL."""
    priv, _, txt = _generate_rsa_keypair(1024)
    resolver = MockDNSResolver()
    resolver.add_txt("s._domainkey.example.com", [txt])
    msg = _sign_message(b"From: a@example.com\r\n\r\nBody\r\n", "s", "example.com", priv, b"rsa-sha256")

    class _BrokenExecutor:
        async def submit(self, *args, **kwargs):
            raise RuntimeError("Simulated unexpected internal worker crash")

    verifier = DKIMVerifier(dns_resolver=resolver, executor=_BrokenExecutor())
    results = await verifier.verify(msg, from_domain="example.com")
    assert len(results) == 1
    assert results[0].status == ProtocolStatus.INDETERMINATE
    assert "internal verification exception" in (results[0].error_reason or "").lower()

    auth_res = await verifier.evaluate_auth_protocol(msg, from_domain="example.com")
    assert auth_res.dkim_status == ProtocolStatus.INDETERMINATE


@pytest.mark.asyncio
async def test_h3_dkim_dns_error_categories_never_become_false_permerror():
    """H3: DNS transport/refused/formerr map to TEMPERROR and INVALID_QUERY maps to INDETERMINATE."""
    priv, _, _ = _generate_rsa_keypair(1024)
    msg = _sign_message(b"From: a@example.com\r\n\r\nBody\r\n", "s", "example.com", priv, b"rsa-sha256")

    # 1. RESOLVER_ERROR, REFUSED, FORMERR -> TEMPERROR (never PERMERROR)
    for err_setter in ("set_resolver_error", "set_refused", "set_formerr"):
        resolver = MockDNSResolver()
        getattr(resolver, err_setter)("s._domainkey.example.com", DNSQueryType.TXT)
        async with DKIMVerifier(dns_resolver=resolver) as verifier:
            res = await verifier.verify(msg, from_domain="example.com")
            assert len(res) == 1
            assert res[0].status == ProtocolStatus.TEMPERROR, f"Expected TEMPERROR for {err_setter}"

    # 2. INVALID_QUERY -> INDETERMINATE (never PERMERROR)
    resolver_inv = MockDNSResolver()
    resolver_inv.set_invalid_query("s._domainkey.example.com", DNSQueryType.TXT)
    async with DKIMVerifier(dns_resolver=resolver_inv) as verifier:
        res_inv = await verifier.verify(msg, from_domain="example.com")
        assert len(res_inv) == 1
        assert res_inv[0].status == ProtocolStatus.INDETERMINATE

    # 3. Genuine NXDOMAIN -> PERMERROR preserved
    resolver_nx = MockDNSResolver()
    resolver_nx.set_nxdomain("s._domainkey.example.com")
    async with DKIMVerifier(dns_resolver=resolver_nx) as verifier:
        res_nx = await verifier.verify(msg, from_domain="example.com")
        assert len(res_nx) == 1
        assert res_nx[0].status == ProtocolStatus.PERMERROR


@pytest.mark.asyncio
async def test_m4_dkim_headerprep_internal_exception_returns_indeterminate_not_permerror(monkeypatch):
    """M4: Unexpected runtime failures in verify_headerprep become INDETERMINATE without leaking sensitive data."""
    import dkim as dkim_lib

    priv, _, txt = _generate_rsa_keypair(1024)
    resolver = MockDNSResolver()
    resolver.add_txt("s._domainkey.example.com", [txt])
    msg = _sign_message(b"From: a@example.com\r\nSubject: SecretTokenXYZ\r\n\r\nSecretBody\r\n", "s", "example.com", priv, b"rsa-sha256")

    def _crashing_headerprep(self, idx=0):
        raise RuntimeError("INTERNAL_SECRET_DO_NOT_LEAK SecretBody")

    monkeypatch.setattr(dkim_lib.DKIM, "verify_headerprep", _crashing_headerprep)
    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        res = await verifier.verify(msg, from_domain="example.com")
        assert len(res) == 1
        assert res[0].status == ProtocolStatus.INDETERMINATE
        assert "RuntimeError" in (res[0].error_reason or "")
        assert "INTERNAL_SECRET_DO_NOT_LEAK" not in (res[0].error_reason or "")
        assert "SecretBody" not in (res[0].error_reason or "")

    # Genuine malformed signature syntax still returns PERMERROR
    monkeypatch.undo()
    malformed_msg = b"DKIM-Signature: v=1; broken_garbage_no_tags\r\nFrom: a@example.com\r\n\r\nBody\r\n"
    async with DKIMVerifier(dns_resolver=MockDNSResolver()) as verifier2:
        res_bad = await verifier2.verify(malformed_msg, from_domain="example.com")
        assert len(res_bad) == 1
        assert res_bad[0].status == ProtocolStatus.PERMERROR


@pytest.mark.asyncio
async def test_h3_dkim_async_resolver_os_socket_runtime_and_psl_alignment_flags():
    """H3 + L2: Real AsyncDNSResolver OS/socket/runtime error propagation and standalone PSL diagnostic markers."""
    import socket
    import dns.resolver
    from app.modules.auth_protocols.dns_resolver import AsyncDNSResolver

    priv, _, txt = _generate_rsa_keypair(1024)
    msg = _sign_message(b"From: a@example.com\r\n\r\nBody\r\n", "s", "example.com", priv, b"rsa-sha256")

    async_res = AsyncDNSResolver()
    async with DKIMVerifier(dns_resolver=async_res) as verifier:
        for exc_obj, expected_status in (
            (OSError("network fail"), ProtocolStatus.TEMPERROR),
            (ConnectionError("conn aborted"), ProtocolStatus.TEMPERROR),
            (socket.gaierror(-2, "dns sock fail"), ProtocolStatus.TEMPERROR),
            (TimeoutError("socket timeout"), ProtocolStatus.TEMPERROR),
            (dns.resolver.NoNameservers(), ProtocolStatus.TEMPERROR),
            (RuntimeError("unexpected runtime error"), ProtocolStatus.INDETERMINATE),
            (dns.resolver.YXDOMAIN(), ProtocolStatus.INDETERMINATE),
            (dns.resolver.NXDOMAIN(), ProtocolStatus.PERMERROR),
            (dns.resolver.NoAnswer(), ProtocolStatus.PERMERROR),
        ):
            async_res.cache.clear()

            async def _boom_dkim(name, rdtype, _e=exc_obj):
                raise _e

            async_res._resolver.resolve = _boom_dkim  # type: ignore[method-assign]
            res_list = await verifier.verify(msg, from_domain="example.com")
            assert len(res_list) == 1
            assert res_list[0].status == expected_status, f"Expected {expected_status} for {type(exc_obj).__name__}"

    # Verify standalone DKIMVerifier marks PSL alignment explicitly non-authoritative
    mock_ok = MockDNSResolver()
    mock_ok.add_txt("s._domainkey.example.com", [txt])
    async with DKIMVerifier(dns_resolver=mock_ok) as verifier_ok:
        auth_out = await verifier_ok.evaluate_auth_protocol(msg, from_domain="sub.example.com")
        assert auth_out.dkim_signatures[0].alignment_source == "standalone_psl_diagnostic_only"
        assert auth_out.dkim_signatures[0].alignment_is_authoritative is False
        assert auth_out.dkim_signatures[0].standalone_psl_aligned_relaxed is True
        assert auth_out.execution_telemetry["dkim_alignment_authoritative"] is False


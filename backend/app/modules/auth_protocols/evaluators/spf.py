"""RFC 7208-compliant Asynchronous SPF (Sender Policy Framework) Evaluator.

Implements:
- Strict trusted transport metadata boundary (no header-inferred client IPs).
- Global 10-term DNS query limit with recursive accounting.
- MX subordinate 10-address record limit with PERMERROR enforcement (per MX host).
- PTR subordinate 10-address record limit with excess record suppression.
- Direct global accounting of queried PTR resource records per REV13.
- Family-aware DNS lookups (A for IPv4, AAAA for IPv6).
- Configurable void-lookup budget (default max 2).
- Full qualifier support (+, -, ~, ?) and mechanisms (all, ip4, ip6, a, mx, ptr, exists, include).
- Modifiers: redirect= with cycle detection and 'all' override, exp= with duplicate detection.
- Safe UTS #46 nontransitional domain normalization.
- Safe handling of null reverse-path (HELO identity fallback per RFC 7208 Section 2.4).
- Macro support: %s, %l, %o, %d, %i, %v, %h, %%, %-, %_.
- Macro & Modifier Limitations:
  * Macro %{p} (validated reverse domain of client IP): Deliberately unsupported per MailSentra
    security architecture (RFC 7208 Sections 5.5 and 7.1 warn of high cost, latency, and fragility);
    evaluates to INDETERMINATE, never PASS or FAIL.
  * Modifier exp= (explanation): Parsed for syntactic validity and duplicate detection (duplicate
    exp= produces PERMERROR per RFC 7208 Section 6.2); external DNS fetching of explanation strings
    is intentionally not executed over the network to prevent outbound amplification and SSRF vectors.
"""

from dataclasses import dataclass, field
import asyncio
import ipaddress
import re
from typing import List, Optional, Set, Tuple, Union
import urllib.parse

import idna

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import (
    BaseDNSResolver,
    DNSErrorType,
    DNSQueryType,
    DNSResponse,
    DNSResponseStatus,
)
from app.modules.contracts import ProtocolStatus, SPFResult, TrustedSMTPMetadata


@dataclass
class _SPFEvaluationContext:
    """Internal evaluation context tracking shared global budgets across recursive calls."""

    client_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    sender_domain: str
    mail_from: str
    helo_domain: str
    config: AuthProtocolsConfig
    resolver: BaseDNSResolver
    dns_terms_queried: int = 0
    void_lookups: int = 0
    mechanisms_evaluated: int = 0
    active_recursion_stack: Set[str] = field(default_factory=set)
    current_recursion_depth: int = 0
    evaluated_records: List[str] = field(default_factory=list)


class SPFEvaluator:
    """Asynchronous, bounded RFC 7208 SPF policy evaluator."""

    def __init__(
        self,
        resolver: BaseDNSResolver,
        config: Optional[AuthProtocolsConfig] = None,
    ):
        self.resolver = resolver
        self.config = config or AuthProtocolsConfig()

    def normalize_domain(self, domain: str) -> str:
        """Normalizes a domain string using UTS #46 Nontransitional processing for IDN labels,
        preserving standard DNS protocol underscores (e.g. _spf, _dmarc, _domainkey).
        Enforces RFC 7208 Section 7.1 / RFC 1035 max length limits (253 total, 63 per label).
        """
        cleaned = domain.strip().rstrip(".")
        if not cleaned:
            raise ValueError("Domain cannot be empty")
        if len(cleaned) > 253:
            raise ValueError(f"Domain name exceeds RFC 7208 limit of 253 characters ({len(cleaned)})")
        labels = cleaned.split(".")
        encoded_labels: List[str] = []
        for label in labels:
            if not label:
                raise ValueError("Empty label in domain")
            if len(label) > 63:
                raise ValueError(f"Domain label exceeds RFC 7208 limit of 63 characters ({len(label)})")
            # If purely ASCII, preserve valid DNS characters (including underscores) in lowercase
            if all(ord(c) < 128 for c in label):
                if not re.match(r"^[a-zA-Z0-9_\-]+$", label):
                    raise ValueError(f"Invalid characters in DNS label: {label}")
                encoded_labels.append(label.lower())
            else:
                encoded_labels.append(
                    idna.encode(label, uts46=True, transitional=False).decode("ascii").lower()
                )
        res = ".".join(encoded_labels)
        if len(res) > 253:
            raise ValueError(f"Domain name exceeds RFC 7208 limit of 253 characters after encoding ({len(res)})")
        return res

    def validate_macro_syntax(
        self, text: str
    ) -> Tuple[bool, Optional[ProtocolStatus], Optional[str]]:
        """Validates RFC 7208 Section 7 macro syntax, transformers, delimiters, and escape sequences.

        Returns:
            (True, None, None) if syntax is valid.
            (False, ProtocolStatus.PERMERROR, reason) if malformed or illegal syntax.
            (False, ProtocolStatus.INDETERMINATE, reason) if unsupported macro %{p} is used.
        """
        if "%" not in text:
            return True, None, None

        # 1. Replace valid escape sequences: %%, %_, %-
        # RFC 7208 Section 7.1:
        # '%%' produces literal '%'
        # '%_' produces literal ' '
        # '%-' produces URL-encoded space '%20'
        cleaned = (
            text.replace("%%", "\x00ESC_PCT\x00")
            .replace("%_", "\x00ESC_SPC\x00")
            .replace("%-", "\x00ESC_20\x00")
        )

        # 2. Reject unbraced macros (e.g. %d, %s, %i, %x, or lone %)
        # RFC 7208 Section 7.1: All macro letters MUST be enclosed in '%{...}'.
        # Unbraced forms like %d, %s are strictly illegal.
        if re.search(r"%(?!\{)", cleaned):
            return (
                False,
                ProtocolStatus.PERMERROR,
                f"Invalid unbraced macro or escape syntax in '{text}'",
            )

        # 3. Check for unclosed or malformed braces:
        # e.g. %{s without closing }, or nested %{...%{...
        if re.search(r"%\{[^}]*$", cleaned) or re.search(r"%\{[^}]*%\{", cleaned):
            return (
                False,
                ProtocolStatus.PERMERROR,
                f"Malformed or unclosed macro brace in '{text}'",
            )

        # 4. Validate all delimited macros %{...}
        matches = list(re.finditer(r"%\{([^}]*)\}", cleaned))
        if not matches:
            return (
                False,
                ProtocolStatus.PERMERROR,
                f"Malformed macro syntax in '{text}'",
            )

        for match in matches:
            content = match.group(1)
            if not content:
                return (
                    False,
                    ProtocolStatus.PERMERROR,
                    "Empty macro expression '%{}'",
                )

            # Match against RFC 7208 Section 7.1 ABNF:
            # macro-letter transformers *delimiter
            # transformers = [ *DIGIT ] [ "r" ]
            # delimiter = "." / "-" / "+" / "," / "/" / "_" / "="
            m_spec = re.match(
                r"^([a-zA-Z])(\d*)([rR])?([\.\-+,\/_\=]*)$", content
            )
            if not m_spec:
                return (
                    False,
                    ProtocolStatus.PERMERROR,
                    f"Malformed macro transformer or delimiter syntax in '%{{{content}}}'",
                )

            letter, digits_str, reverse_flag, delimiters = m_spec.groups()
            letter_lower = letter.lower()

            # Letter validation
            if letter_lower == "p":
                return (
                    False,
                    ProtocolStatus.INDETERMINATE,
                    "Macro %{p} is unsupported per MailSentra security architecture",
                )
            if letter_lower in ("c", "r", "t"):
                return (
                    False,
                    ProtocolStatus.PERMERROR,
                    f"Macro '%{{{letter}}}' is reserved for explanation records and not permitted in domain-spec",
                )
            if letter_lower not in ("s", "l", "o", "d", "i", "v", "h"):
                return (
                    False,
                    ProtocolStatus.PERMERROR,
                    f"Unknown macro letter '%{{{letter}}}' in '%{{{content}}}'",
                )

            # Numeric transformer validation: RFC 7208 Section 7.2:
            # "A non-negative integer: indicates the number of right-hand parts to keep.
            # If 0, it is a syntax error."
            if digits_str:
                if int(digits_str) == 0:
                    return (
                        False,
                        ProtocolStatus.PERMERROR,
                        f"Invalid zero numeric transformer in '%{{{content}}}'",
                    )

        return True, None, None

    async def evaluate(
        self,
        domain: Optional[str] = None,
        smtp_metadata: Optional[TrustedSMTPMetadata] = None,
        scope: str = "mfrom",
    ) -> SPFResult:
        """Evaluates SPF for the given domain and scope using trusted transport metadata.

        Args:
            domain: Explicit sender domain (optional, defaults to envelope sender domain).
            smtp_metadata: Trusted transport metadata from MTA connector.
            scope: "mfrom" (MAIL FROM) or "helo" (HELO/EHLO identity).

        Returns:
            SPFResult strongly typed outcome.
        """
        # 1. Enforce Trusted Transport Metadata Boundary
        if smtp_metadata is None or not smtp_metadata.is_trusted_mta:
            return SPFResult(
                status=ProtocolStatus.NOT_EVALUATED,
                domain=domain,
                scope=scope,
                error_reason="Missing or unverified trusted SMTP transport metadata; direct upload",
            )

        if not smtp_metadata.connecting_ip:
            return SPFResult(
                status=ProtocolStatus.NOT_EVALUATED,
                domain=domain,
                scope=scope,
                error_reason="Missing connecting IP in trusted SMTP metadata",
            )

        try:
            client_ip = ipaddress.ip_address(smtp_metadata.connecting_ip.strip())
        except ValueError as e:
            return SPFResult(
                status=ProtocolStatus.PERMERROR,
                domain=domain,
                scope=scope,
                client_ip=smtp_metadata.connecting_ip,
                error_reason=f"Malformed connecting IP address: {e}",
            )

        # 2. Determine Scope and Evaluation Domain (Handling Null Reverse-Path per RFC 7208 Section 2.4)
        raw_mail_from = smtp_metadata.mail_from_envelope or ""
        clean_mf = raw_mail_from.strip()
        helo = (smtp_metadata.helo_domain or "").strip()

        target_domain = domain
        requested_scope = scope.lower().strip()
        is_synthesized_mfrom = False
        is_standalone_helo = False

        # Check for genuinely empty reverse-path: "" or "<>"
        is_null_reverse_path = (not clean_mf or clean_mf == "<>")

        if requested_scope == "mfrom":
            if is_null_reverse_path:
                # RFC 7208 Section 2.4: Null reverse-path falls back to HELO identity.
                # The identity local-part is 'postmaster', domain is <helo>.
                effective_scope = "helo"
                is_synthesized_mfrom = True
                if not helo:
                    return SPFResult(
                        status=ProtocolStatus.NONE,
                        domain=None,
                        scope="helo",
                        identity=None,
                        is_null_reverse_path=True,
                        is_synthesized_mfrom=True,
                        is_standalone_helo=False,
                        client_ip=str(client_ip),
                        error_reason="Null reverse-path without HELO identity cannot be evaluated",
                    )
                target_domain = helo
                mail_from = f"postmaster@{helo}"
            else:
                effective_scope = "mfrom"
                is_null_reverse_path = False
                mail_from = clean_mf
                if not target_domain:
                    clean_str = clean_mf.strip("<> ")
                    if "@" in clean_str:
                        target_domain = clean_str.split("@")[-1].strip()
                    else:
                        target_domain = clean_str
        else:
            # Explicit standalone scope == "helo"
            effective_scope = "helo"
            is_standalone_helo = True
            is_synthesized_mfrom = False
            is_null_reverse_path = False
            if not target_domain:
                target_domain = helo
            mail_from = f"postmaster@{helo}" if helo else ""

        if not target_domain:
            return SPFResult(
                status=ProtocolStatus.NONE,
                domain=None,
                scope=effective_scope,
                identity=mail_from or None,
                is_null_reverse_path=is_null_reverse_path,
                is_synthesized_mfrom=is_synthesized_mfrom,
                is_standalone_helo=is_standalone_helo,
                client_ip=str(client_ip),
                error_reason="No evaluation domain could be determined from envelope sender or HELO",
            )

        try:
            normalized_domain = self.normalize_domain(target_domain)
        except Exception as e:
            return SPFResult(
                status=ProtocolStatus.PERMERROR,
                domain=target_domain,
                scope=effective_scope,
                identity=mail_from or None,
                is_null_reverse_path=is_null_reverse_path,
                is_synthesized_mfrom=is_synthesized_mfrom,
                is_standalone_helo=is_standalone_helo,
                client_ip=str(client_ip),
                error_reason=f"Invalid or malformed domain name: {e}",
            )

        # 3. Create Shared Context and Run Core Evaluation
        ctx = _SPFEvaluationContext(
            client_ip=client_ip,
            sender_domain=normalized_domain,
            mail_from=mail_from,
            helo_domain=helo,
            config=self.config,
            resolver=self.resolver,
        )

        try:
            status, reason = await self._evaluate_domain(normalized_domain, ctx)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return SPFResult(
                status=ProtocolStatus.INDETERMINATE,
                domain=normalized_domain,
                scope=effective_scope,
                identity=mail_from or None,
                is_null_reverse_path=is_null_reverse_path,
                is_synthesized_mfrom=is_synthesized_mfrom,
                is_standalone_helo=is_standalone_helo,
                mechanisms_evaluated=ctx.mechanisms_evaluated,
                dns_terms_queried=ctx.dns_terms_queried,
                void_lookups=ctx.void_lookups,
                client_ip=str(client_ip),
                error_reason=f"SPF internal evaluation error ({type(exc).__name__})",
            )

        evaluated_record = ctx.evaluated_records[0] if ctx.evaluated_records else None

        return SPFResult(
            status=status,
            domain=normalized_domain,
            scope=effective_scope,
            identity=mail_from or None,
            is_null_reverse_path=is_null_reverse_path,
            is_synthesized_mfrom=is_synthesized_mfrom,
            is_standalone_helo=is_standalone_helo,
            evaluated_record=evaluated_record,
            mechanisms_evaluated=ctx.mechanisms_evaluated,
            dns_terms_queried=ctx.dns_terms_queried,
            void_lookups=ctx.void_lookups,
            client_ip=str(client_ip),
            error_reason=reason,
        )

    async def _evaluate_domain(
        self, domain: str, ctx: _SPFEvaluationContext
    ) -> Tuple[ProtocolStatus, Optional[str]]:
        """Evaluates SPF policy for a specific domain within the shared global context."""
        # Active recursion stack loop protection (RFC 7208)
        if domain in ctx.active_recursion_stack:
            return ProtocolStatus.PERMERROR, f"Recursive SPF include/redirect loop detected for domain: {domain}"

        if ctx.current_recursion_depth >= 10:
            return ProtocolStatus.PERMERROR, "Maximum SPF recursion depth of 10 exceeded"

        ctx.active_recursion_stack.add(domain)
        ctx.current_recursion_depth += 1
        try:
            return await self._evaluate_domain_inner(domain, ctx)
        finally:
            ctx.active_recursion_stack.remove(domain)
            ctx.current_recursion_depth -= 1

    @staticmethod
    def _classify_dns_failure(
        resp: DNSResponse, target: str
    ) -> Tuple[Optional[ProtocolStatus], Optional[str]]:
        """Maps non-void DNS resolver failures explicitly without falling through to NONE."""
        if resp.is_transient_error or resp.is_malformed_response:
            msg = resp.error_message or resp.status.value
            return ProtocolStatus.TEMPERROR, f"DNS transient error querying {target}: {msg}"
        if resp.is_invalid_query or resp.is_internal_error or resp.status == DNSResponseStatus.ERROR:
            msg = resp.error_message or resp.status.value
            return ProtocolStatus.INDETERMINATE, f"DNS invalid query or internal resolver error for {target}: {msg}"
        return None, None

    async def _evaluate_domain_inner(
        self, domain: str, ctx: _SPFEvaluationContext
    ) -> Tuple[ProtocolStatus, Optional[str]]:
        # Discover SPF Record
        dns_resp = await ctx.resolver.resolve(domain, DNSQueryType.TXT)
        err_status, err_reason = self._classify_dns_failure(dns_resp, f"SPF record for {domain}")
        if err_status is not None:
            return err_status, err_reason

        if dns_resp.is_void:
            ctx.void_lookups += 1
            if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                return ProtocolStatus.PERMERROR, f"SPF void lookup limit exceeded ({ctx.config.spf_max_void_lookups})"
            return ProtocolStatus.NONE, f"No SPF record published for {domain}"

        # Filter TXT records for v=spf1
        spf_records: List[str] = []
        for txt in dns_resp.txt_values():
            stripped = txt.strip()
            # Must start with v=spf1 followed by space or end-of-string (case-insensitive)
            if re.match(r"^v=spf1(\s+.*)?$", stripped, re.IGNORECASE):
                spf_records.append(stripped)

        # RFC 7208 Section 3.2: Exactly one record requirement
        if len(spf_records) == 0:
            return ProtocolStatus.NONE, f"No SPF record published for {domain}"
        if len(spf_records) > 1:
            return ProtocolStatus.PERMERROR, f"Multiple SPF records found for {domain} (count: {len(spf_records)})"

        record = spf_records[0]
        ctx.evaluated_records.append(record)

        # Parse terms (mechanisms and modifiers)
        tokens = record.split()
        version_tag = tokens[0].lower()
        if version_tag != "v=spf1":
            return ProtocolStatus.PERMERROR, f"Malformed SPF version tag: {tokens[0]}"

        mechanisms: List[str] = []
        modifiers: Dict[str, str] = {}
        seen_modifiers: Set[str] = set()

        for token in tokens[1:]:
            if not token:
                continue
            if "%" in token:
                valid, err_status, err_reason = self.validate_macro_syntax(token)
                if not valid:
                    return err_status, err_reason

            if "=" in token and not token.startswith(("ip4:", "ip6:", "a:", "mx:", "ptr:", "include:", "exists:")):
                parts = token.split("=", 1)
                mod_name = parts[0].lower().strip()
                mod_val = parts[1].strip()

                # RFC 7208 Section 6: Duplicate redirect or exp produces PERMERROR
                if mod_name in ("redirect", "exp"):
                    if mod_name in seen_modifiers:
                        return ProtocolStatus.PERMERROR, f"Duplicate '{mod_name}' modifier in SPF record"
                    seen_modifiers.add(mod_name)
                    modifiers[mod_name] = mod_val
                else:
                    # Unrecognized modifiers are simply ignored (even if repeated)
                    pass
            else:
                mechanisms.append(token)

        has_all_mechanism = any(
            m.lower() == "all" or m.lower().startswith(("+all", "-all", "~all", "?all"))
            for m in mechanisms
        )

        # Process Mechanisms in Policy Order
        for mech in mechanisms:
            ctx.mechanisms_evaluated += 1
            match_res, reason = await self._evaluate_mechanism(mech, domain, ctx)

            # Permanent or transient errors propagate immediately
            if match_res in (ProtocolStatus.PERMERROR, ProtocolStatus.TEMPERROR, ProtocolStatus.INDETERMINATE):
                return match_res, reason

            if match_res is not None:
                # Mechanism matched!
                return match_res, None

        # RFC 7208 Section 6.1: redirect is evaluated ONLY if no mechanism matched
        # AND no 'all' mechanism appeared in the record.
        if "redirect" in modifiers and not has_all_mechanism:
            redirect_target = modifiers["redirect"]
            ctx.dns_terms_queried += 1
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded at redirect={redirect_target}"

            redirect_expanded = self._expand_macros(redirect_target, domain, ctx)
            try:
                norm_redirect = self.normalize_domain(redirect_expanded)
            except Exception as e:
                return ProtocolStatus.PERMERROR, f"Invalid domain in redirect modifier: {e}"

            red_status, red_reason = await self._evaluate_domain(norm_redirect, ctx)
            if red_status == ProtocolStatus.NONE:
                return ProtocolStatus.PERMERROR, f"Redirected domain {norm_redirect} has no valid SPF record"
            return red_status, red_reason

        # Default outcome when all mechanisms fail to match and no redirect exists
        return ProtocolStatus.NEUTRAL, None

    async def _evaluate_mechanism(
        self, token: str, current_domain: str, ctx: _SPFEvaluationContext
    ) -> Tuple[Optional[ProtocolStatus], Optional[str]]:
        """Evaluates a single mechanism.

        Returns (ProtocolStatus, reason) if mechanism matched or error occurred;
        returns (None, None) if mechanism did not match.
        """
        # Parse qualifier
        qualifier = "+"
        mech_body = token
        if token[0] in ("+", "-", "~", "?"):
            qualifier = token[0]
            mech_body = token[1:]

        qualifier_map = {
            "+": ProtocolStatus.PASS,
            "-": ProtocolStatus.FAIL,
            "~": ProtocolStatus.SOFTFAIL,
            "?": ProtocolStatus.NEUTRAL,
        }
        match_status = qualifier_map[qualifier]

        # Macro syntax validation
        if "%" in mech_body:
            valid, err_status, err_reason = self.validate_macro_syntax(mech_body)
            if not valid:
                return err_status, err_reason

        mech_lower = mech_body.lower()

        # 1. all
        if mech_lower == "all":
            return match_status, None

        # 2. ip4
        if mech_lower.startswith("ip4:"):
            cidr_str = mech_body[4:].strip()
            if not cidr_str:
                return ProtocolStatus.PERMERROR, "Empty CIDR in ip4 mechanism"
            try:
                network = ipaddress.IPv4Network(cidr_str, strict=False)
                if isinstance(ctx.client_ip, ipaddress.IPv4Address) and ctx.client_ip in network:
                    return match_status, None
                return None, None
            except ValueError as e:
                return ProtocolStatus.PERMERROR, f"Invalid IPv4 network syntax '{cidr_str}': {e}"

        # 3. ip6
        if mech_lower.startswith("ip6:"):
            cidr_str = mech_body[4:].strip()
            if not cidr_str:
                return ProtocolStatus.PERMERROR, "Empty CIDR in ip6 mechanism"
            try:
                network = ipaddress.IPv6Network(cidr_str, strict=False)
                if isinstance(ctx.client_ip, ipaddress.IPv6Address) and ctx.client_ip in network:
                    return match_status, None
                return None, None
            except ValueError as e:
                return ProtocolStatus.PERMERROR, f"Invalid IPv6 network syntax '{cidr_str}': {e}"

        # 4. a
        if mech_lower == "a" or mech_lower.startswith(("a:", "a/")):
            ctx.dns_terms_queried += 1
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded"

            target_domain, ip4_prefix, ip6_prefix = self._parse_a_or_mx_spec(mech_body, current_domain, ctx)
            if target_domain is None:
                return ProtocolStatus.PERMERROR, f"Malformed 'a' mechanism syntax: {token}"

            matched, err_status, err_reason = await self._check_ip_match(
                target_domain=target_domain,
                ip4_prefix=ip4_prefix,
                ip6_prefix=ip6_prefix,
                ctx=ctx,
            )
            if err_status:
                return err_status, err_reason
            if matched:
                return match_status, None
            return None, None

        # 5. mx
        if mech_lower == "mx" or mech_lower.startswith(("mx:", "mx/")):
            ctx.dns_terms_queried += 1
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded"

            target_domain, ip4_prefix, ip6_prefix = self._parse_a_or_mx_spec(mech_body, current_domain, ctx)
            if target_domain is None:
                return ProtocolStatus.PERMERROR, f"Malformed 'mx' mechanism syntax: {token}"

            # Query MX records
            mx_resp = await ctx.resolver.resolve(target_domain, DNSQueryType.MX)
            err_status, err_reason = self._classify_dns_failure(mx_resp, f"MX for {target_domain}")
            if err_status is not None:
                return err_status, err_reason
            if mx_resp.is_void:
                ctx.void_lookups += 1
                if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                    return ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
                return None, None

            mx_hosts = [exchange for (_, exchange) in mx_resp.mx_values()]
            if not mx_hosts:
                return None, None

            # RFC 7208 Section 4.6.4: Evaluating an 'mx' mechanism queries at most 10 address
            # records per MX record. If an individual MX record results in querying more than
            # 10 address records, evaluating the mechanism produces a PERMERROR result.
            for mx_host in mx_hosts:
                qtype = DNSQueryType.A if isinstance(ctx.client_ip, ipaddress.IPv4Address) else DNSQueryType.AAAA
                addr_resp = await ctx.resolver.resolve(mx_host, qtype)
                err_status, err_reason = self._classify_dns_failure(addr_resp, f"address for MX host {mx_host}")
                if err_status is not None:
                    return err_status, err_reason

                if addr_resp.is_void:
                    ctx.void_lookups += 1
                    if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                        return ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
                    continue

                # Check per-MX-record limit
                if len(addr_resp.records) > ctx.config.spf_subordinate_address_limit:
                    return ProtocolStatus.PERMERROR, (
                        f"MX subordinate address record limit of {ctx.config.spf_subordinate_address_limit} "
                        f"exceeded for individual MX host '{mx_host}' ({len(addr_resp.records)} records returned)"
                    )

                # Check IP match against returned records
                for rec in addr_resp.records:
                    if self._matches_prefix(rec.value, ctx.client_ip, ip4_prefix, ip6_prefix):
                        return match_status, None

            return None, None

        # 6. ptr
        if mech_lower == "ptr" or mech_lower.startswith("ptr:"):
            # Target domain
            if ":" in mech_body:
                raw_domain = mech_body.split(":", 1)[1].strip()
                expanded_domain = self._expand_macros(raw_domain, current_domain, ctx)
                try:
                    target_domain = self.normalize_domain(expanded_domain)
                except Exception as e:
                    return ProtocolStatus.PERMERROR, f"Invalid domain in ptr mechanism: {e}"
            else:
                target_domain = current_domain

            # Query PTR records on connecting IP
            ptr_resp = await ctx.resolver.resolve(str(ctx.client_ip), DNSQueryType.PTR)
            err_status, err_reason = self._classify_dns_failure(ptr_resp, f"PTR for {ctx.client_ip}")
            if err_status is not None:
                return err_status, err_reason

            if ptr_resp.is_void:
                ctx.void_lookups += 1
                if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                    return ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
                return None, None

            ptr_records = ptr_resp.ptr_values()
            num_ptr_rrs = len(ptr_records)

            # RFC 7208 Section 4.6.4 & REV13: Queried PTR records contribute directly to global limit
            ctx.dns_terms_queried += num_ptr_rrs
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded by PTR resource records ({num_ptr_rrs} PTR RRs returned)"

            # Pre-filter hostnames and validate forward addresses
            target_suffix = target_domain.lower().rstrip(".")
            for ptr_name in ptr_records:
                norm_ptr = ptr_name.strip().lower().rstrip(".")
                # Pre-filter: must end with or equal target_domain
                if not (norm_ptr == target_suffix or norm_ptr.endswith("." + target_suffix)):
                    continue

                # Query forward A or AAAA records for validated PTR hostname
                qtype = DNSQueryType.A if isinstance(ctx.client_ip, ipaddress.IPv4Address) else DNSQueryType.AAAA
                fwd_resp = await ctx.resolver.resolve(norm_ptr, qtype)
                err_status, err_reason = self._classify_dns_failure(fwd_resp, f"forward address for PTR host {norm_ptr}")
                if err_status is not None:
                    return err_status, err_reason

                if fwd_resp.is_void:
                    ctx.void_lookups += 1
                    if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                        return ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
                    continue

                # RFC 7208 Section 4.6.4: Ignore excess records beyond the first 10
                fwd_records = fwd_resp.records[: ctx.config.spf_subordinate_address_limit]
                for rec in fwd_records:
                    try:
                        rec_ip = ipaddress.ip_address(rec.value.strip())
                        if rec_ip == ctx.client_ip:
                            return match_status, None
                    except ValueError:
                        continue

            return None, None

        # 7. exists
        if mech_lower.startswith("exists:"):
            ctx.dns_terms_queried += 1
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded"

            raw_target = mech_body[7:].strip()
            expanded_target = self._expand_macros(raw_target, current_domain, ctx)
            try:
                norm_target = self.normalize_domain(expanded_target)
            except Exception as e:
                return ProtocolStatus.PERMERROR, f"Invalid domain in exists mechanism: {e}"

            # Query A record (RFC 7208 Section 5.7: queries A record)
            exists_resp = await ctx.resolver.resolve(norm_target, DNSQueryType.A)
            err_status, err_reason = self._classify_dns_failure(exists_resp, f"exists domain {norm_target}")
            if err_status is not None:
                return err_status, err_reason
            if exists_resp.is_void:
                ctx.void_lookups += 1
                if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                    return ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
                return None, None

            if exists_resp.is_success and len(exists_resp.records) > 0:
                return match_status, None
            return None, None

        # 8. include
        if mech_lower.startswith("include:"):
            ctx.dns_terms_queried += 1
            if ctx.dns_terms_queried > ctx.config.spf_global_dns_term_limit:
                return ProtocolStatus.PERMERROR, f"SPF global limit of {ctx.config.spf_global_dns_term_limit} DNS terms exceeded"

            include_target = mech_body[8:].strip()
            expanded_include = self._expand_macros(include_target, current_domain, ctx)
            try:
                norm_include = self.normalize_domain(expanded_include)
            except Exception as e:
                return ProtocolStatus.PERMERROR, f"Invalid domain in include mechanism: {e}"

            inc_status, inc_reason = await self._evaluate_domain(norm_include, ctx)

            if inc_status == ProtocolStatus.PASS:
                return match_status, None
            elif inc_status in (ProtocolStatus.FAIL, ProtocolStatus.SOFTFAIL, ProtocolStatus.NEUTRAL):
                return None, None  # Mechanism does not match, continue policy evaluation
            elif inc_status == ProtocolStatus.NONE:
                return ProtocolStatus.PERMERROR, f"Included domain {norm_include} has no valid SPF record"
            else:
                # PERMERROR or TEMPERROR propagates directly
                return inc_status, inc_reason

        return ProtocolStatus.PERMERROR, f"Unknown SPF mechanism '{token}'"

    def _parse_a_or_mx_spec(
        self, spec: str, current_domain: str, ctx: Optional[_SPFEvaluationContext] = None
    ) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """Parses 'a' or 'mx' mechanism specifier with optional domain and dual-CIDR prefix."""
        # Examples: "a", "a/24", "a//64", "a/24//64", "a:mail.com/24//64", "mx:corp.com/24"
        prefix_part = ""
        target_domain = current_domain

        body = spec
        if ":" in body:
            parts = body.split(":", 1)
            body = parts[1]
            if "/" in body:
                domain_part, prefix_part = body.split("/", 1)
                prefix_part = "/" + prefix_part
            else:
                domain_part = body
            if ctx is not None:
                domain_part = self._expand_macros(domain_part, current_domain, ctx)
            try:
                target_domain = self.normalize_domain(domain_part)
            except Exception:
                return None, None, None
        elif "/" in body:
            parts = body.split("/", 1)
            prefix_part = "/" + parts[1]

        ip4_prefix = None
        ip6_prefix = None

        if prefix_part:
            # Parse dual CIDR: e.g. /24, //64, /24//64
            if "//" in prefix_part:
                sub_parts = prefix_part.split("//")
                v4_str = sub_parts[0].lstrip("/")
                v6_str = sub_parts[1]
                if v4_str:
                    try:
                        ip4_prefix = int(v4_str)
                    except ValueError:
                        return None, None, None
                if v6_str:
                    try:
                        ip6_prefix = int(v6_str)
                    except ValueError:
                        return None, None, None
            else:
                try:
                    ip4_prefix = int(prefix_part.lstrip("/"))
                except ValueError:
                    return None, None, None

        if ip4_prefix is not None and not (0 <= ip4_prefix <= 32):
            return None, None, None
        if ip6_prefix is not None and not (0 <= ip6_prefix <= 128):
            return None, None, None

        return target_domain, ip4_prefix, ip6_prefix

    async def _check_ip_match(
        self,
        target_domain: str,
        ip4_prefix: Optional[int],
        ip6_prefix: Optional[int],
        ctx: _SPFEvaluationContext,
    ) -> Tuple[bool, Optional[ProtocolStatus], Optional[str]]:
        """Queries forward address records and checks if connecting IP matches within prefix."""
        qtype = DNSQueryType.A if isinstance(ctx.client_ip, ipaddress.IPv4Address) else DNSQueryType.AAAA
        resp = await ctx.resolver.resolve(target_domain, qtype)

        err_status, err_reason = self._classify_dns_failure(resp, f"{qtype.value} for {target_domain}")
        if err_status is not None:
            return False, err_status, err_reason

        if resp.is_void:
            ctx.void_lookups += 1
            if ctx.void_lookups > ctx.config.spf_max_void_lookups:
                return False, ProtocolStatus.PERMERROR, "SPF void lookup limit exceeded"
            return False, None, None

        for rec in resp.records:
            if self._matches_prefix(rec.value, ctx.client_ip, ip4_prefix, ip6_prefix):
                return True, None, None

        return False, None, None

    def _matches_prefix(
        self,
        record_value: str,
        client_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        ip4_prefix: Optional[int],
        ip6_prefix: Optional[int],
    ) -> bool:
        """Tests if client_ip matches the IP in record_value under the specified prefix."""
        try:
            target_ip = ipaddress.ip_address(record_value.strip())
        except ValueError:
            return False

        if isinstance(client_ip, ipaddress.IPv4Address) and isinstance(target_ip, ipaddress.IPv4Address):
            prefix_len = ip4_prefix if ip4_prefix is not None else 32
            net = ipaddress.IPv4Network(f"{target_ip}/{prefix_len}", strict=False)
            return client_ip in net

        if isinstance(client_ip, ipaddress.IPv6Address) and isinstance(target_ip, ipaddress.IPv6Address):
            prefix_len = ip6_prefix if ip6_prefix is not None else 128
            net = ipaddress.IPv6Network(f"{target_ip}/{prefix_len}", strict=False)
            return client_ip in net

        return False

    def _expand_macros(self, text: str, current_domain: str, ctx: _SPFEvaluationContext) -> str:
        """Expands RFC 7208 Section 7 macros, transformers, delimiters, and escape sequences."""
        if "%" not in text:
            return text

        sender = ctx.mail_from or f"postmaster@{ctx.helo_domain or current_domain}"
        local_part = sender.split("@")[0] if "@" in sender else sender
        sender_domain = sender.split("@")[-1] if "@" in sender else current_domain

        if isinstance(ctx.client_ip, ipaddress.IPv4Address):
            ip_str = str(ctx.client_ip)
            ip_type = "in-addr"
        else:
            # IPv6: 32 dot-separated nibbles in reverse (standard for ip6.arpa)
            ip_str = ".".join(reversed(ctx.client_ip.exploded.replace(":", "")))
            ip_type = "ip6"

        macro_values = {
            "s": sender,
            "l": local_part,
            "o": sender_domain,
            "d": current_domain,
            "i": ip_str,
            "v": ip_type,
            "h": ctx.helo_domain or current_domain,
        }

        # 1. Protect %% escapes so they do not interfere with macro expansion
        # RFC 7208 Section 7.1:
        # '%%' produces literal '%'
        # '%_' produces literal ' '
        # '%-' produces URL-encoded space '%20'
        res = text.replace("%%", "\x00PCT\x00").replace("%_", " ").replace("%-", "%20")

        # 2. Expand braced macros %{...}
        def replace_macro_match(m: re.Match) -> str:
            content = m.group(1)
            m_spec = re.match(r"^([a-zA-Z])(\d*)([rR])?([\.\-+,\/_\=]*)$", content)
            if not m_spec:
                return m.group(0)

            letter, digits_str, reverse_flag, delimiters = m_spec.groups()
            letter_lower = letter.lower()
            val = macro_values.get(letter_lower, "")

            # Step 1: Delimiters and Splitting on raw replacement value
            delim_chars = delimiters if delimiters else "."
            pattern = "[" + "".join(re.escape(c) for c in delim_chars) + "]"
            parts = re.split(pattern, val)

            # Step 2: Reverse transformer ('r')
            if reverse_flag:
                parts = list(reversed(parts))

            # Step 3: Digits truncation (right-hand parts)
            if digits_str:
                num = int(digits_str)
                if num > 0 and num < len(parts):
                    parts = parts[-num:]

            # Step 4: Rejoin with '.'
            rejoined = ".".join(parts)

            # Step 5: RFC 7208 Section 7.3: For uppercase macro letters, URL-encode the resulting
            # value using RFC 3986 unreserved-character rules (safe="").
            # For lowercase macro letters, do not apply URL-encoding.
            if letter.isupper():
                rejoined = urllib.parse.quote(rejoined, safe="")

            return rejoined

        res = re.sub(r"%\{([^}]+)\}", replace_macro_match, res)

        # 3. Restore escaped '%'
        res = res.replace("\x00PCT\x00", "%")
        return res

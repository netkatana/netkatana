# Planned checks

This file is ordered by implementation priority, not by protocol.

## P0: high-signal checks with low-to-medium implementation cost

### Response

- `response_redirect_http_upgrade_missing` — critical

### Existing-group gaps to close early

## P1: expand coverage in groups we already support

### HTTP

- `headers_permissions_policy_missing` — notice
- `headers_permissions_policy_invalid` — critical
- `headers_referrer_policy_duplicated` — warning
- `headers_permissions_policy_too_permissive` — warning
- `headers_permissions_policy_duplicated` — critical
- `headers_permissions_policy_deprecated_feature` — notice
- `headers_x_permitted_cross_domain_policies_missing` — notice
- `headers_x_permitted_cross_domain_policies_invalid` — critical
- `headers_x_permitted_cross_domain_policies_duplicated` — warning
- `headers_x_permitted_cross_domain_policies_unsafe` — warning
- `headers_x_xss_protection_deprecated` — notice
- `headers_expect_ct_deprecated` — notice
- `headers_feature_policy_deprecated` — notice
- `headers_content_type_non_html` — notice
- `headers_content_type_unsafe` — warning

### TLS

- `tls_cert_expiring_7d` — critical
- `tls_cert_expiring_30d` — warning
- `tls_cert_key_size_small` — warning
- `tls_cert_weak_signature` — warning
- `tls_no_forward_secrecy` — warning
- `tls_compression_enabled` — warning

### DNS

- `dns_spf_invalid` — warning
- `dns_spf_softfail` — notice
- `dns_dmarc_invalid` — warning
- `dns_dmarc_policy_none` — warning
- `dns_caa_missing` — warning
- `dns_nameserver_single` — notice

## P2: valuable additions that need new parsers or broader result models

### HTTP

- `headers_allow_methods_unsafe` — notice
- `headers_clear_site_data_invalid` — notice
- `headers_origin_agent_cluster_invalid` — notice
- `headers_coop_duplicated` — critical
- `headers_coep_duplicated` — critical
- `headers_corp_duplicated` — critical
- `headers_permissions_policy_empty` — notice
- `headers_cache_control_invalid` — notice
- `headers_cache_control_sensitive_missing_no_store` — warning
- `response_time_slow` — notice

### DNS

- `dns_dkim_missing` — notice
- `dns_mta_sts_missing` — notice
- `dns_dnssec_missing` — notice
- `dns_dangling_cname` — critical

## P3: expensive or environment-sensitive checks

### DNS

- `dns_zone_transfer_enabled` — critical

### HTTP / legacy / low-signal

- `headers_p3p_deprecated` — notice
- `headers_public_key_pins_deprecated` — notice
- `headers_public_key_pins_report_only_deprecated` — notice
- `headers_report_to_deprecated` — notice
- `headers_x_ua_compatible_deprecated` — notice

## Notes on what we are currently missing

### In groups already implemented

- HSTS currently checks presence, duplicate header instances, and several policy-quality issues, but not duplicate/conflicting directives inside a single header value.
- CORS currently covers the most dangerous origin and credential combinations, but does not yet look at unsafe `Allow` exposure or response-body/content-type context.
- COOP/COEP/CORP have baseline presence and invalid-value coverage, but not duplicate-header handling or richer rollout consistency checks.

### In groups already planned

- `Referrer-Policy` should not stop at "missing"; invalid and unsafe values matter more than absence.
- `Permissions-Policy` should not stop at "missing"; invalid syntax, deprecated features, and wildcard-style permissive policies are the real misconfiguration surface.
- `X-Frame-Options` and `X-Permitted-Cross-Domain-Policies` should include duplicate-header/value checks because browsers handle conflicting values inconsistently.
- DNS email-authentication work should include syntax validation before policy-strength checks.

## Recommended implementation roadmap

1. Ship the low-cost, high-signal HTTP and response rules in P0.
2. Extend shared parsers in `utils.py` for `Referrer-Policy`, `Permissions-Policy`, cookie attributes, and duplicate-header helpers.
3. Define duplicate-header handling as a small shared helper for singleton security-policy headers, then add explicit rules only for the headers where ambiguity matters.
4. Fill P1 gaps in existing families before adding many new header families.
5. Expand `TlsResult` and the `tlsx` runner for certificate age, key size, signature algorithm, forward secrecy, and compression details.
6. Expand `DnsResult` and the DNS scanner for CAA, NS, DKIM, MTA-STS, DNSSEC, and CNAME-based checks.
7. Add P2 and P3 items only after the parser and scanner foundations above are stable.

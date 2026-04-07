## Checks

### HTTP

| Code                                                | Severity | Status      | Description                                                                                                                                      |
|-----------------------------------------------------|----------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `headers_strict_transport_security_missing`         | CRITICAL | implemented | HSTS header missing — browsers may connect over HTTP and be vulnerable to protocol downgrade and SSL stripping                                   |
| `headers_cookie_missing_secure`                     | CRITICAL | planned     | Cookie set without `Secure` flag — transmitted over unencrypted HTTP connections                                                                 |
| `headers_content_security_policy_missing`           | WARNING  | implemented | CSP header missing — no restriction on which resources browsers load, increases XSS/data injection risk                                          |
| `headers_cors_wildcard_origin`                      | WARNING  | planned     | `Access-Control-Allow-Origin: *` — any origin can read the response; may allow unintended cross-origin reads on credentialed endpoints           |
| `headers_x_content_type_options_missing`            | WARNING  | planned     | `nosniff` directive missing — allows MIME-type sniffing attacks                                                                                  |
| `headers_x_frame_options_missing`                   | WARNING  | planned     | No clickjacking protection — page can be embedded in an iframe by any origin                                                                     |
| `headers_cross_origin_resource_policy_missing`      | WARNING  | planned     | No CORP header — other origins can load this resource (Spectre-class side-channel risk)                                                          |
| `headers_cross_origin_opener_policy_missing`        | WARNING  | planned     | No COOP header — page shares a browsing context group with cross-origin pages, enabling XS-Leaks                                                 |
| `headers_cookie_missing_httponly`                   | WARNING  | planned     | Cookie accessible via JavaScript — stolen by XSS without `HttpOnly` flag                                                                         |
| `headers_cookie_missing_samesite`                   | WARNING  | planned     | Cookie missing `SameSite` attribute — may be sent on cross-site requests, enabling CSRF                                                          |
| `headers_hsts_max_age_low`                          | WARNING  | planned     | HSTS `max-age` is less than one year — too short to provide meaningful downgrade protection                                                      |
| `headers_referrer_policy_missing`                   | NOTICE   | planned     | No `Referrer-Policy` — full URL may leak to third parties via the `Referer` header                                                               |
| `headers_permissions_policy_missing`                | NOTICE   | planned     | No `Permissions-Policy` — browser features (camera, microphone, geolocation, etc.) are unconstrained                                             |
| `headers_cross_origin_embedder_policy_missing`      | NOTICE   | planned     | No COEP header — prevents enabling cross-origin isolation (required for SharedArrayBuffer/high-res timers)                                       |
| `headers_x_permitted_cross_domain_policies_missing` | NOTICE   | planned     | No `X-Permitted-Cross-Domain-Policies` — Flash/PDF clients may load cross-domain data                                                            |
| `headers_server_disclosure`                         | NOTICE   | planned     | `Server` header present — reveals server software and version to potential attackers                                                             |
| `headers_x_powered_by_disclosure`                   | NOTICE   | planned     | `X-Powered-By` header present — reveals framework or runtime to potential attackers                                                              |
| `headers_x_xss_protection_deprecated`               | NOTICE   | planned     | `X-XSS-Protection` header present — deprecated and can introduce vulnerabilities in older browsers                                               |
| `headers_expect_ct_deprecated`                      | NOTICE   | planned     | `Expect-CT` header present — deprecated since Chrome 115; Certificate Transparency is now enforced by browsers                                   |
| `headers_feature_policy_deprecated`                 | NOTICE   | planned     | `Feature-Policy` header present — superseded by `Permissions-Policy`; use the modern header instead                                              |
| `headers_cookie_prefix_secure_missing`              | NOTICE   | planned     | Cookie has `Secure` flag but no `__Secure-` prefix — prefix enforces the flag at the browser level                                               |
| `headers_cookie_prefix_host_missing`                | NOTICE   | planned     | Cookie has `Secure; Path=/` and no `Domain` but lacks `__Host-` prefix — prefix provides stricter origin binding                                 |
| `headers_cookie_prefix_secure_misconfigured`        | CRITICAL | planned     | Cookie uses `__Secure-` prefix but is missing the `Secure` flag — browser silently drops it, breaking functionality                              |
| `headers_cookie_prefix_host_misconfigured`          | CRITICAL | planned     | Cookie uses `__Host-` prefix but violates its requirements (`Secure`, `Path=/`, no `Domain`) — browser silently drops it, breaking functionality |
| `headers_strict_transport_security_invalid`         | CRITICAL | planned     | HSTS header present but malformed (missing `max-age`, non-numeric value, bad syntax) — browser ignores it, same effect as missing                |
| `headers_content_security_policy_invalid`           | WARNING  | planned     | CSP header present but malformed — browser may ignore the entire header, leaving XSS protections ineffective                                     |
| `headers_x_content_type_options_invalid`            | WARNING  | planned     | `X-Content-Type-Options` value is not `nosniff` — browser ignores it, MIME-type sniffing remains enabled                                         |
| `headers_x_frame_options_invalid`                   | WARNING  | planned     | `X-Frame-Options` value is not `DENY` or `SAMEORIGIN` — browser ignores it, clickjacking protection is not applied                               |

### TLS

| Code                      | Severity           | Status      | Description                                                                                           |
|---------------------------|--------------------|-------------|-------------------------------------------------------------------------------------------------------|
| `tls_cert_expired`        | CRITICAL           | implemented | Certificate has passed its expiry date — clients will receive security warnings or refuse to connect  |
| `tls_cert_self_signed`    | CRITICAL           | implemented | Certificate not issued by a trusted CA — browsers and clients will reject or warn                     |
| `tls_cert_mismatched`     | CRITICAL           | implemented | Certificate does not cover the requested hostname — clients will reject the connection                |
| `tls_cert_revoked`        | CRITICAL           | implemented | Certificate has been revoked by the CA — clients that check revocation will reject it                 |
| `tls_cert_untrusted`      | CRITICAL           | implemented | Certificate chain cannot be verified against any trusted root CA                                      |
| `tls_version_deprecated`  | CRITICAL           | implemented | SSL 3.0, TLS 1.0, or TLS 1.1 in use — contains known vulnerabilities (BEAST, POODLE)                  |
| `tls_cert_expiring`       | CRITICAL / WARNING | outdated    | Certificate expiring soon — CRITICAL if ≤7 days remain, WARNING if ≤30 days remain                    |
| `tls_cipher_weak`         | WARNING            | implemented | Weak cipher suite negotiated (RC4, NULL, EXPORT, DES, 3DES, IDEA, SEED)                               |
| `tls_cert_key_size_small` | WARNING            | planned     | RSA key < 2048 bits or ECC key < 256 bits — insufficient cryptographic strength                       |
| `tls_cert_weak_signature` | WARNING            | planned     | Certificate signed with MD5 or SHA-1 — vulnerable to collision attacks                                |
| `tls_no_forward_secrecy`  | WARNING            | planned     | No ECDHE/DHE cipher suites offered — past sessions can be decrypted if the private key is compromised |
| `tls_compression_enabled` | WARNING            | planned     | TLS compression enabled — vulnerable to CRIME attack                                                  |
| `tls_version_outdated`    | WARNING / NOTICE   | outdated    | TLS 1.2 negotiated — WARNING if TLS 1.3 is not supported at all, NOTICE if TLS 1.3 is also available  |

### DNS

| Code                        | Severity | Status  | Description                                                                                 |
|-----------------------------|----------|---------|---------------------------------------------------------------------------------------------|
| `dns_zone_transfer_enabled` | CRITICAL | planned | DNS zone transfer (AXFR) is allowed — exposes the full DNS zone to any requester            |
| `dns_dangling_cname`        | CRITICAL | planned | CNAME record points to an unclaimed or non-existent resource — subdomain takeover risk      |
| `dns_spf_missing`           | WARNING  | planned | No SPF TXT record — the domain can be spoofed in email phishing attacks                     |
| `dns_dmarc_missing`         | WARNING  | planned | No DMARC record at `_dmarc.<domain>` — email spoofing and phishing are unmitigated          |
| `dns_dmarc_policy_none`     | WARNING  | planned | DMARC policy is `p=none` — monitoring only, no enforcement against spoofed emails           |
| `dns_caa_missing`           | WARNING  | planned | No CAA record — any certificate authority can issue certificates for this domain            |
| `dns_dnssec_missing`        | NOTICE   | planned | DNSSEC not configured — DNS responses can be spoofed or poisoned                            |
| `dns_dkim_missing`          | NOTICE   | planned | No DKIM TXT record found — outbound email integrity cannot be verified                      |
| `dns_mta_sts_missing`       | NOTICE   | planned | No MTA-STS policy — email delivery is not enforced to use TLS                               |
| `dns_nameserver_single`     | NOTICE   | planned | Only one authoritative nameserver — single point of failure for DNS resolution              |
| `dns_spf_invalid`           | WARNING  | planned | SPF TXT record is malformed — mail servers treat it as absent, leaving the domain spoofable |
| `dns_spf_multiple`          | WARNING  | planned | More than one SPF TXT record present — causes `permerror`, effectively disabling SPF        |
| `dns_dmarc_invalid`         | WARNING  | planned | DMARC record is malformed — treated as absent by mail servers, no enforcement               |

### Response

| Code                                     | Severity | Status  | Description                                                                                                  |
|------------------------------------------|----------|---------|--------------------------------------------------------------------------------------------------------------|
| `response_redirect_https_downgrade`      | CRITICAL | planned | Redirect leads from HTTPS to HTTP — active downgrade of transport security                                   |
| `response_redirect_http_upgrade_missing` | WARNING  | planned | HTTP endpoint does not redirect to HTTPS — unencrypted access is silently accepted                           |
| `response_status_server_error`           | WARNING  | planned | Server returned 5xx — may expose stack traces, internal paths, or indicate misconfiguration                  |
| `response_redirect_chain_long`           | NOTICE   | planned | More than 3 redirects — indicates misconfiguration, adds latency, and can confuse security tools             |
| `response_redirect_chain_mixed_schemes`  | NOTICE   | planned | Redirect chain switches between HTTP and HTTPS mid-chain — intermediate hops leak the request over plaintext |
| `response_time_slow`                     | NOTICE   | planned | Response exceeded time threshold — potential indicator of resource exhaustion or misconfigured upstream      |

## Ideas

- `headers_content_security_policy_unsafe_inline` — CSP contains `unsafe-inline` directive, negating script/style injection protection
- `headers_content_security_policy_unsafe_eval` — CSP contains `unsafe-eval` directive, allowing dynamic code execution via `eval()` and similar

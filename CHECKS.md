# Checks

This file is the source of truth for all checks. Update it when adding or changing a check.

## Conventions

Each check entry has a `> severity, status` line and a one- or two-sentence description. That description is used verbatim as the `detail` field on `Finding` objects and in console output, so it must follow these rules:

- **Informative, not prescriptive.** Explain what the header/directive/feature does and why it matters. Do not tell the user what to do ("use X", "set Y to Z", "submit via ...").
- **Neutral with respect to outcome.** The same text appears on both PASS and FAIL findings. Phrases like "header absent" or "is missing" imply failure — avoid them. Write from the perspective of what the feature is and what happens when it is or isn't configured.
- **Concise.** One or two sentences. Prefer a semicolon to join cause and consequence over a long subordinate clause.
- **Single quotes, not backticks.** Use single quotes for header names, directive names, and values (e.g. 'max-age', 'unsafe-inline'). Backticks render in Markdown but not in the terminal.

## HTTP

### headers_hsts_missing

> CRITICAL, implemented

The 'Strict-Transport-Security' header instructs browsers to always use HTTPS for this domain, preventing protocol
downgrade and SSL stripping attacks.

### headers_hsts_invalid

> CRITICAL, implemented

The 'Strict-Transport-Security' header requires a valid 'max-age' directive; a malformed header is silently ignored by
browsers.

### headers_hsts_max_age_zero

> CRITICAL, implemented

'max-age=0' instructs browsers to delete the cached HSTS policy, removing HTTPS enforcement for returning users.

### headers_hsts_max_age_low

> WARNING, implemented

The 'max-age' directive controls how long browsers enforce HTTPS for this domain; values below one year (31,536,000 s)
leave a wider window for downgrade attacks between visits.

### headers_hsts_include_subdomains_missing

> NOTICE, implemented

The 'includeSubDomains' directive extends HSTS to all subdomains; without it, subdomains are reachable over plain HTTP
and parent-domain cookies may be intercepted.

### headers_hsts_preload_not_eligible

> WARNING, implemented

The 'preload' directive signals intent to join browser preload lists, which hardcode the HSTS policy before a user's
first visit; qualifying requires 'max-age' ≥ 31,536,000 s and 'includeSubDomains'.

### headers_csp_missing

> WARNING, implemented

The 'Content-Security-Policy' header restricts which resources browsers can load, reducing the risk of XSS and data
injection attacks.

### headers_csp_unsafe_inline

> CRITICAL, implemented

'unsafe-inline' in 'script-src' (or 'default-src') permits all inline scripts; a nonce or hash neutralizes it and
restores XSS protection in CSP Level 2+ browsers.

### headers_csp_unsafe_eval

> CRITICAL, implemented

'unsafe-eval' in 'script-src' (or 'default-src') permits eval(), new Function(string), and similar dynamic code
execution from strings.

### headers_csp_object_src_unsafe

> WARNING, implemented

'object-src' (or 'default-src') controls <object> and <embed> elements; plugin content runs outside the browser's
normal security model and has historically enabled code execution.

### headers_csp_base_uri_missing

> WARNING, implemented

'base-uri' restricts the <base> element's 'href', preventing attackers from redirecting relative resource loads and
bypassing 'script-src'; it does not fall back to 'default-src'.

### headers_csp_frame_ancestors_missing

> WARNING, implemented

'frame-ancestors' controls which origins can embed this page in a frame or iframe, preventing clickjacking; it does not
fall back to 'default-src'.

### headers_csp_form_action_missing

> WARNING, implemented

'form-action' restricts which URLs forms may submit to, preventing data exfiltration via injected forms; it does not
fall back to 'default-src'.

### headers_csp_script_src_missing

> CRITICAL, implemented

'script-src' (falling back to 'default-src') restricts which scripts browsers execute; without either directive, scripts
are completely unrestricted.

### headers_csp_script_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'script-src' (or 'default-src') allows scripts from any origin, making
the allowlist pointless.

### headers_csp_style_src_missing

> CRITICAL, implemented

'style-src' (falling back to 'default-src') restricts which stylesheets browsers load; without either directive, CSS
injection and data exfiltration via url() probes are possible.

### headers_csp_style_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'style-src' (or 'default-src') allows stylesheets from any origin,
making the allowlist pointless.

### headers_csp_connect_src_missing

> CRITICAL, implemented

'connect-src' (falling back to 'default-src') restricts fetch, XHR, and WebSocket destinations; without either
directive, connections to arbitrary origins are unrestricted.

### headers_csp_connect_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'connect-src' (or 'default-src') allows fetch, XHR, and WebSocket
connections to any origin, making the allowlist pointless.

### headers_csp_report_only_unsafe_inline

> CRITICAL, implemented

Same as `headers_csp_unsafe_inline`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_unsafe_eval

> CRITICAL, implemented

Same as `headers_csp_unsafe_eval`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_object_src_unsafe

> WARNING, implemented

Same as `headers_csp_object_src_unsafe`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_base_uri_missing

> WARNING, implemented

Same as `headers_csp_base_uri_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_frame_ancestors_missing

> WARNING, implemented

Same as `headers_csp_frame_ancestors_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_form_action_missing

> WARNING, implemented

Same as `headers_csp_form_action_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_script_src_missing

> CRITICAL, implemented

Same as `headers_csp_script_src_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_script_src_unrestricted

> CRITICAL, implemented

Same as `headers_csp_script_src_unrestricted`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_style_src_missing

> CRITICAL, implemented

Same as `headers_csp_style_src_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_style_src_unrestricted

> CRITICAL, implemented

Same as `headers_csp_style_src_unrestricted`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_connect_src_missing

> CRITICAL, implemented

Same as `headers_csp_connect_src_missing`, applied to `Content-Security-Policy-Report-Only`.

### headers_csp_report_only_connect_src_unrestricted

> CRITICAL, implemented

Same as `headers_csp_connect_src_unrestricted`, applied to `Content-Security-Policy-Report-Only`.

### headers_cors_wildcard_origin

> WARNING, planned

`Access-Control-Allow-Origin: *` — any origin can read the response; may allow unintended cross-origin reads on
credentialed endpoints.

### headers_x_content_type_options_missing

> WARNING, planned

`nosniff` directive missing — allows MIME-type sniffing attacks.

### headers_x_content_type_options_invalid

> WARNING, planned

`X-Content-Type-Options` value is not `nosniff` — browser ignores it, MIME-type sniffing remains enabled.

### headers_x_frame_options_missing

> WARNING, planned

No clickjacking protection — page can be embedded in an iframe by any origin.

### headers_x_frame_options_invalid

> WARNING, planned

`X-Frame-Options` value is not `DENY` or `SAMEORIGIN` — browser ignores it, clickjacking protection is not applied.

### headers_cross_origin_resource_policy_missing

> WARNING, planned

No CORP header — other origins can load this resource (Spectre-class side-channel risk).

### headers_cross_origin_opener_policy_missing

> WARNING, planned

No COOP header — page shares a browsing context group with cross-origin pages, enabling XS-Leaks.

### headers_cookie_missing_secure

> CRITICAL, planned

Cookie set without `Secure` flag — transmitted over unencrypted HTTP connections.

### headers_cookie_missing_httponly

> WARNING, planned

Cookie accessible via JavaScript — stolen by XSS without `HttpOnly` flag.

### headers_cookie_missing_samesite

> WARNING, planned

Cookie missing `SameSite` attribute — may be sent on cross-site requests, enabling CSRF.

### headers_cookie_prefix_secure_misconfigured

> CRITICAL, planned

Cookie uses `__Secure-` prefix but is missing the `Secure` flag — browser silently drops it, breaking functionality.

### headers_cookie_prefix_host_misconfigured

> CRITICAL, planned

Cookie uses `__Host-` prefix but violates its requirements (`Secure`, `Path=/`, no `Domain`) — browser silently drops
it, breaking functionality.

### headers_cookie_prefix_secure_missing

> NOTICE, planned

Cookie has `Secure` flag but no `__Secure-` prefix — prefix enforces the flag at the browser level.

### headers_cookie_prefix_host_missing

> NOTICE, planned

Cookie has `Secure; Path=/` and no `Domain` but lacks `__Host-` prefix — prefix provides stricter origin binding.

### headers_referrer_policy_missing

> NOTICE, planned

No `Referrer-Policy` — full URL may leak to third parties via the `Referer` header.

### headers_permissions_policy_missing

> NOTICE, planned

No `Permissions-Policy` — browser features (camera, microphone, geolocation, etc.) are unconstrained.

### headers_cross_origin_embedder_policy_missing

> NOTICE, planned

No COEP header — prevents enabling cross-origin isolation (required for SharedArrayBuffer/high-res timers).

### headers_x_permitted_cross_domain_policies_missing

> NOTICE, planned

No `X-Permitted-Cross-Domain-Policies` — Flash/PDF clients may load cross-domain data.

### headers_server_disclosure

> NOTICE, planned

`Server` header present — reveals server software and version to potential attackers.

### headers_x_powered_by_disclosure

> NOTICE, planned

`X-Powered-By` header present — reveals framework or runtime to potential attackers.

### headers_x_xss_protection_deprecated

> NOTICE, planned

`X-XSS-Protection` header present — deprecated and can introduce vulnerabilities in older browsers.

### headers_expect_ct_deprecated

> NOTICE, planned

`Expect-CT` header present — deprecated since Chrome 115; Certificate Transparency is now enforced by browsers.

### headers_feature_policy_deprecated

> NOTICE, planned

`Feature-Policy` header present — superseded by `Permissions-Policy`; use the modern header instead.

## TLS

### tls_cert_expired

> CRITICAL, implemented

Certificate has passed its expiry date — clients will receive security warnings or refuse to connect.

### tls_cert_self_signed

> CRITICAL, implemented

Certificate not issued by a trusted CA — browsers and clients will reject or warn.

### tls_cert_mismatched

> CRITICAL, implemented

Certificate does not cover the requested hostname — clients will reject the connection.

### tls_cert_revoked

> CRITICAL, implemented

Certificate has been revoked by the CA — clients that check revocation will reject it.

### tls_cert_untrusted

> CRITICAL, implemented

Certificate chain cannot be verified against any trusted root CA.

### tls_version_deprecated

> CRITICAL, implemented

SSL 3.0, TLS 1.0, or TLS 1.1 in use — contains known vulnerabilities (BEAST, POODLE).

### tls_cert_expiring

> CRITICAL / WARNING, outdated

Certificate expiring soon — CRITICAL if ≤7 days remain, WARNING if ≤30 days remain.

### tls_cipher_weak

> WARNING, implemented

Weak cipher suite negotiated (RC4, NULL, EXPORT, DES, 3DES, IDEA, SEED).

### tls_cert_key_size_small

> WARNING, planned

RSA key < 2048 bits or ECC key < 256 bits — insufficient cryptographic strength.

### tls_cert_weak_signature

> WARNING, planned

Certificate signed with MD5 or SHA-1 — vulnerable to collision attacks.

### tls_no_forward_secrecy

> WARNING, planned

No ECDHE/DHE cipher suites offered — past sessions can be decrypted if the private key is compromised.

### tls_compression_enabled

> WARNING, planned

TLS compression enabled — vulnerable to CRIME attack.

### tls_version_outdated

> WARNING / NOTICE, outdated

TLS 1.2 negotiated — WARNING if TLS 1.3 is not supported at all, NOTICE if TLS 1.3 is also available.

## DNS

### dns_zone_transfer_enabled

> CRITICAL, planned

DNS zone transfer (AXFR) is allowed — exposes the full DNS zone to any requester.

### dns_dangling_cname

> CRITICAL, planned

CNAME record points to an unclaimed or non-existent resource — subdomain takeover risk.

### dns_spf_missing

> NOTICE, implemented

No SPF TXT record — the domain can be spoofed in email phishing attacks.

### dns_spf_permissive

> CRITICAL, implemented

SPF record ends with `+all` — any server on the internet is authorized to send email as this domain.

### dns_spf_invalid

> WARNING, planned

SPF TXT record is malformed — mail servers treat it as absent, leaving the domain spoofable.

### dns_spf_multiple

> WARNING, planned

More than one SPF TXT record present — causes `permerror`, effectively disabling SPF.

### dns_dmarc_missing

> NOTICE, implemented

No DMARC record at `_dmarc.<domain>` — email spoofing and phishing are unmitigated.

### dns_dmarc_policy_none

> WARNING, planned

DMARC policy is `p=none` — monitoring only, no enforcement against spoofed emails.

### dns_dmarc_invalid

> WARNING, planned

DMARC record is malformed — treated as absent by mail servers, no enforcement.

### dns_dkim_missing

> NOTICE, planned

No DKIM TXT record found — outbound email integrity cannot be verified.

### dns_mta_sts_missing

> NOTICE, planned

No MTA-STS policy — email delivery is not enforced to use TLS.

### dns_caa_missing

> WARNING, planned

No CAA record — any certificate authority can issue certificates for this domain.

### dns_dnssec_missing

> NOTICE, planned

DNSSEC not configured — DNS responses can be spoofed or poisoned.

### dns_nameserver_single

> NOTICE, planned

Only one authoritative nameserver — single point of failure for DNS resolution.

## Response

### response_redirect_https_downgrade

> CRITICAL, planned

Redirect leads from HTTPS to HTTP — active downgrade of transport security.

### response_redirect_http_upgrade_missing

> WARNING, planned

HTTP endpoint does not redirect to HTTPS — unencrypted access is silently accepted.

### response_status_server_error

> WARNING, planned

Server returned 5xx — may expose stack traces, internal paths, or indicate misconfiguration.

### response_redirect_chain_long

> NOTICE, planned

More than 3 redirects — indicates misconfiguration, adds latency, and can confuse security tools.

### response_redirect_chain_mixed_schemes

> NOTICE, planned

Redirect chain switches between HTTP and HTTPS mid-chain — intermediate hops leak the request over plaintext.

### response_time_slow

> NOTICE, planned

Response exceeded time threshold — potential indicator of resource exhaustion or misconfigured upstream.

## References

- [HTTP Strict Transport Security (HSTS)](https://datatracker.ietf.org/doc/html/rfc6797)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)

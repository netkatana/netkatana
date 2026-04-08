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

The 'Strict-Transport-Security' header instructs browsers to always use HTTPS for this domain, preventing protocol downgrade and SSL stripping attacks.

### headers_hsts_invalid

> CRITICAL, implemented

The 'Strict-Transport-Security' header requires a valid 'max-age' directive; a malformed header is silently ignored by browsers.

### headers_hsts_max_age_zero

> CRITICAL, implemented

'max-age=0' instructs browsers to delete the cached HSTS policy, removing HTTPS enforcement for returning users.

### headers_hsts_max_age_low

> WARNING, implemented

The 'max-age' directive controls how long browsers enforce HTTPS for this domain; values below one year (31,536,000 s) leave a wider window for downgrade attacks between visits.

### headers_hsts_include_subdomains_missing

> NOTICE, implemented

The 'includeSubDomains' directive extends HSTS to all subdomains; without it, subdomains are reachable over plain HTTP and parent-domain cookies may be intercepted.

### headers_hsts_preload_not_eligible

> WARNING, implemented

The 'preload' directive signals intent to join browser preload lists, which hardcode the HSTS policy before a user's first visit; qualifying requires 'max-age' ≥ 31,536,000 s and 'includeSubDomains'.

### headers_csp_missing

> WARNING, implemented

The 'Content-Security-Policy' header restricts which resources browsers can load, reducing the risk of XSS and data injection attacks.

### headers_csp_unsafe_inline

> CRITICAL, implemented

'unsafe-inline' in 'script-src' (or 'default-src') permits all inline scripts; a nonce or hash neutralizes it and restores XSS protection in CSP Level 2+ browsers.

### headers_csp_unsafe_eval

> CRITICAL, implemented

'unsafe-eval' in 'script-src' (or 'default-src') permits eval(), new Function(string), and similar dynamic code execution from strings.

### headers_csp_object_src_unsafe

> WARNING, implemented

'object-src' (or 'default-src') controls <object> and <embed> elements; plugin content runs outside the browser's normal security model and has historically enabled code execution.

### headers_csp_base_uri_missing

> WARNING, implemented

'base-uri' restricts the <base> element's 'href', preventing attackers from redirecting relative resource loads and bypassing 'script-src'; it does not fall back to 'default-src'.

### headers_csp_frame_ancestors_missing

> WARNING, implemented

'frame-ancestors' controls which origins can embed this page in a frame or iframe, preventing clickjacking; it does not fall back to 'default-src'.

### headers_csp_form_action_missing

> WARNING, implemented

'form-action' restricts which URLs forms may submit to, preventing data exfiltration via injected forms; it does not fall back to 'default-src'.

### headers_csp_script_src_missing

> CRITICAL, implemented

'script-src' (falling back to 'default-src') restricts which scripts browsers execute; without either directive, scripts are completely unrestricted.

### headers_csp_script_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'script-src' (or 'default-src') allows scripts from any origin, making the allowlist pointless.

### headers_csp_style_src_missing

> CRITICAL, implemented

'style-src' (falling back to 'default-src') restricts which stylesheets browsers load; without either directive, CSS injection and data exfiltration via url() probes are possible.

### headers_csp_style_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'style-src' (or 'default-src') allows stylesheets from any origin, making the allowlist pointless.

### headers_csp_connect_src_missing

> CRITICAL, implemented

'connect-src' (falling back to 'default-src') restricts fetch, XHR, and WebSocket destinations; without either directive, connections to arbitrary origins are unrestricted.

### headers_csp_connect_src_unrestricted

> CRITICAL, implemented

A wildcard source (*, 'https:', or 'http:') in 'connect-src' (or 'default-src') allows fetch, XHR, and WebSocket connections to any origin, making the allowlist pointless.

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

The 'Access-Control-Allow-Origin' header controls which origins can read the response; a wildcard value (*) grants read access to any origin, including on credentialed endpoints.

### headers_x_content_type_options_missing

> WARNING, planned

The 'X-Content-Type-Options' header with value 'nosniff' prevents browsers from guessing the content type, blocking MIME-sniffing attacks.

### headers_x_content_type_options_invalid

> WARNING, planned

The 'X-Content-Type-Options' header only takes effect when its value is exactly 'nosniff'; any other value is ignored by browsers.

### headers_x_frame_options_missing

> WARNING, planned

The 'X-Frame-Options' header restricts which origins can embed this page in a frame or iframe, preventing clickjacking attacks.

### headers_x_frame_options_invalid

> WARNING, planned

The 'X-Frame-Options' header only takes effect when its value is 'DENY' or 'SAMEORIGIN'; any other value is ignored by browsers.

### headers_cross_origin_resource_policy_missing

> WARNING, planned

The 'Cross-Origin-Resource-Policy' header restricts which origins can load this resource, reducing Spectre-class side-channel risks.

### headers_cross_origin_opener_policy_missing

> WARNING, planned

The 'Cross-Origin-Opener-Policy' header isolates the page's browsing context group from cross-origin pages, preventing XS-Leaks.

### headers_cookie_missing_secure

> CRITICAL, planned

The 'Secure' cookie flag restricts transmission to HTTPS connections only, preventing the cookie from being sent over unencrypted HTTP.

### headers_cookie_missing_httponly

> WARNING, planned

The 'HttpOnly' cookie flag prevents JavaScript access to the cookie, reducing the risk of session theft via XSS.

### headers_cookie_missing_samesite

> WARNING, planned

The 'SameSite' cookie attribute controls whether the cookie is sent on cross-site requests, limiting CSRF exposure.

### headers_cookie_prefix_secure_misconfigured

> CRITICAL, planned

The '__Secure-' cookie prefix requires the 'Secure' flag; browsers silently drop cookies that use the prefix without meeting this requirement.

### headers_cookie_prefix_host_misconfigured

> CRITICAL, planned

The '__Host-' cookie prefix requires 'Secure', 'Path=/', and no 'Domain' attribute; browsers silently drop cookies that use the prefix without meeting all requirements.

### headers_cookie_prefix_secure_missing

> NOTICE, planned

The '__Secure-' cookie prefix enforces the 'Secure' flag at the browser level, providing a stronger guarantee than the flag alone.

### headers_cookie_prefix_host_missing

> NOTICE, planned

The '__Host-' cookie prefix combines 'Secure', 'Path=/', and no 'Domain', providing the strictest origin binding available for cookies.

### headers_referrer_policy_missing

> NOTICE, planned

The 'Referrer-Policy' header controls how much of the URL is sent in the 'Referer' header to other origins, limiting information leakage to third parties.

### headers_permissions_policy_missing

> NOTICE, planned

The 'Permissions-Policy' header controls access to browser features such as camera, microphone, and geolocation, limiting their availability to trusted contexts.

### headers_cross_origin_embedder_policy_missing

> NOTICE, planned

The 'Cross-Origin-Embedder-Policy' header enables cross-origin isolation, which is required to access APIs such as SharedArrayBuffer and high-resolution timers.

### headers_x_permitted_cross_domain_policies_missing

> NOTICE, planned

The 'X-Permitted-Cross-Domain-Policies' header controls whether Flash and PDF clients may load cross-domain data from this origin.

### headers_server_disclosure

> NOTICE, planned

The 'Server' header identifies the server software and version; exposing this information makes targeted attacks easier.

### headers_x_powered_by_disclosure

> NOTICE, planned

The 'X-Powered-By' header identifies the framework or runtime; exposing this information makes targeted attacks easier.

### headers_x_xss_protection_deprecated

> NOTICE, planned

The 'X-XSS-Protection' header is deprecated and can introduce vulnerabilities in older browsers; modern browsers rely on CSP instead.

### headers_expect_ct_deprecated

> NOTICE, planned

The 'Expect-CT' header is deprecated since Chrome 115; Certificate Transparency enforcement is now built into browsers.

### headers_feature_policy_deprecated

> NOTICE, planned

The 'Feature-Policy' header is superseded by 'Permissions-Policy'; most modern browsers no longer process it.

## TLS

### tls_cert_expired

> CRITICAL, implemented

TLS certificates have an expiry date; after that date, clients will reject the connection or display a security warning.

### tls_cert_self_signed

> CRITICAL, implemented

TLS certificates must be issued by a CA trusted by the client; self-signed certificates are rejected or warned about by browsers.

### tls_cert_mismatched

> CRITICAL, implemented

A TLS certificate must cover the hostname being accessed; a mismatch causes clients to reject the connection.

### tls_cert_revoked

> CRITICAL, implemented

CAs can revoke certificates before they expire; clients that check revocation status will reject a revoked certificate.

### tls_cert_untrusted

> CRITICAL, implemented

The TLS certificate chain must be traceable to a root CA trusted by the client; an unverifiable chain causes connection rejection.

### tls_version_deprecated

> CRITICAL, implemented

SSL 3.0, TLS 1.0, and TLS 1.1 contain known vulnerabilities (BEAST, POODLE) and are rejected by modern clients.

### tls_cert_expiring

> CRITICAL / WARNING, outdated

Certificates nearing expiry leave little time for renewal; CRITICAL if ≤7 days remain, WARNING if ≤30 days remain.

### tls_cipher_weak

> WARNING, implemented

Cipher suites such as RC4, NULL, EXPORT, DES, 3DES, IDEA, and SEED have known weaknesses and should not be negotiated.

### tls_cert_key_size_small

> WARNING, planned

Key size determines cryptographic strength; RSA keys below 2048 bits and ECC keys below 256 bits provide insufficient security.

### tls_cert_weak_signature

> WARNING, planned

MD5 and SHA-1 signature algorithms are vulnerable to collision attacks and are no longer accepted by modern clients.

### tls_no_forward_secrecy

> WARNING, planned

ECDHE and DHE cipher suites provide forward secrecy, ensuring past sessions cannot be decrypted even if the private key is later compromised.

### tls_compression_enabled

> WARNING, planned

TLS compression reduces ciphertext entropy in a way that enables the CRIME attack, allowing session cookie theft.

### tls_version_outdated

> WARNING / NOTICE, outdated

TLS 1.3 offers improved security and performance over TLS 1.2; WARNING if TLS 1.3 is not supported at all, NOTICE if TLS 1.3 is also available.

## DNS

### dns_zone_transfer_enabled

> CRITICAL, planned

DNS zone transfers (AXFR) replicate the full zone to secondary nameservers; allowing unrestricted transfers exposes all DNS records to any requester.

### dns_dangling_cname

> CRITICAL, planned

A CNAME pointing to an unclaimed or non-existent resource can be registered by an attacker, enabling subdomain takeover.

### dns_spf_missing

> NOTICE, implemented

An SPF TXT record lists the servers authorized to send email for this domain; without it, mail servers cannot verify sender authenticity.

### dns_spf_permissive

> CRITICAL, implemented

The '+all' mechanism in an SPF record authorizes any server on the internet to send email for this domain, negating anti-spoofing protection.

### dns_spf_invalid

> WARNING, planned

An SPF TXT record must be well-formed to be evaluated by mail servers; a malformed record is treated as absent.

### dns_spf_multiple

> WARNING, planned

Only one SPF TXT record is permitted per domain; multiple records cause a 'permerror' result, effectively disabling SPF evaluation.

### dns_dmarc_missing

> NOTICE, implemented

A DMARC record at '_dmarc.<domain>' specifies how mail receivers should handle messages that fail SPF or DKIM checks.

### dns_dmarc_policy_none

> WARNING, planned

The DMARC 'p=none' policy collects reports without rejecting or quarantining messages that fail authentication.

### dns_dmarc_invalid

> WARNING, planned

A DMARC record must be well-formed to be evaluated by mail servers; a malformed record is treated as absent.

### dns_dkim_missing

> NOTICE, planned

DKIM TXT records publish public keys used to verify that outbound email was not tampered with in transit.

### dns_mta_sts_missing

> NOTICE, planned

MTA-STS allows domains to publish a policy requiring mail servers to deliver email over TLS, preventing downgrade attacks.

### dns_caa_missing

> WARNING, planned

CAA records restrict which certificate authorities are permitted to issue TLS certificates for this domain.

### dns_dnssec_missing

> NOTICE, planned

DNSSEC signs DNS responses, allowing resolvers to verify their authenticity and detect spoofed or poisoned records.

### dns_nameserver_single

> NOTICE, planned

Multiple authoritative nameservers provide redundancy; a single nameserver is a single point of failure for DNS resolution.

## Response

### response_redirect_https_downgrade

> CRITICAL, planned

A redirect from HTTPS to HTTP downgrades transport security, exposing the request and response to interception.

### response_redirect_http_upgrade_missing

> WARNING, planned

An HTTP-to-HTTPS redirect ensures clients that connect over plain HTTP are upgraded to an encrypted connection.

### response_status_server_error

> WARNING, planned

5xx responses indicate a server-side error and may expose stack traces, internal paths, or signal misconfiguration.

### response_redirect_chain_long

> NOTICE, planned

Redirect chains longer than 3 hops add latency, may indicate misconfiguration, and can cause security tools to miss intermediate steps.

### response_redirect_chain_mixed_schemes

> NOTICE, planned

A redirect chain that switches between HTTP and HTTPS exposes intermediate requests over plaintext, leaking URLs and headers.

### response_time_slow

> NOTICE, planned

Response time above the threshold may indicate resource exhaustion, network issues, or a misconfigured upstream service.

## References

- [HTTP Strict Transport Security (HSTS)](https://datatracker.ietf.org/doc/html/rfc6797)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)

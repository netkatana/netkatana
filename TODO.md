# Planned checks

## HTTP

- `headers_x_content_type_options_missing` — warning
- `headers_x_content_type_options_invalid` — warning
- `headers_x_frame_options_missing` — warning
- `headers_x_frame_options_invalid` — warning
- `headers_cross_origin_resource_policy_missing` — warning
- `headers_cross_origin_opener_policy_missing` — warning
- `headers_cookie_missing_secure` — critical
- `headers_cookie_missing_httponly` — warning
- `headers_cookie_missing_samesite` — warning
- `headers_cookie_prefix_secure_misconfigured` — critical
- `headers_cookie_prefix_host_misconfigured` — critical
- `headers_cookie_prefix_secure_missing` — notice
- `headers_cookie_prefix_host_missing` — notice
- `headers_referrer_policy_missing` — notice
- `headers_permissions_policy_missing` — notice
- `headers_cross_origin_embedder_policy_missing` — notice
- `headers_x_permitted_cross_domain_policies_missing` — notice
- `headers_server_disclosure` — notice
- `headers_x_powered_by_disclosure` — notice
- `headers_x_xss_protection_deprecated` — notice
- `headers_expect_ct_deprecated` — notice
- `headers_feature_policy_deprecated` — notice

## TLS

- `tls_cert_expiring` — critical/warning (≤7 days: critical, ≤30 days: warning)
- `tls_cert_key_size_small` — warning
- `tls_cert_weak_signature` — warning
- `tls_no_forward_secrecy` — warning
- `tls_compression_enabled` — warning

## DNS

- `dns_zone_transfer_enabled` — critical
- `dns_dangling_cname` — critical
- `dns_spf_invalid` — warning
- `dns_dmarc_policy_none` — warning
- `dns_dmarc_invalid` — warning
- `dns_dmarc_multiple` — warning
- `dns_dkim_missing` — notice
- `dns_mta_sts_missing` — notice
- `dns_caa_missing` — warning
- `dns_dnssec_missing` — notice
- `dns_nameserver_single` — notice

## Response

- `response_redirect_https_downgrade` — critical
- `response_redirect_http_upgrade_missing` — warning
- `response_status_server_error` — warning
- `response_redirect_chain_long` — notice
- `response_redirect_chain_mixed_schemes` — notice
- `response_time_slow` — notice

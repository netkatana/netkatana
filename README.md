# netkatana

🚧Experiment, under construction 🚧

Security scanner for HTTP headers, TLS certificates (using [tlsx](https://github.com/projectdiscovery/tlsx)),
and DNS configuration.

```sh
uvx netkatana http example.com
uvx netkatana tls example.com
uvx netkatana dns example.com
```

Implemented checks:

- headers_hsts_missing
- headers_hsts_invalid
- headers_hsts_max_age_zero
- headers_hsts_max_age_low
- headers_hsts_include_subdomains_missing
- headers_hsts_preload_not_eligible
- headers_csp_missing
- headers_csp_unsafe_inline
- headers_csp_unsafe_eval
- headers_csp_object_src_unsafe
- headers_csp_base_uri_missing
- headers_csp_frame_ancestors_missing
- headers_csp_form_action_missing
- headers_csp_script_src_missing
- headers_csp_script_src_unrestricted
- headers_csp_style_src_missing
- headers_csp_style_src_unrestricted
- headers_csp_connect_src_missing
- headers_csp_connect_src_unrestricted
- headers_csp_report_only_unsafe_inline
- headers_csp_report_only_unsafe_eval
- headers_csp_report_only_object_src_unsafe
- headers_csp_report_only_base_uri_missing
- headers_csp_report_only_frame_ancestors_missing
- headers_csp_report_only_form_action_missing
- headers_csp_report_only_script_src_missing
- headers_csp_report_only_script_src_unrestricted
- headers_csp_report_only_style_src_missing
- headers_csp_report_only_style_src_unrestricted
- headers_csp_report_only_connect_src_missing
- headers_csp_report_only_connect_src_unrestricted
- headers_cors_allow_origin_wildcard
- headers_cors_allow_origin_null
- headers_cors_allow_credentials_wildcard
- headers_cors_allow_credentials_invalid
- headers_cors_allow_methods_unsafe
- headers_cors_max_age_excessive
- tls_version_deprecated
- tls_version_outdated
- tls_cert_expired
- tls_cert_self_signed
- tls_cert_mismatched
- tls_cert_revoked
- tls_cert_untrusted
- tls_cipher_weak
- dns_spf_missing
- dns_spf_multiple
- dns_spf_permissive
- dns_dmarc_missing
- dns_dmarc_multiple

Architecture notes:

- rules are defined in [src/netkatana/rules.py](src/netkatana/rules.py)
- validators live under [src/netkatana/validators](src/netkatana/validators)

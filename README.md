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
- headers_corp_missing
- headers_corp_invalid
- headers_corp_same_site
- headers_corp_cross_origin
- headers_coep_missing
- headers_coep_invalid
- headers_coep_unsafe_none
- headers_coep_credentialless
- headers_coep_report_only_invalid
- headers_coep_report_only_unsafe_none
- headers_coep_report_only_credentialless
- headers_coop_missing
- headers_coop_invalid
- headers_coop_unsafe_none
- headers_coop_same_origin_allow_popups
- headers_coop_noopener_allow_popups
- headers_coop_report_only_invalid
- headers_coop_report_only_unsafe_none
- headers_coop_report_only_same_origin_allow_popups
- headers_coop_report_only_noopener_allow_popups
- headers_x_content_type_options_missing
- headers_x_content_type_options_invalid
- headers_x_content_type_options_duplicated
- headers_referrer_policy_missing
- headers_referrer_policy_invalid
- headers_referrer_policy_unsafe
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

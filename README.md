# netkatana

[![CI](https://github.com/netkatana/netkatana/actions/workflows/ci.yml/badge.svg)](https://github.com/netkatana/netkatana/actions/workflows/ci.yml)

🚧Experiment, under construction 🚧

Security scanner for HTTP headers, TLS certificates (using [tlsx](https://github.com/projectdiscovery/tlsx)),
and DNS configuration.

```sh
uvx netkatana http example.com
uvx netkatana tls example.com --severity critical
uvx netkatana dns example.com
```

## Implemented Checks

- HTTP: 247 checks
- HTTP headers: 241 checks
- HTTP response behavior: 6 checks
- CSP: 191 checks
- HSTS: 7 checks
- CORS: 6 checks
- COOP / COEP / CORP: 20 checks
- Cookies: 6 checks
- TLS: 8 checks
- DNS: 5 checks

Architecture notes:

- rules are defined in [rules.py](https://github.com/netkatana/netkatana/blob/main/src/netkatana/rules.py)
- validators live under [validators](https://github.com/netkatana/netkatana/tree/main/src/netkatana/validators)

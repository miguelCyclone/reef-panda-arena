# Security policy

This repository contains a **synthetic, local-only security research arena** with C00–C43 replay cases. It is not approved for use with production secrets, real customer records, arbitrary endpoints, or public network exposure.

Please disclose suspected vulnerabilities privately through the repository host's security advisory feature when available; otherwise contact the maintainers through a non-public channel listed on the future project page. Do not file an issue containing credentials or real exfiltration data. Maintainers have not yet published a support or patch SLA.

Avoid running third-party or unknown agent tools in the same host context as personal secrets. Run with least privilege and bind local services to loopback.

Private database receipts retain payload integrity digests. Ordinary API/SSE events expose bounded metadata and redacted lineage, excluding raw payloads, receiver keys and target-dependent payload digests. A database reader is outside the modeled actor boundary; a digest of a low-entropy value can enable offline guessing. This is a local synthetic arena, not a secrecy guarantee for production data. Raw model prompt/response capture is not enabled. Use only synthetic fixtures and keep the service bound to loopback.

The booking UI provides an explicit post-run **Reveal synthetic data** action: `POST /v1/booking/runs/{run_id}/inspection` with `reveal_synthetic: true`. This intentionally reveals the fictional source attribute and receiver convention to the local human operator, plus finite accepted-payload reconstructions verified against saved receipt hashes. It is separate from sanitized reports/SSE, refuses active runs or unverified fixtures, uses `Cache-Control: no-store`, and never returns installation keys or changes experiment scoring. Published demonstration screenshots may include this explicitly revealed synthetic evidence.

## Dependency versions and historical archives

The current installer requires patched dependency lines: `cryptography>=50,<51`, `setuptools>=84.1,<85`, and `pip>=26.2,<27`. The publication review checked installed dependencies with `pip-audit`; a clean scan means no known advisories returned at that time, not a general security guarantee.

The source archives under `docs/data/` are immutable research evidence. They preserve the dependencies actually used in historical experiments, including older versions with subsequently identified advisories. Use the current checkout and installer for normal execution. Archived environments are for isolated historical reproduction with synthetic data; their dependency metadata is not a recommendation to deploy those versions.

Relevant upstream fixes: [cryptography PKCS#7 decryption](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5), [setuptools legacy wheel installation](https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w), and [pip advisory](https://github.com/advisories/GHSA-qwm4-qh6w-59xr).

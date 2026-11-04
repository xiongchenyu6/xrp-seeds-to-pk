# Dependency security notes

Verified 2026-11-04. Install from the committed Poetry/Cargo locks; the Python
manifest also declares security floors for the HTTP transport, certifi and PyNaCl.

## Remaining python-ecdsa advisory

`bip-utils 2.12.3 -> ecdsa 0.19.2` remains affected by
[CVE-2024-23342 / GHSA-wj6h-64fc-37mp](https://github.com/tlsfuzzer/python-ecdsa/security/advisories/GHSA-wj6h-64fc-37mp).
Upstream lists every version as affected and explicitly plans no fix. The reported
Minerva attack concerns P-256 signing; upstream also warns that its scalar
multiplication is not constant-time, affecting key generation and ECDH. An
attacker able to measure sufficient private-operation timings may recover key
material. Signature verification is unaffected.

The converter's BIP44 Ripple path uses secp256k1 through native coincurve, selected
by bip-utils' default `EccConf.USE_COINCURVE`. Regression tests verify that backend
and derive nine synthetic cases while blocking python-ecdsa private-key creation,
signing and ECDH APIs. This is evidence about this conversion path, not a claim
that the installed ecdsa package is fixed or that every dependency is constant-time.
Do not change the backend to python-ecdsa or reuse it for private-key operations.
Removing the package requires replacing bip-utils and separately validating the
cryptographic migration; deleting it from the lock alone breaks declared dependencies.
The advisory is deliberately not suppressed or dismissed.

Run `poetry sync --no-root` and `poetry run python -m unittest discover -s tests -v`
with Python 3.10–3.13. The tests never execute the script's top-level example input.

## Patched Rust TLS dependency

Cargo updated `rustls 0.23.40 -> 0.23.46` and its required
`rustls-webpki 0.103.13 -> 0.103.16`, without changing application code or other
locked packages. The lock dependency path is
`xrpl-rust -> reqwest -> hyper-rustls -> tokio-rustls/rustls`.
Rustls is optional: `cargo tree --locked --offline --target all -i rustls` has no
active reverse dependency with the current default feature selection. The CLI
uses xrpl-rust for local wallet derivation, not TLS requests. Updating the lock
still protects future feature selection and resolves the vulnerable package record.

| Advisory | Impact / triggering condition | First fixed |
| --- | --- | --- |
| [GHSA-2mjx-qc3c-rqvc](https://github.com/advisories/GHSA-2mjx-qc3c-rqvc) | A peer can send TLS 1.3 handshake messages across encryption boundaries; transcript authentication still applies. | 0.23.45 |
| [GHSA-h2v8-394m-p7vv](https://github.com/advisories/GHSA-h2v8-394m-p7vv) | Enabling Brotli certificate decompression permits attacker-controlled allocation up to 1 GiB and denial of service. | 0.23.46 |
| [GHSA-c8m5-c952-6cm4](https://github.com/advisories/GHSA-c8m5-c952-6cm4) | Custom session-store Debug logging can expose TLS master secrets or resumption PSKs. | 0.23.46 |
| [GHSA-w44r-93j7-qv28](https://github.com/advisories/GHSA-w44r-93j7-qv28) | An unauthenticated ServerHello can poison cached per-name key-exchange hints, allowing later classical-only negotiation when the server accepts that share. | 0.23.46 |

Dependabot alerts on the default branch remain open until the fix is merged and
GitHub rescans. A draft PR and successful tests do not close those alerts.

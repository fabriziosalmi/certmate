# Post-quantum cryptography

What CertMate does with post-quantum cryptography today, and what it does not. Each
statement below names the test or the measurement it rests on.

There are three separate questions. Their answers differ:

| | Today |
| --- | --- |
| [Key exchange](#key-exchange) on CertMate's own TLS connections | Hybrid post-quantum, in the Docker image |
| [Certificates and signatures](#certificates-and-signatures) | Classical (RSA, ECDSA, Ed25519) |
| [Inventory](#inventory) of what you have deployed | Classifies classical algorithms as quantum-vulnerable |

## Key exchange

Key exchange protects what is sent over a TLS connection against an attacker who records
it now and decrypts it later with a quantum computer.

- **CertMate's outbound connections, in the Docker image.** The image's OpenSSL 3.5 offers
  the hybrid group `X25519MLKEM768` (RFC 10024) by default, so a connection made through
  Python's `ssl` module with a default context offers it, as certbot's requests to the CA's
  ACME directory do. The probe that checks whether an endpoint still accepts TLS 1.0 or 1.1
  does not, by design: those versions have no such group. Every image build checks the
  default, inside the built image (`scripts/check_hybrid_key_exchange.py`, run by the
  `build` job in `.github/workflows/ci.yml`).
- **Whether it is used depends on the server.** The hybrid group is offered, and the server
  picks. Measured on 7 November 2026: `api.cloudflare.com` negotiated `X25519MLKEM768`;
  `acme-v02.api.letsencrypt.org` did not offer it and negotiated `X25519`.
- **Installed from source** (pip, systemd), CertMate uses the host's OpenSSL, and offers the
  hybrid group only with OpenSSL 3.5 or later. `GET /api/diagnostics/snapshot` (admin)
  reports the version in `openssl_version`.
- **The web interface and the API** are plain HTTP behind your reverse proxy. Post-quantum
  key exchange there is the proxy's to offer: with OpenSSL, that means OpenSSL 3.5 or later.

## Certificates and signatures

A certificate's signature proves who the server is. It does not protect recorded traffic,
so it is less urgent than key exchange, and it is not yet possible on the public web.

- **Publicly trusted certificates.** CertMate issues these with certbot, which offers RSA
  and ECDSA keys (`--key-type {rsa,ecdsa}` in certbot 5.8.0). The CA/Browser Forum Baseline
  Requirements (version 2.3.1) permit only RSA and ECDSA in publicly trusted TLS
  certificates. Let's Encrypt has announced Merkle Tree Certificates as its post-quantum
  path, with staging targeted for late 2026 and production for 2027 (its post of 3 June
  2026). CertMate will follow when certbot supports it.
- **CertMate's own CAs** (the client certificate CA and the ACME server) have RSA 4096
  roots. The cryptography library CertMate ships can sign ML-DSA certificates, CSRs and CRLs
  (`tests/test_the_pinned_cryptography_speaks_ml_dsa.py`), but CertMate does not offer an
  ML-DSA CA yet.
- **The audit trail** is signed with Ed25519, a classical algorithm.

## Inventory

The [cryptographic readiness report](./discovery-inventory.md#cryptographic-readiness-report)
classifies every managed and discovered certificate:

- RSA, ECDSA and EdDSA keys are flagged as quantum-vulnerable. NIST IR 8547 (Final, October
  2026) deprecates them after 2030 and disallows them after 2035.
- A key algorithm the report does not recognise is counted apart, as not known
  (`quantum_vulnerability_unknown`), and never as quantum-safe. An ML-DSA certificate found
  by discovery is in that count today, because the probe does not name ML-DSA yet.
- Whether a stored private key belongs to its certificate is checked by comparing the public
  keys' bytes, which works for every algorithm, ML-DSA included.

## Sources

- RFC 10024, hybrid key agreement for TLS 1.3 (`X25519MLKEM768`).
- RFC 9881, ML-DSA in X.509 certificates.
- CA/Browser Forum, TLS Baseline Requirements, version 2.3.1, sections 6.1.5 and 7.1.3.1.
- Let's Encrypt, "A Post-Quantum Future for Let's Encrypt", 3 June 2026.
- NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", Final, October 2026,
  Table 2.

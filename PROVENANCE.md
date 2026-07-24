# Reconstruction provenance

Reconstruction date: 2026-07-23

## Inputs

- Recovered baseline archive: `ebae-reference-prototype.zip`
  - SHA-256: `8de8912f134838a99758cbf759f50b785147a6f5e9be3892f136eae72acdf5e7`
  - Observed result: 17/17 tests passed.
- Supplied audit record: `AUDITEBAE.pdf`
  - SHA-256: `810f72e753b3e4b989cf88f192098fa2bcfbf783f1f756520ee7c70f3a6b00e2`
- Paper record: <https://doi.org/10.5281/zenodo.21385239>

## Identity statement

This is a **new reconstructed build**, not a byte-for-byte recovery of the
previously reported final archive. The earlier final archive was reported
as `ebae-reference-prototype-v0.2.zip` with SHA-256:

`82d44c4cfb14249a2731ae5c53fa1aa2fee118f794c0a7ee28532da1044b15ed`

That earlier archive was not available as a reconstruction input. This
package therefore has a new package checksum. Its member checksums are in
`SHA256SUMS`, and the outer ZIP checksum is supplied alongside the ZIP.

## Verification environment

- Python 3.12.13
- `cryptography` 46.0.0
- Linux
- Two consecutive clean-directory verification runs passed 29/29.

No claim is made that passing this finite suite establishes production
security or reproduces an unavailable archive exactly.


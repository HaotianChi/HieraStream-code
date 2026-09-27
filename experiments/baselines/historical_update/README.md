# Historical ciphertext-update baseline

## Class of approaches
Must process **accumulated historical CP-ABE ciphertexts** after an attribute
secret changes — distinct from HieraStream **prospective** revocation
(current-state key refresh only; historical CT untouched).

## Algebra
Attribute `a`: `t_old → t_new`, `PK_a = g^{t_a}`.

Leaf component `C_a = PK_a^{q} = g^{t_a · q}` updates as:

```
C_a' = C_a ^{t_new / t_old} = g^{t_new · q}
```

so refreshed keys `E_ua' = g^{β r_u / t_new}` satisfy
`e(E_ua', C_a') = e(g,g)^{β r_u q}`.

AES payloads and role envelopes are **not** rewritten.

## Instrumented metrics
- `historical_segments_touched`
- `leaf_components_updated`
- `cryptographic_update_s`
- `bytes_read` / `bytes_written`
- `metadata_storage_update_work`
- `aes_payloads_rewritten` (must be 0)
- `role_envelopes_rewritten` (must be 0)

## Implementation
`baseline.py` — `HistoricalUpdateBaseline.revoke_with_historical_update`

## Secrecy
`t_old`, `t_new`, and update ratios are never exported in return values or logs.

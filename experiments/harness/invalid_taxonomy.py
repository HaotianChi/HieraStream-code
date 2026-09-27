"""Invalid / failure taxonomy for live Fabric E3.

Categories (manuscript must not conflate client failures with Fabric invalids):

A. FABRIC_VALIDATION — ledger validation (e.g. MVCC_READ_CONFLICT)
B. CHAINCODE_REJECT — chaincode / business-rule rejection
C. ENDORSEMENT_FAIL — endorsement / proposal failure
D. GATEWAY_COMMIT — Gateway commit/status error (non-MVCC)
E. CLIENT_HTTP — client HTTP / transport to bench
F. TIMEOUT — deadline / timeout
G. RESOURCE_EXHAUST — connection / FD / resource exhaustion
H. UNKNOWN
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, Mapping, MutableMapping


CATEGORIES = (
    "A_FABRIC_VALIDATION",
    "B_CHAINCODE_REJECT",
    "C_ENDORSEMENT_FAIL",
    "D_GATEWAY_COMMIT",
    "E_CLIENT_HTTP",
    "F_TIMEOUT",
    "G_RESOURCE_EXHAUST",
    "H_UNKNOWN",
)


def classify_failure(status: str = "", reason: str = "", code: str = "") -> str:
    s = f"{status} {reason} {code}".upper()
    if not s.strip() or status.upper() == "VALID":
        return "VALID"

    # A — Fabric validation
    if "MVCC" in s or "MVCC_READ_CONFLICT" in s:
        return "A_FABRIC_VALIDATION"
    if "VALIDATION" in s and ("CODE" in s or "FAILED" in s):
        return "A_FABRIC_VALIDATION"

    # F — timeout / deadline
    if "TIMEOUT" in s or "DEADLINE" in s or "TIMED OUT" in s or "CONTEXT DEADLINE" in s:
        return "F_TIMEOUT"

    # G — resource / connection exhaustion
    if any(
        x in s
        for x in (
            "TOO MANY OPEN FILES",
            "CONNECTION RESET",
            "CONNECTION REFUSED",
            "BROKEN PIPE",
            "CANNOT ASSIGN REQUESTED ADDRESS",
            "RESOURCE TEMPORARILY UNAVAILABLE",
            "EMFILE",
            "ENFILE",
            "ECONNRESET",
            "ECONNREFUSED",
        )
    ):
        return "G_RESOURCE_EXHAUST"

    # E — client HTTP to bench
    if any(x in s for x in ("HTTP ERROR", "URLERROR", "REMOTE DISCONNECTED", "BAD STATUS LINE")):
        return "E_CLIENT_HTTP"
    if status.upper() in {"HTTP_ERROR", "CLIENT_ERROR"}:
        return "E_CLIENT_HTTP"

    # C — endorsement
    if "ENDORSE" in s or "ENDORSEMENT" in s:
        return "C_ENDORSEMENT_FAIL"

    # B — chaincode / ACL business reject
    if any(
        x in s
        for x in (
            "ACL_DENIED",
            "CHAINCODE",
            "POLICY",
            "UNAUTHORIZED",
            "DENIED",
            "INVALID ARG",
            "VERSION MISMATCH",
            "AUTHSTATE",
        )
    ):
        # ACL is chaincode/business path for our CC
        if "ACL" in s or "DENIED" in s or "UNAUTHORIZED" in s:
            return "B_CHAINCODE_REJECT"
        if "CHAINCODE" in s or "VERSION" in s or "AUTHSTATE" in s:
            return "B_CHAINCODE_REJECT"

    # D — gateway commit / status
    if any(x in s for x in ("COMMIT", "GATEWAY", "SUBMIT", "STATUS")):
        return "D_GATEWAY_COMMIT"
    if status.upper() in {"INVALID", "FAILED"} and reason:
        return "D_GATEWAY_COMMIT"

    if status.upper() in {"INVALID", "FAILED", "ERROR"}:
        return "H_UNKNOWN"
    return "H_UNKNOWN"


def summarize_failures(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """rows: mappings with status/reason/code (or invalid_category)."""
    counts: Counter[str] = Counter()
    total = 0
    invalid = 0
    for r in rows:
        total += 1
        cat = r.get("invalid_category")
        if not cat:
            st = str(r.get("status", r.get("validation_status", "")))
            if st.upper() == "VALID":
                counts["VALID"] += 1
                continue
            cat = classify_failure(
                status=st,
                reason=str(r.get("reason", r.get("error", ""))),
                code=str(r.get("code", "")),
            )
        if cat == "VALID":
            counts["VALID"] += 1
            continue
        invalid += 1
        counts[str(cat)] += 1

    rates = {k: (counts[k] / total if total else 0.0) for k in CATEGORIES}
    rates["VALID"] = counts["VALID"] / total if total else 0.0
    return {
        "total": total,
        "invalid": invalid,
        "invalid_rate": invalid / total if total else 0.0,
        "counts": {k: int(counts.get(k, 0)) for k in ("VALID",) + CATEGORIES},
        "rates": rates,
    }


def attach_category(out: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    st = str(out.get("status", "INVALID"))
    if st.upper() == "VALID":
        out["invalid_category"] = "VALID"
    else:
        out["invalid_category"] = classify_failure(
            status=st,
            reason=str(out.get("reason", out.get("error", ""))),
            code=str(out.get("code", "")),
        )
    return out

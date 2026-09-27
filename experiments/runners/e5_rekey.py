"""E5 — Current-state rekey scalability (attribute revocation + role reassignment)."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary
from experiments.harness.run_context import create_run, load_config


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.authorization.lifecycle import AuthorizationLifecycle
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto

    cfg = load_config("rekey", config_path)
    holders = [2, 4] if smoke else list(cfg.get("holders", [10, 50, 100]))
    role_bindings = [2, 4] if smoke else list(cfg.get("role_bindings", [10, 50, 100]))
    repeats = 1 if smoke else int(cfg.get("repeats", 3))

    run_ctx = create_run(
        "rekey",
        {**cfg, "smoke": smoke, "holders": holders, "role_bindings": role_bindings},
    )

    # --- Attribute revocation: vary non-revoked holders ---
    for n in holders:
        for rep in range(repeats):
            crypto = SegmentCrypto()
            lc = AuthorizationLifecycle(
                owner_id="e5-attr",
                crypto=crypto,
                hierarchy=HEALTHCARE_FIXTURE,
                attr_universe=["doctor", "cardiology", "nurse", "emergency", "researcher"],
            )
            lc.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
            for i in range(n):
                lc.provision_user(f"u{i}", ["doctor", "cardiology"], ["AttendingPhysician"])

            t0 = time.perf_counter()
            snap = lc.revoke_attribute("doctor", revoked_users=["u0"])
            auth_s = time.perf_counter() - t0

            # Measure refreshed key material from last public commit payload path
            # issued_Eua was applied into keys; count refreshed users = n-1 holders of doctor
            refreshed = 0
            refreshed_bytes = 0
            for uid in [f"u{i}" for i in range(n)]:
                if uid == "u0":
                    continue
                cur = lc.keys.current_attr(uid) if lc.keys else None
                if cur is None:
                    continue
                if "doctor" in cur.material.E_ua:
                    refreshed += 1
                    refreshed_bytes += len(cur.material.E_ua["doctor"].to_bytes())

            # Distribution bytes ≈ refreshed key hex payloads (no UpdateRatio)
            dist_bytes = refreshed_bytes
            row: Dict[str, Any] = {
                "experiment": "E5",
                "phase": "attribute_revocation",
                "non_revoked_holders": n - 1,
                "total_users": n,
                "authority_computation_s": auth_s,
                "refreshed_key_count": refreshed,
                "refreshed_key_bytes": refreshed_bytes,
                "update_distribution_bytes": dist_bytes,
                "new_version": snap.version,
                "repeat": rep,
            }
            run_ctx.add_row(row)

        subset = [r for r in run_ctx.rows if r.get("phase") == "attribute_revocation" and r.get("non_revoked_holders") == n - 1]
        run_ctx.add_row(
            {
                "experiment": "E5",
                "phase": "attribute_revocation_summary",
                "non_revoked_holders": n - 1,
                **latency_summary([r["authority_computation_s"] for r in subset], prefix="authority_computation_s"),
            }
        )

    # --- Role reassignment: vary active role-user bindings ---
    for n in role_bindings:
        for rep in range(repeats):
            crypto = SegmentCrypto()
            lc = AuthorizationLifecycle(
                owner_id="e5-role",
                crypto=crypto,
                hierarchy=HEALTHCARE_FIXTURE,
                attr_universe=["doctor", "cardiology"],
            )
            lc.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
            membership: Dict[str, List[str]] = {}
            for i in range(n):
                uid = f"r{i}"
                lc.provision_user(uid, ["doctor", "cardiology"], ["AttendingPhysician"])
                membership[uid] = ["AttendingPhysician"]

            t0 = time.perf_counter()
            # Reassignment: demote half to Nurse (membership change)
            new_mem = {
                uid: (["Nurse"] if int(uid[1:]) % 2 == 0 else ["AttendingPhysician"])
                for uid in membership
            }
            snap = lc.reassign_roles(new_mem)
            auth_s = time.perf_counter() - t0

            refreshed = 0
            refreshed_bytes = 0
            for uid in membership:
                cur = lc.keys.current_role(uid) if lc.keys else None
                if cur is None:
                    continue
                for rk in cur.material.RK.values():
                    refreshed += 1
                    refreshed_bytes += len(rk.to_bytes())

            row = {
                "experiment": "E5",
                "phase": "role_reassignment",
                "active_role_user_bindings": n,
                "authority_computation_s": auth_s,
                "refreshed_key_count": refreshed,
                "refreshed_key_bytes": refreshed_bytes,
                "update_distribution_bytes": refreshed_bytes,
                "new_version": snap.version,
                "repeat": rep,
            }
            run_ctx.add_row(row)

        subset = [r for r in run_ctx.rows if r.get("phase") == "role_reassignment" and r.get("active_role_user_bindings") == n]
        run_ctx.add_row(
            {
                "experiment": "E5",
                "phase": "role_reassignment_summary",
                "active_role_user_bindings": n,
                **latency_summary([r["authority_computation_s"] for r in subset], prefix="authority_computation_s"),
            }
        )

    run_ctx.extra = {"experiment": "E5"}
    run_ctx.finish()
    return 0

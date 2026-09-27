"""Unit tests: dual-layer crypto + hierarchy + segment key (simulated backend)."""

from __future__ import annotations

import pytest

from core.protocol.system import HieraStreamSystem, and_gate, leaf, thresh
from core.roles.hierarchy import DEFAULT_HEALTHCARE_HIERARCHY, validate_dominates_fix
from core.crypto.python_ref.simulated import derive_segment_key


def test_hierarchy_path_monotonicity():
    validate_dominates_fix(DEFAULT_HEALTHCARE_HIERARCHY)
    h = DEFAULT_HEALTHCARE_HIERARCHY
    assert h.dominates("ChiefMedicalOfficer", "Resident")
    assert h.dominates("AttendingPhysician", "Resident")
    assert not h.dominates("Resident", "AttendingPhysician")
    assert not h.dominates("Nurse", "Resident")


def test_authorized_access_success():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("u1", ["doctor", "cardiology"], ["AttendingPhysician"])
    seg = sys.protect_and_publish(b"ehr-segment-1", targets=["Resident"])
    pt = sys.access("u1", seg.seg_id)
    assert pt == b"ehr-segment-1"


def test_attribute_unauthorized_fails():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("u2", ["nurse"], ["Nurse"])
    seg = sys.protect_and_publish(b"secret", targets=["Nurse"])
    with pytest.raises(PermissionError):
        sys.access("u2", seg.seg_id)


def test_role_unauthorized_fails():
    sys = HieraStreamSystem()
    sys.setup()
    # Satisfies attribute policy but only Nurse role; target is Resident
    sys.provision_user("u3", ["doctor", "cardiology"], ["Nurse"])
    seg = sys.protect_and_publish(b"secret", targets=["Resident"])
    with pytest.raises(PermissionError):
        sys.access("u3", seg.seg_id)


def test_ancestor_role_inherits_target():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("chief", ["doctor", "cardiology"], ["ChiefMedicalOfficer"])
    seg = sys.protect_and_publish(b"lvad-trace", targets=["Resident"])
    assert sys.access("chief", seg.seg_id) == b"lvad-trace"


def test_threshold_policy():
    sys = HieraStreamSystem()
    sys.setup()
    sys.active_tree = thresh(2, leaf("doctor"), leaf("nurse"), leaf("researcher"))
    # Re-install policy id would require auth update; for unit crypto path,
    # protect uses active_tree directly.
    sys.provision_user("u", ["doctor", "researcher"], ["AttendingPhysician"])
    seg = sys.protect_and_publish(b"x", targets=["AttendingPhysician"])
    assert sys.access("u", seg.seg_id) == b"x"


def test_multi_target_independent_d():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("u", ["doctor", "cardiology"], ["Nurse"])
    seg = sys.protect_and_publish(b"m", targets=["Nurse", "Resident"])
    ds = [e.d for e in seg.role_envelopes]
    assert len(ds) == 2 and ds[0] != ds[1]
    assert sys.access("u", seg.seg_id) == b"m"


def test_kdf_domain_separation():
    # Same GT value through different domain tags must differ
    from core.crypto.python_ref.simulated import kdf_gt

    z = 123456789
    assert kdf_gt(z, b"HieraStream-Attribute-v1") != kdf_gt(z, b"HieraStream-Role-v1")
    k = derive_segment_key(1, 2)
    assert len(k) == 32

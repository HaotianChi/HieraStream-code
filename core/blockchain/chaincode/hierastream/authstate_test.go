package main

import "testing"

func TestEtaDigestStable(t *testing.T) {
	a := EtaDigest("c", "m", 0, "p", "a", "r")
	b := EtaDigest("c", "m", 0, "p", "a", "r")
	if a != b || len(a) != 64 {
		t.Fatalf("unstable eta: %s", a)
	}
	if EtaDigest("c", "m", 1, "p", "a", "r") == a {
		t.Fatal("version should change eta")
	}
}

func TestValidateCommitSegment(t *testing.T) {
	auth := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	eta := EtaDigest("cid", "mcid", 0, "p", "a", "r")
	rec, err := ValidateCommitSegment(auth, "cid", "mcid", 0, "p", "a", "r", eta)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CID != "cid" {
		t.Fatal(rec)
	}
	_, err = ValidateCommitSegment(auth, "cid", "mcid", 1, "p", "a", "r", eta)
	if err == nil {
		t.Fatal("expected snapshot mismatch")
	}
}

func TestNextAuthRecord(t *testing.T) {
	cur := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	next := AuthRecord{Version: 1, PolicyID: "p2", AttrStateID: "a", RoleStateID: "r"}
	got, err := NextAuthRecord(cur, cur, next)
	if err != nil || got.Version != 1 {
		t.Fatalf("%v %v", got, err)
	}
	_, err = NextAuthRecord(cur, cur, AuthRecord{Version: 2, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"})
	if err == nil {
		t.Fatal("expected version increment error")
	}
	// Explicit expectedVersion mismatch: leave state conceptually unchanged (no write here).
	stale := AuthRecord{Version: 1, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	_, err = NextAuthRecord(cur, stale, AuthRecord{Version: 2, PolicyID: "p2", AttrStateID: "a", RoleStateID: "r"})
	if err == nil || err.Error() != "expectedVersion mismatch" {
		t.Fatalf("expected expectedVersion mismatch, got %v", err)
	}
	// Carry-forward / policy-only nextRefs
	policyOnly := AuthRecord{Version: 1, PolicyID: "pX", AttrStateID: "a", RoleStateID: "r"}
	got, err = NextAuthRecord(cur, cur, policyOnly)
	if err != nil || got.PolicyID != "pX" || got.AttrStateID != "a" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestCarryForwardAuth(t *testing.T) {
	cur := AuthRecord{Version: 3, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	got := CarryForwardAuth(cur, "p2", "", "")
	if got.Version != 4 || got.PolicyID != "p2" || got.AttrStateID != "a" || got.RoleStateID != "r" {
		t.Fatalf("%+v", got)
	}
}

func TestACLAllows(t *testing.T) {
	if !ACLAllows("CommitSegment", RoleGateway) {
		t.Fatal("gateway should commit")
	}
	if ACLAllows("CommitSegment", RoleAuthority) {
		t.Fatal("authority must not CommitSegment")
	}
	if !ACLAllows("UpdateAuthorization", RoleAuthority) {
		t.Fatal("authority should update")
	}
	if ACLAllows("UpdateAuthorization", RoleGateway) {
		t.Fatal("gateway must not UpdateAuthorization")
	}
	if !ACLAllows("GetAuthorization", RoleUnknown) {
		t.Fatal("queries allowed")
	}
}

func TestWorldStateKeys(t *testing.T) {
	if AuthKey("o1") != "AuthKey/o1" {
		t.Fatal(AuthKey("o1"))
	}
	if SegmentKey("o1", "s") != "Segment/o1/s" {
		t.Fatal(SegmentKey("o1", "s"))
	}
	if PolicyStateKey("p") != "PolicyState/p" {
		t.Fatal(PolicyStateKey("p"))
	}
}

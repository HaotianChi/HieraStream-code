// Package main — HieraStream Hyperledger Fabric chaincode (world-state + Algorithm 1).
//
// Pure authorization/segment logic (no Fabric imports) so offline smoke builds work.
// Fabric contract wiring is in chaincode_fabric.go (build tag: fabric).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// World-state keys
// ---------------------------------------------------------------------------

func AuthKey(ownerID string) string { return "AuthKey/" + ownerID }

func SegmentKey(ownerID, segID string) string {
	return "Segment/" + ownerID + "/" + segID
}

func PolicyStateKey(policyID string) string { return "PolicyState/" + policyID }

func AttributeStateKey(attrStateID string) string { return "AttributeState/" + attrStateID }

func RoleStateKey(roleStateID string) string { return "RoleState/" + roleStateID }

func OwnerRegistryKey(ownerID string) string { return "Owner/" + ownerID }

// ---------------------------------------------------------------------------
// World-state value types
// ---------------------------------------------------------------------------

// AuthRecord is AuthKey(ownerId) — Eq.(10) / Algorithm 1.
type AuthRecord struct {
	Version     int    `json:"version"`
	PolicyID    string `json:"policyId"`
	AttrStateID string `json:"attrStateId"`
	RoleStateID string `json:"roleStateId"`
}

// SegmentRecord is PutState(Segment/owner/segId, R_j).
type SegmentRecord struct {
	CID         string `json:"CID"`
	MCID        string `json:"MCID"`
	Version     int    `json:"version"`
	PolicyID    string `json:"policyId"`
	AttrStateID string `json:"attrStateId"`
	RoleStateID string `json:"roleStateId"`
	Eta         string `json:"eta"`
}

// OwnerRecord registers a sharing domain.
type OwnerRecord struct {
	OwnerID   string `json:"ownerId"`
	GatewayID string `json:"gatewayId"` // expected gateway identity hint
	Active    bool   `json:"active"`
}

// PolicyStateRecord stores a content-addressed policy reference payload.
type PolicyStateRecord struct {
	PolicyID string          `json:"policyId"`
	Version  int             `json:"version"`
	Payload  json.RawMessage `json:"payload"`
}

// AttributeStateRecord stores public attribute-state reference payload.
type AttributeStateRecord struct {
	AttrStateID string          `json:"attrStateId"`
	Version     int             `json:"version"`
	Payload     json.RawMessage `json:"payload"`
}

// RoleStateRecord stores public role-state reference payload.
type RoleStateRecord struct {
	RoleStateID string          `json:"roleStateId"`
	Version     int             `json:"version"`
	Payload     json.RawMessage `json:"payload"`
}

// ---------------------------------------------------------------------------
// Digests / Algorithm 1 / UpdateAuthorization
// ---------------------------------------------------------------------------

// EtaDigest mirrors core/canonical.py::eta_digest (UTF-8 fields, 0x1F separators).
func EtaDigest(cid, mcid string, version int, policyID, attrStateID, roleStateID string) string {
	parts := []string{cid, mcid, fmt.Sprintf("%d", version), policyID, attrStateID, roleStateID}
	blob := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(blob))
	return hex.EncodeToString(sum[:])
}

// ValidateCommitSegment implements Algorithm 1 checks (without ledger I/O).
func ValidateCommitSegment(auth AuthRecord, cid, mcid string, version int,
	policyID, attrStateID, roleStateID, eta string) (SegmentRecord, error) {
	if auth.Version != version || auth.PolicyID != policyID ||
		auth.AttrStateID != attrStateID || auth.RoleStateID != roleStateID {
		return SegmentRecord{}, fmt.Errorf("authorization snapshot mismatch")
	}
	etaPrime := EtaDigest(cid, mcid, version, policyID, attrStateID, roleStateID)
	if etaPrime != eta {
		return SegmentRecord{}, fmt.Errorf("eta mismatch")
	}
	if eta == "" {
		return SegmentRecord{}, fmt.Errorf("empty eta")
	}
	return SegmentRecord{
		CID: cid, MCID: mcid, Version: version,
		PolicyID: policyID, AttrStateID: attrStateID, RoleStateID: roleStateID, Eta: eta,
	}, nil
}

// NextAuthRecord implements UpdateAuthorization versioning rules.
// Unchanged references are carried forward by the caller constructing `next`.
//
// Manuscript guard: reject when auth.version != expectedVersion without writing.
// On success, next.Version must be current.Version+1 (complete nextRefs tuple).
// Additional expected policy/attr/role ID match is retained (strict superset of
// the manuscript's version-only check) so stale endorsements cannot rewrite refs
// under a colliding version integer.
func NextAuthRecord(current AuthRecord, expected AuthRecord, next AuthRecord) (AuthRecord, error) {
	if current.Version != expected.Version {
		return AuthRecord{}, fmt.Errorf("expectedVersion mismatch")
	}
	if current.PolicyID != expected.PolicyID ||
		current.AttrStateID != expected.AttrStateID || current.RoleStateID != expected.RoleStateID {
		return AuthRecord{}, fmt.Errorf("expected current state mismatch")
	}
	if next.Version != current.Version+1 {
		return AuthRecord{}, fmt.Errorf("version must increment by exactly one")
	}
	if next.PolicyID == "" || next.AttrStateID == "" || next.RoleStateID == "" {
		return AuthRecord{}, fmt.Errorf("next auth record missing state references")
	}
	return next, nil
}

// CarryForwardAuth builds next AuthRecord, replacing only provided refs (empty = carry).
func CarryForwardAuth(current AuthRecord, newPolicyID, newAttrID, newRoleID string) AuthRecord {
	out := AuthRecord{
		Version:     current.Version + 1,
		PolicyID:    current.PolicyID,
		AttrStateID: current.AttrStateID,
		RoleStateID: current.RoleStateID,
	}
	if newPolicyID != "" {
		out.PolicyID = newPolicyID
	}
	if newAttrID != "" {
		out.AttrStateID = newAttrID
	}
	if newRoleID != "" {
		out.RoleStateID = newRoleID
	}
	return out
}

func MustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// IdentityRole encodes the ACL principal class for a caller.
type IdentityRole string

const (
	RoleGateway   IdentityRole = "gateway"
	RoleAuthority IdentityRole = "authority"
	RoleAdmin     IdentityRole = "admin"
	RoleUnknown   IdentityRole = "unknown"
)

// ParseIdentityRole maps MSP / attribute hints to ACL roles.
// Accepts: "gateway", "authority", "admin", or composite "gateway:owner-1".
func ParseIdentityRole(hint string) IdentityRole {
	h := strings.ToLower(strings.TrimSpace(hint))
	switch {
	case h == "gateway" || strings.HasPrefix(h, "gateway:"):
		return RoleGateway
	case h == "authority" || strings.HasPrefix(h, "authority:") ||
		h == "aa" || h == "rm" || h == "ca":
		return RoleAuthority
	case h == "admin":
		return RoleAdmin
	default:
		return RoleUnknown
	}
}

func ACLAllows(fn string, role IdentityRole) bool {
	switch fn {
	case "CommitSegment":
		return role == RoleGateway || role == RoleAdmin
	case "UpdateAuthorization", "RegisterPolicyState", "RegisterAttributeState",
		"RegisterRoleState", "RegisterOwner":
		return role == RoleAuthority || role == RoleAdmin
	case "GetAuthorization", "GetSegment", "GetPolicyState", "GetAttributeState", "GetRoleState":
		return true
	default:
		return role == RoleAdmin
	}
}

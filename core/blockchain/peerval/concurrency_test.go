package peerval_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hierastream/peerval"
)

type AuthRecord struct {
	Version     int    `json:"version"`
	PolicyID    string `json:"policyId"`
	AttrStateID string `json:"attrStateId"`
	RoleStateID string `json:"roleStateId"`
}

func authKey(owner string) string { return "AuthKey/" + owner }
func segKey(owner, seg string) string {
	return "Segment/" + owner + "/" + seg
}

func etaDigest(cid, mcid string, version int, policyID, attrStateID, roleStateID string) string {
	parts := []string{cid, mcid, fmt.Sprintf("%d", version), policyID, attrStateID, roleStateID}
	blob := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(blob))
	return hex.EncodeToString(sum[:])
}

func bootstrap(p *peerval.PeerLedger, owner string, auth AuthRecord) {
	p.BootstrapPut(authKey(owner), peerval.MustJSON(auth))
}

func endorseCommitSegment(p *peerval.PeerLedger, txID, caller, owner, seg, cid, mcid string, auth AuthRecord, eta string) peerval.EndorsedTx {
	ctx := p.EndorseBegin(txID, caller, "CommitSegment")
	raw, _ := ctx.GetState(authKey(owner)) // Fabric MVCC read dependency
	if raw == nil {
		ctx.Reject("AuthKey missing")
		return ctx.Finish()
	}
	var got AuthRecord
	_ = json.Unmarshal(raw, &got)
	if got.Version != auth.Version || got.PolicyID != auth.PolicyID ||
		got.AttrStateID != auth.AttrStateID || got.RoleStateID != auth.RoleStateID {
		ctx.Reject("authorization snapshot mismatch")
		return ctx.Finish()
	}
	prime := etaDigest(cid, mcid, auth.Version, auth.PolicyID, auth.AttrStateID, auth.RoleStateID)
	if prime != eta {
		ctx.Reject("eta mismatch")
		return ctx.Finish()
	}
	rec := map[string]any{
		"CID": cid, "MCID": mcid, "version": auth.Version,
		"policyId": auth.PolicyID, "attrStateId": auth.AttrStateID,
		"roleStateId": auth.RoleStateID, "eta": eta,
	}
	ctx.PutState(segKey(owner, seg), peerval.MustJSON(rec))
	return ctx.Finish()
}

func endorseUpdateAuth(p *peerval.PeerLedger, txID, caller, owner string, expected, next AuthRecord) peerval.EndorsedTx {
	ctx := p.EndorseBegin(txID, caller, "UpdateAuthorization")
	raw, _ := ctx.GetState(authKey(owner)) // SAME AuthKey(ownerId)
	if raw == nil {
		ctx.Reject("AuthKey missing")
		return ctx.Finish()
	}
	var got AuthRecord
	_ = json.Unmarshal(raw, &got)
	if got.Version != expected.Version {
		ctx.Reject("expectedVersion mismatch")
		return ctx.Finish()
	}
	if got.PolicyID != expected.PolicyID ||
		got.AttrStateID != expected.AttrStateID || got.RoleStateID != expected.RoleStateID {
		ctx.Reject("expected current state mismatch")
		return ctx.Finish()
	}
	if next.Version != got.Version+1 {
		ctx.Reject("version must increment by exactly one")
		return ctx.Finish()
	}
	ctx.PutState(authKey(owner), peerval.MustJSON(next))
	return ctx.Finish()
}

func TestCase1_UpdateFirstInvalidatesStaleCommitSegment(t *testing.T) {
	p := peerval.NewPeerLedger()
	p.SetACL("CommitSegment", "gw")
	p.SetACL("UpdateAuthorization", "aa")
	auth0 := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	bootstrap(p, "o1", auth0)

	eta := etaDigest("c", "m", 0, "p", "a", "r")
	segTx := endorseCommitSegment(p, "tx-seg", "gw", "o1", "s1", "c", "m", auth0, eta)

	auth1 := AuthRecord{Version: 1, PolicyID: "p", AttrStateID: "a2", RoleStateID: "r"}
	upd := endorseUpdateAuth(p, "tx-upd", "aa", "o1", auth0, auth1)
	resU := p.ValidateAndCommit(upd)
	if resU.Status != peerval.VALID {
		t.Fatalf("update: %v", resU)
	}

	resS := p.ValidateAndCommit(segTx)
	if resS.Status != peerval.MVCCReadConflict {
		t.Fatalf("expected MVCC_READ_CONFLICT, got %v", resS)
	}
	if !strings.Contains(resS.Reason, "AuthKey/o1") {
		t.Fatalf("expected AuthKey in reason: %s", resS.Reason)
	}
}

func TestCase2_CommitFirstThenUpdateBothValid(t *testing.T) {
	p := peerval.NewPeerLedger()
	p.SetACL("CommitSegment", "gw")
	p.SetACL("UpdateAuthorization", "aa")
	auth0 := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	bootstrap(p, "o1", auth0)
	eta := etaDigest("c", "m", 0, "p", "a", "r")

	segTx := endorseCommitSegment(p, "tx1", "gw", "o1", "s1", "c", "m", auth0, eta)
	if res := p.ValidateAndCommit(segTx); res.Status != peerval.VALID {
		t.Fatalf("seg: %v", res)
	}

	auth1 := AuthRecord{Version: 1, PolicyID: "p2", AttrStateID: "a", RoleStateID: "r"}
	upd := endorseUpdateAuth(p, "tx2", "aa", "o1", auth0, auth1)
	if res := p.ValidateAndCommit(upd); res.Status != peerval.VALID {
		t.Fatalf("upd: %v", res)
	}
}

func TestCase3_MismatchedTupleRejected(t *testing.T) {
	p := peerval.NewPeerLedger()
	p.SetACL("CommitSegment", "gw")
	auth0 := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	bootstrap(p, "o1", auth0)
	eta := etaDigest("c", "m", 0, "p", "a", "r")
	bad := AuthRecord{Version: 1, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	tx := endorseCommitSegment(p, "tx", "gw", "o1", "s", "c", "m", bad, eta)
	res := p.ValidateAndCommit(tx)
	if res.Status != peerval.INVALIDOther {
		t.Fatalf("expected INVALID (mismatch), got %v", res)
	}
}

func TestCase4_ACLRejection(t *testing.T) {
	p := peerval.NewPeerLedger()
	p.SetACL("UpdateAuthorization", "aa")
	auth0 := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	bootstrap(p, "o1", auth0)
	auth1 := AuthRecord{Version: 1, PolicyID: "p2", AttrStateID: "a", RoleStateID: "r"}
	tx := endorseUpdateAuth(p, "tx", "evil", "o1", auth0, auth1)
	res := p.ValidateAndCommit(tx)
	if res.Status != peerval.ACLDenied {
		t.Fatalf("expected ACL_DENIED, got %v", res)
	}
}

func TestCase5_BothPathsTouchSameAuthKey(t *testing.T) {
	p := peerval.NewPeerLedger()
	p.SetACL("CommitSegment", "gw")
	p.SetACL("UpdateAuthorization", "aa")
	auth0 := AuthRecord{Version: 0, PolicyID: "p", AttrStateID: "a", RoleStateID: "r"}
	bootstrap(p, "o1", auth0)
	eta := etaDigest("c", "m", 0, "p", "a", "r")

	segTx := endorseCommitSegment(p, "tx-s", "gw", "o1", "s1", "c", "m", auth0, eta)
	updTx := endorseUpdateAuth(p, "tx-u", "aa", "o1", auth0,
		AuthRecord{Version: 1, PolicyID: "p", AttrStateID: "a", RoleStateID: "r2"})

	segHas, updHas := false, false
	for _, r := range segTx.ReadSet {
		if r.Key == authKey("o1") {
			segHas = true
		}
	}
	for _, r := range updTx.ReadSet {
		if r.Key == authKey("o1") {
			updHas = true
		}
	}
	if !segHas || !updHas {
		t.Fatalf("both txs must read AuthKey/o1: seg=%v upd=%v", segHas, updHas)
	}
	if _, ok := updTx.WriteSet[authKey("o1")]; !ok {
		t.Fatal("UpdateAuthorization must write AuthKey")
	}
	if _, ok := segTx.WriteSet[segKey("o1", "s1")]; !ok {
		t.Fatal("CommitSegment must write Segment")
	}
}

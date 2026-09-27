// Package peerval implements Hyperledger Fabric state-based MVCC validation
// as performed by the peer (VSCC / statebasedval), not application business logic.
//
// Algorithm (Fabric peer):
//   for each key in the transaction read-set:
//     if ledger version(key) != endorsed read version(key) → MVCC_READ_CONFLICT
//   else apply write-set atomically.
//
// Concurrency tests for CommitSegment vs UpdateAuthorization MUST use this
// validator (or a live Fabric peer). Do not invent VALID/INVALID in Python
// experiment code.
package peerval

import (
	"encoding/json"
	"fmt"
	"sync"
)

// TxStatus mirrors Fabric validation outcomes visible to clients.
type TxStatus string

const (
	VALID              TxStatus = "VALID"
	MVCCReadConflict   TxStatus = "MVCC_READ_CONFLICT"
	INVALIDOther       TxStatus = "INVALID"
	ACLDenied          TxStatus = "ACL_DENIED"
)

// VersionedKV is one world-state entry with a Fabric-style per-key version.
type VersionedKV struct {
	Value   []byte
	Version uint64 // block-height style monotonic counter per key
}

// ReadSetEntry is one key observed during endorsement.
type ReadSetEntry struct {
	Key     string
	Version uint64 // version at endorsement; 0 means key did not exist (Fabric uses nil version)
	Exists  bool
}

// EndorsedTx is a peer-endorsed transaction awaiting ordering/validation.
type EndorsedTx struct {
	TxID     string
	Caller   string
	Function string
	ReadSet  []ReadSetEntry
	WriteSet map[string][]byte // key -> value (nil value = delete; we only put)
	// AppReject: chaincode returned error during endorsement simulation
	AppReject bool
	AppReason string
}

// Result is the validation outcome for one transaction.
type Result struct {
	TxID   string
	Status TxStatus
	Reason string
}

// PeerLedger is an in-process world-state with Fabric peer MVCC commit.
type PeerLedger struct {
	mu      sync.Mutex
	state   map[string]*VersionedKV
	history []Result
	acl     map[string]map[string]struct{} // function -> allowed callers
}

func NewPeerLedger() *PeerLedger {
	return &PeerLedger{
		state: make(map[string]*VersionedKV),
		acl:   make(map[string]map[string]struct{}),
	}
}

func (p *PeerLedger) SetACL(function string, callers ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	set := make(map[string]struct{}, len(callers))
	for _, c := range callers {
		set[c] = struct{}{}
	}
	p.acl[function] = set
}

// BootstrapPut writes genesis state without MVCC (channel bootstrap / Init).
func (p *PeerLedger) BootstrapPut(key string, value []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ver := uint64(1)
	if cur, ok := p.state[key]; ok {
		ver = cur.Version + 1
	}
	p.state[key] = &VersionedKV{Value: append([]byte(nil), value...), Version: ver}
}

func (p *PeerLedger) Get(key string) ([]byte, uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	kv, ok := p.state[key]
	if !ok {
		return nil, 0, false
	}
	return append([]byte(nil), kv.Value...), kv.Version, true
}

// EndorseBegin starts an endorsement simulation context.
func (p *PeerLedger) EndorseBegin(txID, caller, function string) *EndorseCtx {
	return &EndorseCtx{
		ledger:   p,
		txID:     txID,
		caller:   caller,
		function: function,
		reads:    map[string]ReadSetEntry{},
		writes:   map[string][]byte{},
	}
}

// EndorseCtx records GetState versions into the Fabric read-set.
type EndorseCtx struct {
	ledger    *PeerLedger
	txID      string
	caller    string
	function  string
	reads     map[string]ReadSetEntry
	writes    map[string][]byte
	appReject bool
	appReason string
}

func (e *EndorseCtx) GetState(key string) ([]byte, error) {
	e.ledger.mu.Lock()
	defer e.ledger.mu.Unlock()
	kv, ok := e.ledger.state[key]
	if !ok {
		e.reads[key] = ReadSetEntry{Key: key, Version: 0, Exists: false}
		return nil, nil
	}
	e.reads[key] = ReadSetEntry{Key: key, Version: kv.Version, Exists: true}
	return append([]byte(nil), kv.Value...), nil
}

func (e *EndorseCtx) PutState(key string, value []byte) {
	e.writes[key] = append([]byte(nil), value...)
}

func (e *EndorseCtx) Reject(reason string) {
	e.appReject = true
	e.appReason = reason
}

func (e *EndorseCtx) Finish() EndorsedTx {
	rs := make([]ReadSetEntry, 0, len(e.reads))
	for _, r := range e.reads {
		rs = append(rs, r)
	}
	return EndorsedTx{
		TxID: e.txID, Caller: e.caller, Function: e.function,
		ReadSet: rs, WriteSet: e.writes,
		AppReject: e.appReject, AppReason: e.appReason,
	}
}

// ValidateAndCommit runs Fabric peer state-based MVCC validation then applies writes.
func (p *PeerLedger) ValidateAndCommit(tx EndorsedTx) Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	if allowed, ok := p.acl[tx.Function]; ok {
		if _, ok2 := allowed[tx.Caller]; !ok2 {
			res := Result{TxID: tx.TxID, Status: ACLDenied, Reason: "ACL"}
			p.history = append(p.history, res)
			return res
		}
	}
	if tx.AppReject {
		res := Result{TxID: tx.TxID, Status: INVALIDOther, Reason: tx.AppReason}
		p.history = append(p.history, res)
		return res
	}

	// --- Fabric state-based MVCC (peer) ---
	for _, r := range tx.ReadSet {
		cur, ok := p.state[r.Key]
		if !r.Exists {
			if ok {
				res := Result{
					TxID: tx.TxID, Status: MVCCReadConflict,
					Reason: fmt.Sprintf("key=%s expectedAbsent gotVer=%d", r.Key, cur.Version),
				}
				p.history = append(p.history, res)
				return res
			}
			continue
		}
		if !ok || cur.Version != r.Version {
			got := uint64(0)
			if ok {
				got = cur.Version
			}
			res := Result{
				TxID: tx.TxID, Status: MVCCReadConflict,
				Reason: fmt.Sprintf("key=%s endorsedVer=%d ledgerVer=%d", r.Key, r.Version, got),
			}
			p.history = append(p.history, res)
			return res
		}
	}

	for k, v := range tx.WriteSet {
		ver := uint64(1)
		if cur, ok := p.state[k]; ok {
			ver = cur.Version + 1
		}
		p.state[k] = &VersionedKV{Value: append([]byte(nil), v...), Version: ver}
	}
	res := Result{TxID: tx.TxID, Status: VALID}
	p.history = append(p.history, res)
	return res
}

func (p *PeerLedger) History() []Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Result, len(p.history))
	copy(out, p.history)
	return out
}

func MustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

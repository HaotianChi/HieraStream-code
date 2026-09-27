package main

// Live Fabric / peer-lifecycle entrypoint.
// Offline smoke stub lives in main_stub.go with //go:build ignore.
// Requires fabric-contract-api-go (see go.mod).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract is the HieraStream chaincode surface.
type SmartContract struct {
	contractapi.Contract
}

// callerRole reads ClientIdentity attribute "hierastream.role", cert CN, or MSP hint.
// Single-org research mapping (cryptogen users):
//   Admin@org1 → admin, User1@org1 → gateway, User2@org1 → authority.
// ACL rules themselves are unchanged (see authstate.go).
func callerRole(ctx contractapi.TransactionContextInterface) (IdentityRole, string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return RoleUnknown, "", err
	}
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return RoleUnknown, id, err
	}
	attr, found, _ := ctx.GetClientIdentity().GetAttributeValue("hierastream.role")
	if found && attr != "" {
		return ParseIdentityRole(attr), id, nil
	}
	if cert, err := ctx.GetClientIdentity().GetX509Certificate(); err == nil && cert != nil {
		cn := strings.ToLower(cert.Subject.CommonName)
		switch {
		case strings.HasPrefix(cn, "admin@"):
			return RoleAdmin, id, nil
		case strings.HasPrefix(cn, "user1@"):
			return RoleGateway, id, nil
		case strings.HasPrefix(cn, "user2@"):
			return RoleAuthority, id, nil
		}
	}
	// Fallback: OrgGatewayMSP / OrgAuthorityMSP naming convention
	low := strings.ToLower(msp)
	switch {
	case strings.Contains(low, "gateway"):
		return RoleGateway, id, nil
	case strings.Contains(low, "authority"):
		return RoleAuthority, id, nil
	default:
		return ParseIdentityRole(msp), id, nil
	}
}

func requireACL(ctx contractapi.TransactionContextInterface, fn string) error {
	role, _, err := callerRole(ctx)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if !ACLAllows(fn, role) {
		return fmt.Errorf("ACL denied: %s not permitted for role %s", fn, role)
	}
	return nil
}

// ---- Registration / management ----

func (s *SmartContract) RegisterOwner(ctx contractapi.TransactionContextInterface,
	ownerID, gatewayID string) error {
	if err := requireACL(ctx, "RegisterOwner"); err != nil {
		return err
	}
	rec := OwnerRecord{OwnerID: ownerID, GatewayID: gatewayID, Active: true}
	return ctx.GetStub().PutState(OwnerRegistryKey(ownerID), MustJSON(rec))
}

func (s *SmartContract) RegisterPolicyState(ctx contractapi.TransactionContextInterface,
	policyID string, version int, payloadJSON string) error {
	if err := requireACL(ctx, "RegisterPolicyState"); err != nil {
		return err
	}
	rec := PolicyStateRecord{
		PolicyID: policyID, Version: version, Payload: json.RawMessage(payloadJSON),
	}
	return ctx.GetStub().PutState(PolicyStateKey(policyID), MustJSON(rec))
}

func (s *SmartContract) RegisterAttributeState(ctx contractapi.TransactionContextInterface,
	attrStateID string, version int, payloadJSON string) error {
	if err := requireACL(ctx, "RegisterAttributeState"); err != nil {
		return err
	}
	rec := AttributeStateRecord{
		AttrStateID: attrStateID, Version: version, Payload: json.RawMessage(payloadJSON),
	}
	return ctx.GetStub().PutState(AttributeStateKey(attrStateID), MustJSON(rec))
}

func (s *SmartContract) RegisterRoleState(ctx contractapi.TransactionContextInterface,
	roleStateID string, version int, payloadJSON string) error {
	if err := requireACL(ctx, "RegisterRoleState"); err != nil {
		return err
	}
	rec := RoleStateRecord{
		RoleStateID: roleStateID, Version: version, Payload: json.RawMessage(payloadJSON),
	}
	return ctx.GetStub().PutState(RoleStateKey(roleStateID), MustJSON(rec))
}

// InitAuth bootstraps AuthKey(ownerId) at ν=0 (authority).
func (s *SmartContract) InitAuth(ctx contractapi.TransactionContextInterface,
	ownerID string, version int, policyID, attrStateID, roleStateID string) error {
	if err := requireACL(ctx, "UpdateAuthorization"); err != nil {
		return err
	}
	existing, err := ctx.GetStub().GetState(AuthKey(ownerID))
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("AuthKey already exists for %s", ownerID)
	}
	rec := AuthRecord{Version: version, PolicyID: policyID, AttrStateID: attrStateID, RoleStateID: roleStateID}
	return ctx.GetStub().PutState(AuthKey(ownerID), MustJSON(rec))
}

// ---- Queries ----

func (s *SmartContract) GetAuthorization(ctx contractapi.TransactionContextInterface,
	ownerID string) (*AuthRecord, error) {
	if err := requireACL(ctx, "GetAuthorization"); err != nil {
		return nil, err
	}
	b, err := ctx.GetStub().GetState(AuthKey(ownerID))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("AuthKey missing")
	}
	var auth AuthRecord
	if err := json.Unmarshal(b, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

func (s *SmartContract) GetSegment(ctx contractapi.TransactionContextInterface,
	ownerID, segID string) (*SegmentRecord, error) {
	if err := requireACL(ctx, "GetSegment"); err != nil {
		return nil, err
	}
	b, err := ctx.GetStub().GetState(SegmentKey(ownerID, segID))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("segment missing")
	}
	var rec SegmentRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SmartContract) GetPolicyState(ctx contractapi.TransactionContextInterface,
	policyID string) (*PolicyStateRecord, error) {
	b, err := ctx.GetStub().GetState(PolicyStateKey(policyID))
	if err != nil || b == nil {
		return nil, fmt.Errorf("policy state missing")
	}
	var rec PolicyStateRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SmartContract) GetAttributeState(ctx contractapi.TransactionContextInterface,
	attrStateID string) (*AttributeStateRecord, error) {
	b, err := ctx.GetStub().GetState(AttributeStateKey(attrStateID))
	if err != nil || b == nil {
		return nil, fmt.Errorf("attribute state missing")
	}
	var rec AttributeStateRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SmartContract) GetRoleState(ctx contractapi.TransactionContextInterface,
	roleStateID string) (*RoleStateRecord, error) {
	b, err := ctx.GetStub().GetState(RoleStateKey(roleStateID))
	if err != nil || b == nil {
		return nil, fmt.Errorf("role state missing")
	}
	var rec RoleStateRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ---- Algorithm 1: CommitSegment ----

func (s *SmartContract) CommitSegment(ctx contractapi.TransactionContextInterface,
	ownerID, segID, cid, mcid string,
	version int, policyID, attrStateID, roleStateID, eta string) error {

	if err := requireACL(ctx, "CommitSegment"); err != nil {
		return err
	}

	// GetState(AuthKey) — MUST appear in Fabric read-set (MVCC dependency).
	authBytes, err := ctx.GetStub().GetState(AuthKey(ownerID))
	if err != nil {
		return fmt.Errorf("GetState AuthKey: %w", err)
	}
	if authBytes == nil {
		return fmt.Errorf("AuthKey missing")
	}
	var auth AuthRecord
	if err := json.Unmarshal(authBytes, &auth); err != nil {
		return err
	}
	rec, err := ValidateCommitSegment(auth, cid, mcid, version, policyID, attrStateID, roleStateID, eta)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(SegmentKey(ownerID, segID), MustJSON(rec))
}

// ---- UpdateAuthorization ----

func (s *SmartContract) UpdateAuthorization(ctx contractapi.TransactionContextInterface,
	ownerID string,
	expectedVersion int, expectedPolicyID, expectedAttrID, expectedRoleID string,
	newPolicyID, newAttrID, newRoleID string) error {

	if err := requireACL(ctx, "UpdateAuthorization"); err != nil {
		return err
	}

	// Same AuthKey(ownerId) as CommitSegment — shared MVCC key.
	authBytes, err := ctx.GetStub().GetState(AuthKey(ownerID))
	if err != nil {
		return fmt.Errorf("GetState AuthKey: %w", err)
	}
	if authBytes == nil {
		return fmt.Errorf("AuthKey missing")
	}
	var auth AuthRecord
	if err := json.Unmarshal(authBytes, &auth); err != nil {
		return err
	}
	expected := AuthRecord{
		Version: expectedVersion, PolicyID: expectedPolicyID,
		AttrStateID: expectedAttrID, RoleStateID: expectedRoleID,
	}
	next := CarryForwardAuth(auth, newPolicyID, newAttrID, newRoleID)
	updated, err := NextAuthRecord(auth, expected, next)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(AuthKey(ownerID), MustJSON(updated))
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(err)
	}
	// CCAAS / chaincode-as-a-service when CHAINCODE_SERVER_ADDRESS is set .
	if addr := os.Getenv("CHAINCODE_SERVER_ADDRESS"); addr != "" {
		ccid := os.Getenv("CORE_CHAINCODE_ID_NAME")
		server := &shim.ChaincodeServer{
			CCID:    ccid,
			Address: addr,
			CC:      chaincode,
			TLSProps: shim.TLSProperties{
				Disabled: true,
			},
		}
		if err := server.Start(); err != nil {
			panic(err)
		}
		return
	}
	if err := chaincode.Start(); err != nil {
		panic(err)
	}
}

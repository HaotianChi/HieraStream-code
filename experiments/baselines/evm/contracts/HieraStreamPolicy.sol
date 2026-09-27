// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import "./IComparison.sol";

/// @notice EVM comparison contract mirroring AuthKey-style authorization snapshot.
/// @dev Separate from Hyperledger Fabric chaincode. Used only for Ganache/EVM benches.
contract HieraStreamPolicy is IComparison {
    struct AuthSnap {
        uint64 version;
        bytes32 policyId;
        bytes32 attrStateId;
        bytes32 roleStateId;
        bool exists;
    }

    mapping(bytes32 => AuthSnap) public auth;

    function initAuth(
        bytes32 ownerId,
        bytes32 policyId,
        bytes32 attrStateId,
        bytes32 roleStateId
    ) external {
        require(!auth[ownerId].exists, "exists");
        auth[ownerId] = AuthSnap(0, policyId, attrStateId, roleStateId, true);
    }

    /// @notice On-chain policy / authorization update (ν → ν+1 with identity checks).
    function policyUpdate(
        bytes32 ownerId,
        uint64 newVersion,
        bytes32 policyId,
        bytes32 attrStateId,
        bytes32 roleStateId
    ) external override {
        AuthSnap storage s = auth[ownerId];
        require(s.exists, "missing");
        require(newVersion == s.version + 1, "version");
        s.version = newVersion;
        s.policyId = policyId;
        s.attrStateId = attrStateId;
        s.roleStateId = roleStateId;
    }

    /// @notice Query / access snapshot read.
    function queryAccess(bytes32 ownerId)
        external
        view
        override
        returns (uint64 version, bytes32 policyId, bytes32 attrStateId, bytes32 roleStateId)
    {
        AuthSnap storage s = auth[ownerId];
        require(s.exists, "missing");
        return (s.version, s.policyId, s.attrStateId, s.roleStateId);
    }
}

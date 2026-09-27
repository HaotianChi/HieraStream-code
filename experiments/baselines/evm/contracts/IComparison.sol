// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/// @title Shared interface for EVM cross-scheme comparison (not Fabric).
interface IComparison {
    function policyUpdate(bytes32 ownerId, uint64 newVersion, bytes32 policyId, bytes32 attrStateId, bytes32 roleStateId) external;
    function queryAccess(bytes32 ownerId) external view returns (uint64 version, bytes32 policyId, bytes32 attrStateId, bytes32 roleStateId);
}

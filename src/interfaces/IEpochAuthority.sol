// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IEpochAuthority: destination-chain epoch authorization (SPEC §7.3, §8.2)
/// @notice Implemented by the Ethereum `CommitteeRegistry` and by the per-chain immutable
///         `EpochMirror` adapters (Job 3). `BeaconVerifier.submit` consults it for every epoch
///         after the genesis epoch; `verify` never does (the pure check has no epoch gate).
interface IEpochAuthority {
    /// @notice True once `epoch` of `networkId` has been activated by a finalized handover
    ///         certificate (or its authenticated mirror record) that preserved the pinned group key.
    ///         Must be false for epochs that were never activated, including failed handovers.
    function isEpochAuthorized(bytes32 networkId, uint64 epoch) external view returns (bool);
}

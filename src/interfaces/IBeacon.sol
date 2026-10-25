// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IBeacon: read and publish imd-beacon rounds
/// @notice Frozen ABI for the imd-beacon verifier (docs/SPEC.md §8.2, §8.3), fixed by Job 2.
///         Encodings and semantics are those of SPEC §4.3:
///         - M(r) = "IMD_BEACON_ROUND_V1" || networkId || U64BE(E(r)) || U64BE(r)
///         - H(M) = RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ with
///           DST "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
///         - R(r) = SHA256(standard 48-byte compressed G1 signature)
///         - T(r) = genesisTime + period * (r - 1), E(r) = (r - 1) / epochLength, r >= 1
interface IBeacon {
    /// @notice Emitted once per round, when its group signature is first verified and stored.
    /// @param networkId the immutable network id of this verifier
    /// @param epoch E(round)
    /// @param round the round number (r >= 1)
    /// @param value R(round) = SHA256(signature)
    /// @param signature the 48-byte standard compressed G1 encoding of the group signature,
    ///        exactly the preimage of `value`. The 96-byte submit form is never emitted.
    event RoundVerified(
        bytes32 indexed networkId, uint64 indexed epoch, uint64 indexed round, bytes32 value, bytes signature
    );

    // ------------------------------------------------------------------ verification and storage

    /// @notice Verify a round's group signature and return its randomness R(round).
    ///         Pure check with no side effects and no epoch gate: it derives E(round) and M(round)
    ///         from the immutable descriptor, checks the pairing against the immutable group key,
    ///         and returns SHA256 of the reconstructed compressed signature.
    ///         Reverts on round 0, a round whose T(round) does not fit in uint64, a length other
    ///         than 96 bytes, non-canonical coordinates, infinity, off-curve or non-subgroup points,
    ///         a failed pairing (wrong network, wrong key, wrong round or epoch) and any precompile
    ///         that fails or returns an unexpected length.
    /// @param round the round number
    /// @param affineG1Signature 96 bytes: x || y, canonical 48-byte big-endian base-field integers, no flags
    function verify(uint64 round, bytes calldata affineG1Signature) external view returns (bytes32);

    /// @notice Verify and store a round. Anyone may call once `block.timestamp >= T(round)`;
    ///         an earlier call reverts. Rounds in an epoch after the genesis epoch additionally
    ///         require `epochAuthority().isEpochAuthorized(networkId(), E(round))` (SPEC §8.2, §7.3).
    ///         Rounds may be published in any order; round r does not require round r - 1.
    ///         A matching duplicate is a no-op that returns false, performs no write, emits
    ///         nothing and therefore can never be paid twice; a mismatching submission for an
    ///         available round reverts.
    /// @return firstWrite true only for the call that first stored the round
    function submit(uint64 round, bytes calldata affineG1Signature) external returns (bool firstWrite);

    /// @notice Stored round value. `available` is explicit because R may legitimately be zero.
    function get(uint64 round) external view returns (bool available, bytes32 value);

    // ------------------------------------------------------------------ immutable descriptor (SPEC §8.3)

    /// @notice networkId = keccak256("IMD_BEACON_NETWORK_V1" || configHash), fixed at genesis.
    function networkId() external view returns (bytes32);

    /// @notice T0: release time of round 1, in seconds.
    function genesisTime() external view returns (uint64);

    /// @notice Seconds between rounds (30 in SPEC v1).
    function period() external view returns (uint64);

    /// @notice Rounds per epoch (2,880 in SPEC v1).
    function epochLength() external view returns (uint64);

    /// @notice Largest round whose T(round) fits in uint64; larger rounds are rejected as overflow.
    function maxRound() external view returns (uint64);

    /// @notice The immutable group key as the 256-byte EIP-2537 affine G2 encoding
    ///         (x.c0 || x.c1 || y.c0 || y.c1, each a 64-byte padded canonical field element).
    function groupKey() external view returns (bytes memory);

    /// @notice The immutable epoch-authorization source consulted by `submit` for epochs >= 1.
    function epochAuthority() external view returns (address);

    /// @notice T(round) = genesisTime + period * (round - 1). Reverts for round 0 or overflow.
    function roundTime(uint64 round) external view returns (uint64);

    /// @notice E(round) = (round - 1) / epochLength. Reverts for round 0.
    function epochOf(uint64 round) external view returns (uint64);

    /// @notice Smallest round whose release time is at least `timestamp`; the consumer helper of
    ///         SPEC §8.3 calls this with `block.timestamp + lead`. Returns 1 for timestamps before
    ///         genesis; reverts if the result would exceed `maxRound()`.
    function roundAt(uint64 timestamp) external view returns (uint64);
}

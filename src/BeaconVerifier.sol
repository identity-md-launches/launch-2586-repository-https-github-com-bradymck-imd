// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IBeacon} from "./interfaces/IBeacon.sol";
import {IEpochAuthority} from "./interfaces/IEpochAuthority.sol";
import {BLS12381} from "./bls/BLS12381.sol";
import {HashToCurveG1} from "./bls/HashToCurveG1.sol";

/// @title BeaconVerifier: immutable on-chain verifier and store for imd-beacon rounds
/// @notice Job 2 of docs/SPEC.md. The network descriptor and the BLS12-381 group key are
///         installed once in the constructor, which exercises every precompile the verifier
///         relies on with known answers (verified genesis), and can never change afterwards.
///         There is no owner, no admin and no setter of any kind.
///
///         Cryptography (SPEC §4.3): signatures in G1, group key in G2,
///         M(r) = "IMD_BEACON_ROUND_V1" || networkId || U64BE(E(r)) || U64BE(r),
///         H = RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ with the BLS basic-scheme DST,
///         check e(sig, G2) == e(H(M), PK), R(r) = SHA256(compressed 48-byte signature).
///
///         Rewards (Job 7) are out of scope: `submit` returns whether it was the first write so a
///         separate escrow can pay the first valid submitter exactly once (SPEC §8.2, §9).
contract BeaconVerifier is IBeacon {
    // ------------------------------------------------------------------ errors
    error InvalidRound(uint64 round);
    error RoundNotReleased(uint64 round, uint64 releaseTime);
    error EpochNotAuthorized(uint64 epoch);
    error InvalidSignature();
    error RoundValueMismatch(uint64 round);
    error InvalidDescriptor();
    error GenesisSelfTestFailed();

    // ------------------------------------------------------------------ constructor input
    /// @notice The group key as eight 32-byte words of its 256-byte EIP-2537 affine G2 encoding:
    ///         pad64(x.c0) || pad64(x.c1) || pad64(y.c0) || pad64(y.c1), split into (hi, lo) words.
    struct GroupKeyWords {
        bytes32 xc0Hi;
        bytes32 xc0Lo;
        bytes32 xc1Hi;
        bytes32 xc1Lo;
        bytes32 yc0Hi;
        bytes32 yc0Lo;
        bytes32 yc1Hi;
        bytes32 yc1Lo;
    }

    // ------------------------------------------------------------------ constants (SPEC §4.3)
    bytes internal constant MESSAGE_PREFIX = "IMD_BEACON_ROUND_V1";
    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    uint64 public constant PERIOD = 30;
    uint64 public constant EPOCH_LENGTH = 2880;
    /// @dev hash_to_curve("IMD_BEACON_GENESIS_SELFTEST_V1") under DST, computed by @noble/curves;
    ///      the constructor recomputes it through MODEXP, MAP_FP_TO_G1 and G1ADD.
    bytes32 internal constant SELFTEST_X_HI = 0x00000000000000000000000000000000057e361a451d19beef90457e3ba984c4;
    bytes32 internal constant SELFTEST_X_LO = 0x44b61f5958afeceae1efabac1dee7c0fa082eac2892e8089e9f6590350e30296;
    bytes32 internal constant SELFTEST_Y_HI = 0x0000000000000000000000000000000016f3e38a34a539dd0fd21243dc77e22b;
    bytes32 internal constant SELFTEST_Y_LO = 0xef6bffcd74f47d00b3a339b051850d1e13b54e08e0324d8ee64c50e69e86385d;

    // ------------------------------------------------------------------ immutable descriptor
    bytes32 public immutable override networkId;
    uint64 public immutable override genesisTime;
    uint64 public immutable override maxRound;
    address public immutable override epochAuthority;

    bytes32 private immutable _pk0;
    bytes32 private immutable _pk1;
    bytes32 private immutable _pk2;
    bytes32 private immutable _pk3;
    bytes32 private immutable _pk4;
    bytes32 private immutable _pk5;
    bytes32 private immutable _pk6;
    bytes32 private immutable _pk7;

    // ------------------------------------------------------------------ storage
    /// @dev R(round) for stored rounds. Zero is a legal value, so availability is tracked separately.
    mapping(uint64 round => bytes32 value) private _values;
    /// @dev Availability bitmap: word `round >> 8`, bit `round & 255`.
    mapping(uint256 word => uint256 bits) private _available;

    /// @param networkId_ keccak256("IMD_BEACON_NETWORK_V1" || configHash); never zero
    /// @param genesisTime_ T0, release time of round 1; never zero
    /// @param key the group key in EIP-2537 affine G2 words; validated on curve and in subgroup
    /// @param epochAuthority_ the registry or epoch mirror consulted for epochs >= 1; never zero.
    ///        Not called here, so deployment does not depend on it having code yet.
    constructor(bytes32 networkId_, uint64 genesisTime_, GroupKeyWords memory key, address epochAuthority_) {
        if (networkId_ == bytes32(0) || genesisTime_ == 0 || epochAuthority_ == address(0)) revert InvalidDescriptor();
        networkId = networkId_;
        genesisTime = genesisTime_;
        epochAuthority = epochAuthority_;
        maxRound = uint64((type(uint64).max - genesisTime_) / PERIOD + 1);

        bytes memory pk =
            abi.encodePacked(key.xc0Hi, key.xc0Lo, key.xc1Hi, key.xc1Lo, key.yc0Hi, key.yc0Lo, key.yc1Hi, key.yc1Lo);
        BLS12381.validateGroupKey(pk); // canonical, non-infinity, on twist, subgroup (G2MSM)
        _pk0 = key.xc0Hi;
        _pk1 = key.xc0Lo;
        _pk2 = key.xc1Hi;
        _pk3 = key.xc1Lo;
        _pk4 = key.yc0Hi;
        _pk5 = key.yc0Lo;
        _pk6 = key.yc1Hi;
        _pk7 = key.yc1Lo;

        // Verified genesis: the hash-to-curve path (SHA-256, MODEXP, MAP_FP_TO_G1, G1ADD) must
        // reproduce a known answer, and the pairing precompile must accept e(G1, -G2) * e(G1, G2) == 1
        // with the constants used at run time. Missing precompiles make deployment fail (R6).
        bytes memory h = HashToCurveG1.hashToG1("IMD_BEACON_GENESIS_SELFTEST_V1", DST);
        if (keccak256(h) != keccak256(abi.encodePacked(SELFTEST_X_HI, SELFTEST_X_LO, SELFTEST_Y_HI, SELFTEST_Y_LO))) {
            revert GenesisSelfTestFailed();
        }
        bytes memory g1 = BLS12381.g1Generator();
        bytes memory negG2 = BLS12381.negG2Generator();
        bytes memory g2 = _negateG2(negG2);
        if (!BLS12381.pairingCheck(g1, g1, g2)) revert GenesisSelfTestFailed();
    }

    // ------------------------------------------------------------------ IBeacon: verification and storage

    /// @inheritdoc IBeacon
    function verify(uint64 round, bytes calldata affineG1Signature) external view override returns (bytes32) {
        (bytes32 value,) = _verify(round, affineG1Signature);
        return value;
    }

    /// @inheritdoc IBeacon
    function submit(uint64 round, bytes calldata affineG1Signature) external override returns (bool firstWrite) {
        uint64 releaseTime = roundTime(round); // also rejects round 0 and overflow
        if (block.timestamp < releaseTime) revert RoundNotReleased(round, releaseTime);
        uint64 epoch = (round - 1) / EPOCH_LENGTH;

        (uint256 word, uint256 bit) = _slot(round);
        if (_available[word] & bit != 0) {
            // Already available. A resubmission gets the full verification (encoding checks,
            // hash-to-curve, pairing): an invalid input reverts with the same error a first
            // submission gets, whether or not its compressed form matches the stored preimage
            // (audit round 2, finding 1: a point with the signature's x and sign bit but another y
            // has the same hash while being off the curve). The signature on (PK, M) is unique, so
            // a verified duplicate is the stored one; the comparison is kept as a final check.
            // Nothing is written or emitted, so a duplicate can never be paid.
            (bytes32 resubmitted,) = _verify(round, affineG1Signature);
            if (resubmitted != _values[round]) revert RoundValueMismatch(round);
            return false;
        }

        if (epoch != 0 && !IEpochAuthority(epochAuthority).isEpochAuthorized(networkId, epoch)) {
            revert EpochNotAuthorized(epoch);
        }

        (bytes32 value, bytes memory compressed) = _verify(round, affineG1Signature);
        _values[round] = value;
        _available[word] |= bit;
        emit RoundVerified(networkId, epoch, round, value, compressed);
        return true;
    }

    /// @inheritdoc IBeacon
    function get(uint64 round) external view override returns (bool available, bytes32 value) {
        (uint256 word, uint256 bit) = _slot(round);
        available = _available[word] & bit != 0;
        value = available ? _values[round] : bytes32(0);
    }

    // ------------------------------------------------------------------ IBeacon: descriptor

    /// @inheritdoc IBeacon
    function period() external pure override returns (uint64) {
        return PERIOD;
    }

    /// @inheritdoc IBeacon
    function epochLength() external pure override returns (uint64) {
        return EPOCH_LENGTH;
    }

    /// @inheritdoc IBeacon
    function groupKey() public view override returns (bytes memory) {
        return abi.encodePacked(_pk0, _pk1, _pk2, _pk3, _pk4, _pk5, _pk6, _pk7);
    }

    /// @inheritdoc IBeacon
    function roundTime(uint64 round) public view override returns (uint64) {
        if (round == 0 || round > maxRound) revert InvalidRound(round);
        return genesisTime + PERIOD * (round - 1);
    }

    /// @inheritdoc IBeacon
    function epochOf(uint64 round) external pure override returns (uint64) {
        if (round == 0) revert InvalidRound(round);
        return (round - 1) / EPOCH_LENGTH;
    }

    /// @inheritdoc IBeacon
    function roundAt(uint64 timestamp) external view override returns (uint64) {
        if (timestamp <= genesisTime) return 1;
        uint256 r = (uint256(timestamp) - genesisTime + PERIOD - 1) / PERIOD + 1;
        if (r > maxRound) revert InvalidRound(type(uint64).max);
        return uint64(r);
    }

    // ------------------------------------------------------------------ internals

    /// @dev Full verification: encoding checks, message derivation, hash-to-curve, pairing, hash.
    function _verify(uint64 round, bytes calldata affineG1Signature)
        internal
        view
        returns (bytes32 value, bytes memory compressed)
    {
        if (round == 0 || round > maxRound) revert InvalidRound(round);
        bytes memory sigEip = BLS12381.parseAffineG1(affineG1Signature);
        uint64 epoch = (round - 1) / EPOCH_LENGTH;
        bytes memory message = abi.encodePacked(MESSAGE_PREFIX, networkId, bytes8(epoch), bytes8(round));
        bytes memory hm = HashToCurveG1.hashToG1(message, DST);
        if (!BLS12381.pairingCheck(sigEip, hm, groupKey())) revert InvalidSignature();
        compressed = BLS12381.compressG1(sigEip);
        value = BLS12381.sha256Strict(compressed);
    }

    function _slot(uint64 round) private pure returns (uint256 word, uint256 bit) {
        word = uint256(round) >> 8;
        bit = 1 << (round & 255);
    }

    /// @dev Negates a 256-byte EIP-form G2 point: y -> p - y per coefficient (only used at genesis).
    function _negateG2(bytes memory g) private pure returns (bytes memory out) {
        out = new bytes(256);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(g, 32), 128)
        }
        for (uint256 i = 0; i < 2; i++) {
            uint256 yHi;
            uint256 yLo;
            assembly ("memory-safe") {
                let p := add(add(g, 160), mul(i, 64))
                yHi := mload(p)
                yLo := mload(add(p, 32))
            }
            // p - y with a borrow across the two words
            uint256 nLo;
            uint256 nHi;
            unchecked {
                nLo = BLS12381.P_LO - yLo;
                nHi = BLS12381.P_HI - yHi - (BLS12381.P_LO < yLo ? 1 : 0);
            }
            assembly ("memory-safe") {
                let p := add(add(out, 160), mul(i, 64))
                mstore(p, nHi)
                mstore(add(p, 32), nLo)
            }
        }
    }
}

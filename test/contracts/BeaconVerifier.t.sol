// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "../forge-std/src/Test.sol";
import {Vm} from "../forge-std/src/Vm.sol";
import {BeaconVerifier} from "../../src/BeaconVerifier.sol";
import {IBeacon} from "../../src/interfaces/IBeacon.sol";
import {IEpochAuthority} from "../../src/interfaces/IEpochAuthority.sol";
import {BLS12381} from "../../src/bls/BLS12381.sol";
import {HashToCurveG1} from "../../src/bls/HashToCurveG1.sol";

/// @dev Exposes library internals for vector tests. Test-only.
contract BlsHarness {
    function expandMessageXmd(bytes calldata msg_, bytes calldata dst, uint256 len)
        external
        view
        returns (bytes memory)
    {
        return HashToCurveG1.expandMessageXmd(msg_, dst, len);
    }

    function hashToField(bytes calldata msg_, bytes calldata dst) external view returns (bytes memory, bytes memory) {
        return HashToCurveG1.hashToFieldFp2(msg_, dst);
    }

    function hashToG1(bytes calldata msg_, bytes calldata dst) external view returns (bytes memory) {
        return HashToCurveG1.hashToG1(msg_, dst);
    }

    function parse(bytes calldata affine) external pure returns (bytes memory) {
        return BLS12381.parseAffineG1(affine);
    }

    function compress(bytes calldata affine) external pure returns (bytes memory) {
        return BLS12381.compressG1(BLS12381.parseAffineG1(affine));
    }

    function pairing(bytes calldata sigAffine, bytes calldata hm, bytes calldata pk) external view returns (bool) {
        return BLS12381.pairingCheck(BLS12381.parseAffineG1(sigAffine), hm, pk);
    }

    function validateKey(bytes calldata pk) external view {
        BLS12381.validateGroupKey(pk);
    }

    /// @dev G1MSM (0x0c) over EIP-form points and 32-byte scalars; test-only threshold reconstruction.
    function g1Msm(bytes calldata input) external view returns (bytes memory) {
        return BLS12381.callPrecompile(address(0x0c), input, 128, 200_000);
    }

    /// @dev G1ADD (0x0b) of two 128-byte EIP-form points; builds valid subgroup points (sig + G1, 2·sig)
    ///      that are not the signature, for the modified-signature tests.
    function addG1(bytes calldata a, bytes calldata b) external view returns (bytes memory) {
        return BLS12381.addG1(a, b);
    }

    function g1Generator() external pure returns (bytes memory) {
        return BLS12381.g1Generator();
    }
}

/// @dev TEST-ONLY epoch authority. Production uses the registry / EpochMirror (Job 3).
contract MockEpochAuthority is IEpochAuthority {
    mapping(bytes32 => mapping(uint64 => bool)) public authorized;

    function set(bytes32 networkId, uint64 epoch, bool ok) external {
        authorized[networkId][epoch] = ok;
    }

    function isEpochAuthorized(bytes32 networkId, uint64 epoch) external view returns (bool) {
        return authorized[networkId][epoch];
    }
}

abstract contract BeaconVerifierFixture is Test {
    string internal json;
    BeaconVerifier internal verifier;
    BlsHarness internal harness;
    MockEpochAuthority internal authority;

    bytes32 internal networkId;
    uint64 internal genesisTime;
    uint64 internal maxRound;
    BeaconVerifier.GroupKeyWords internal key;
    bytes internal keyEip;

    struct RoundVec {
        uint64 round;
        uint64 epoch;
        bytes affine;
        bytes compressed;
        bytes32 value;
    }

    RoundVec[] internal rounds;

    function setUp() public virtual {
        json = vm.readFile("test/vectors/bls12.json");
        networkId = vm.parseJsonBytes32(json, ".network.networkId");
        genesisTime = uint64(vm.parseJsonUint(json, ".network.genesisTime"));
        maxRound = uint64(vm.parseJsonUint(json, ".network.maxRound"));
        key = _keyFrom(".key.groupKeyWords");
        keyEip = vm.parseJsonBytes(json, ".key.groupKeyEip256");

        uint256 n = _roundCount();
        for (uint256 i = 0; i < n; i++) {
            string memory p = string.concat(".rounds[", vm.toString(i), "]");
            rounds.push(
                RoundVec({
                    round: uint64(vm.parseJsonUint(json, string.concat(p, ".round"))),
                    epoch: uint64(vm.parseJsonUint(json, string.concat(p, ".epoch"))),
                    affine: vm.parseJsonBytes(json, string.concat(p, ".signatureAffine")),
                    compressed: vm.parseJsonBytes(json, string.concat(p, ".signatureCompressed")),
                    value: vm.parseJsonBytes32(json, string.concat(p, ".value"))
                })
            );
        }
        assertGe(rounds.length, 100, "fixture must hold at least 100 independent signatures");

        authority = new MockEpochAuthority();
        verifier = new BeaconVerifier(networkId, genesisTime, key, address(authority));
        harness = new BlsHarness();
        vm.warp(uint256(genesisTime) + 365 days); // every round of epoch 0..1 is released
        authority.set(networkId, 1, true);
    }

    // ------------------------------------------------------------------ helpers

    function _roundCount() internal view returns (uint256 n) {
        while (vm.keyExistsJson(json, string.concat(".rounds[", vm.toString(n), "].round"))) n++;
    }

    function _keyFrom(string memory path) internal view returns (BeaconVerifier.GroupKeyWords memory k) {
        bytes32[] memory w = vm.parseJsonBytes32Array(json, path);
        require(w.length == 8, "key words");
        k = BeaconVerifier.GroupKeyWords(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    }

    function _vec(uint64 round) internal view returns (RoundVec memory) {
        for (uint256 i = 0; i < rounds.length; i++) {
            if (rounds[i].round == round) return rounds[i];
        }
        revert("no vector");
    }

    function _negativeBytes(string memory name) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".negative.", name));
    }

    function _isAvailable(uint64 round) internal view returns (bool a) {
        (a,) = verifier.get(round);
    }

    function _assertUnset(uint64 round) internal view {
        (bool available, bytes32 value) = verifier.get(round);
        assertFalse(available, "failed call made round available");
        assertEq(value, bytes32(0), "failed call left randomness behind");
    }

    function _failure(address target) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, target);
    }

    // ------------------------------------------------------------------ encoding helpers

    function _pad64(bytes memory fp48) internal pure returns (bytes memory) {
        require(fp48.length == 48, "fp48");
        return bytes.concat(new bytes(16), fp48);
    }

    /// @dev 96-byte submit form -> 128-byte EIP-2537 form.
    function _affineToEip(bytes memory affine) internal pure returns (bytes memory) {
        require(affine.length == 96, "affine96");
        bytes memory x = new bytes(48);
        bytes memory y = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            x[i] = affine[i];
            y[i] = affine[48 + i];
        }
        return bytes.concat(_pad64(x), _pad64(y));
    }

    /// @dev 128-byte EIP-2537 form -> 96-byte submit form.
    function _eipToAffine(bytes memory eip) internal pure returns (bytes memory affine) {
        require(eip.length == 128, "eip128");
        affine = new bytes(96);
        for (uint256 i = 0; i < 48; i++) {
            affine[i] = eip[16 + i];
            affine[48 + i] = eip[80 + i];
        }
    }

    /// @dev Reads the 48-byte coordinate at `off` (0 = x, 48 = y) of a 96-byte encoding as (hi, lo):
    ///      hi holds the top 16 bytes, lo the low 32 bytes, the same split as BLS12381's field checks.
    function _coord(bytes memory m, uint256 off) internal pure returns (uint256 hi, uint256 lo) {
        require(m.length == 96 && (off == 0 || off == 48), "coord");
        assembly ("memory-safe") {
            hi := shr(128, mload(add(add(m, 32), off)))
            lo := mload(add(add(m, 48), off))
        }
    }

    function _setCoord(bytes memory m, uint256 off, uint256 hi, uint256 lo) internal pure {
        require(m.length == 96 && (off == 0 || off == 48) && hi >> 128 == 0, "coord");
        assembly ("memory-safe") {
            let p := add(add(m, 32), off)
            mstore(p, or(shl(128, hi), and(mload(p), sub(shl(128, 1), 1))))
            mstore(add(p, 16), lo)
        }
    }

    /// @dev (hi, lo) + p as a 384-bit integer; still fits 48 bytes because p < 2^381.
    function _plusP(uint256 hi, uint256 lo) internal pure returns (uint256, uint256) {
        unchecked {
            uint256 nLo = lo + BLS12381.P_LO;
            uint256 carry = nLo < lo ? 1 : 0;
            return (hi + BLS12381.P_HI + carry, nLo);
        }
    }

    /// @dev p - (hi, lo) for a canonical non-zero field element.
    function _pMinus(uint256 hi, uint256 lo) internal pure returns (uint256, uint256) {
        unchecked {
            uint256 nLo = BLS12381.P_LO - lo;
            uint256 borrow = BLS12381.P_LO < lo ? 1 : 0;
            return (BLS12381.P_HI - hi - borrow, nLo);
        }
    }

    /// @dev The negated point (x, p - y): a valid subgroup point that is not the signature.
    function _negated(bytes memory affine) internal pure returns (bytes memory m) {
        m = bytes.concat(affine);
        (uint256 yHi, uint256 yLo) = _coord(m, 48);
        (yHi, yLo) = _pMinus(yHi, yLo);
        _setCoord(m, 48, yHi, yLo);
    }

    /// @dev Expected revert data for an arbitrary byte string presented as a signature whose point is
    ///      not the signature: the verifier's encoding checks in their order (length, canonical
    ///      coordinates, infinity), then the pairing precompile, which rejects every remaining
    ///      off-curve or non-subgroup point. Only used where a fuzzed mutation decides canonicality.
    function _expectedEncodingError(bytes memory m) internal pure returns (bytes memory) {
        if (m.length != 96) return abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, m.length);
        (uint256 xHi, uint256 xLo) = _coord(m, 0);
        (uint256 yHi, uint256 yLo) = _coord(m, 48);
        if (!BLS12381.isCanonicalFp(xHi, xLo) || !BLS12381.isCanonicalFp(yHi, yLo)) {
            return abi.encodeWithSelector(BLS12381.NonCanonicalFieldElement.selector);
        }
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) {
            return abi.encodeWithSelector(BLS12381.InfinityPoint.selector);
        }
        return _failure(address(0x0f));
    }
}

contract BeaconVerifierTest is BeaconVerifierFixture {
    // ------------------------------------------------------------------ §10.3 required tests

    function test_Rfc9380Vectors() public view {
        // K.1 expand_message_xmd(SHA-256)
        uint256 i;
        while (vm.keyExistsJson(json, string.concat(".rfc9380.expandMessageXmd[", vm.toString(i), "].msg"))) {
            string memory p = string.concat(".rfc9380.expandMessageXmd[", vm.toString(i), "]");
            bytes memory out = harness.expandMessageXmd(
                bytes(vm.parseJsonString(json, string.concat(p, ".msg"))),
                bytes(vm.parseJsonString(json, string.concat(p, ".dst"))),
                vm.parseJsonUint(json, string.concat(p, ".lenInBytes"))
            );
            assertEq(out, vm.parseJsonBytes(json, string.concat(p, ".uniformBytes")), p);
            i++;
        }
        assertEq(i, 10, "ten expand_message_xmd vectors");

        // J.9.1 BLS12381G1_XMD:SHA-256_SSWU_RO_
        i = 0;
        while (vm.keyExistsJson(json, string.concat(".rfc9380.hashToCurveG1[", vm.toString(i), "].msg"))) {
            string memory p = string.concat(".rfc9380.hashToCurveG1[", vm.toString(i), "]");
            bytes memory msg_ = bytes(vm.parseJsonString(json, string.concat(p, ".msg")));
            bytes memory dst = bytes(vm.parseJsonString(json, string.concat(p, ".dst")));
            (bytes memory u0, bytes memory u1) = harness.hashToField(msg_, dst);
            assertEq(u0, _pad64(vm.parseJsonBytes(json, string.concat(p, ".u0"))), "u0");
            assertEq(u1, _pad64(vm.parseJsonBytes(json, string.concat(p, ".u1"))), "u1");
            bytes memory pt = harness.hashToG1(msg_, dst);
            bytes memory expected = bytes.concat(
                _pad64(vm.parseJsonBytes(json, string.concat(p, ".px"))),
                _pad64(vm.parseJsonBytes(json, string.concat(p, ".py")))
            );
            assertEq(pt, expected, p);
            i++;
        }
        assertEq(i, 5, "five hash-to-curve vectors");
    }

    function test_IndependentBlsVectors() public view {
        // Every signature produced by @noble/curves verifies and yields the independently hashed R.
        for (uint256 i = 0; i < rounds.length; i++) {
            RoundVec memory v = rounds[i];
            assertEq(verifier.verify(v.round, v.affine), v.value, string.concat("round ", vm.toString(v.round)));
            assertEq(verifier.epochOf(v.round), v.epoch);
        }
        assertEq(rounds[rounds.length - 1].round, maxRound, "fixture covers maxRound");

        // Deterministic threshold fixture: partials verify under their public shares, every
        // t-subset reconstructs the same group signature on-chain (G1MSM), and it verifies.
        uint64 thRound = uint64(vm.parseJsonUint(json, ".threshold.round"));
        bytes memory hm = harness.hashToG1(
            vm.parseJsonBytes(json, ".threshold.message"), bytes(vm.parseJsonString(json, ".network.dst"))
        );
        assertEq(hm, _affineToEip(vm.parseJsonBytes(json, ".threshold.hashToCurveAffine")), "H(M)");
        uint256 n = vm.parseJsonUint(json, ".threshold.n");
        bytes[] memory partialEip = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory p = string.concat(".threshold.shares[", vm.toString(i), "]");
            bytes memory partialSig = vm.parseJsonBytes(json, string.concat(p, ".partialAffine"));
            bytes memory share = vm.parseJsonBytes(json, string.concat(p, ".publicShareEip256"));
            assertTrue(harness.pairing(partialSig, hm, share), "partial verifies under public share");
            partialEip[i] = _affineToEip(partialSig);
        }
        bytes memory groupAffine = vm.parseJsonBytes(json, ".threshold.groupSignatureAffine");
        bytes memory groupEip = _affineToEip(groupAffine);
        uint256 s;
        while (vm.keyExistsJson(json, string.concat(".threshold.subsets[", vm.toString(s), "].indices"))) {
            string memory p = string.concat(".threshold.subsets[", vm.toString(s), "]");
            uint256[] memory idx = vm.parseJsonUintArray(json, string.concat(p, ".indices"));
            uint256[] memory lambdas = vm.parseJsonUintArray(json, string.concat(p, ".lambdas"));
            bytes memory input;
            for (uint256 k = 0; k < idx.length; k++) {
                input = bytes.concat(input, partialEip[idx[k]], bytes32(lambdas[k]));
            }
            assertEq(harness.g1Msm(input), groupEip, string.concat("subset ", vm.toString(s)));
            s++;
        }
        assertEq(s, 4, "all 3-of-4 subsets");
        assertEq(verifier.verify(thRound, groupAffine), vm.parseJsonBytes32(json, ".threshold.value"));
    }

    function test_CanonicalCompressionHash() public view {
        bool sawSet;
        bool sawClear;
        for (uint256 i = 0; i < rounds.length; i++) {
            RoundVec memory v = rounds[i];
            bytes memory c = harness.compress(v.affine);
            assertEq(c, v.compressed, "compressed form matches the independent encoder");
            assertEq(sha256(c), v.value, "R = SHA256(compressed)");
            if (uint8(c[0]) & 0x20 != 0) sawSet = true;
            else sawClear = true;
        }
        assertTrue(sawSet && sawClear, "fixture exercises both sign bits");
    }

    function test_RejectInfinity() public {
        bytes memory inf = _negativeBytes("infinityAffine");
        vm.expectRevert(BLS12381.InfinityPoint.selector);
        verifier.verify(1, inf);
        vm.expectRevert(BLS12381.InfinityPoint.selector);
        verifier.submit(1, inf);
        // infinity group key at genesis
        vm.expectRevert(BLS12381.InvalidGroupKey.selector);
        new BeaconVerifier(networkId, genesisTime, _keyFrom(".negative.groupKeyInfinityWords"), address(authority));
    }

    function test_RejectNonSubgroup() public {
        // On the curve, outside the prime-order subgroup: the pairing precompile fails the call.
        bytes memory ns = _negativeBytes("nonSubgroupG1Affine");
        vm.expectRevert(abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, address(0x0f)));
        verifier.verify(1, ns);
        bytes memory off = _negativeBytes("offCurveG1Affine");
        vm.expectRevert(abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, address(0x0f)));
        verifier.verify(1, off);
        // Group key outside the G2 subgroup, or with swapped coefficient order, never installs.
        vm.expectRevert(BLS12381.InvalidGroupKey.selector);
        new BeaconVerifier(networkId, genesisTime, _keyFrom(".negative.groupKeyNonSubgroupWords"), address(authority));
        vm.expectRevert(BLS12381.InvalidGroupKey.selector);
        new BeaconVerifier(
            networkId, genesisTime, _keyFrom(".negative.groupKeyWrongCoefficientOrderWords"), address(authority)
        );
    }

    function test_RejectNonCanonicalField() public {
        vm.expectRevert(BLS12381.NonCanonicalFieldElement.selector);
        verifier.verify(1, _negativeBytes("nonCanonicalXAffine"));
        vm.expectRevert(BLS12381.NonCanonicalFieldElement.selector);
        verifier.verify(1, _negativeBytes("nonCanonicalYAffine"));
        // compressed-form flag bits in the submit form are non-canonical too
        bytes memory flagged = _vec(1).affine;
        flagged[0] = bytes1(uint8(flagged[0]) | 0x80);
        vm.expectRevert(BLS12381.NonCanonicalFieldElement.selector);
        verifier.verify(1, flagged);
        vm.expectRevert(BLS12381.InvalidGroupKey.selector);
        new BeaconVerifier(networkId, genesisTime, _keyFrom(".negative.groupKeyNonCanonicalWords"), address(authority));
    }

    function test_RejectMalformedLength() public {
        bytes memory good = _vec(1).affine;
        uint256[7] memory lengths = [uint256(0), 1, 47, 48, 95, 97, 128];
        for (uint256 i = 0; i < lengths.length; i++) {
            bytes memory b = new bytes(lengths[i]);
            for (uint256 j = 0; j < b.length && j < 96; j++) {
                b[j] = good[j];
            }
            vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, lengths[i]));
            verifier.verify(1, b);
            vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, lengths[i]));
            verifier.submit(1, b);
        }
        // the 48-byte compressed form is not accepted as submit form
        vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, 48));
        verifier.verify(1, _vec(1).compressed);
    }

    function test_RejectWrongNetworkEpochRound() public {
        RoundVec memory r1 = _vec(1);
        // wrong network: same key, same round, other networkId in M
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.verify(1, vm.parseJsonBytes(json, ".negative.otherNetworkRound1.signatureAffine"));
        // wrong epoch field in M
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.verify(1, vm.parseJsonBytes(json, ".negative.wrongEpochRound1.signatureAffine"));
        // wrong key
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.verify(1, vm.parseJsonBytes(json, ".negative.wrongKeyRound1.signatureAffine"));
        // wrong round for a valid signature
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.verify(2, r1.affine);
        // round 0 and overflow
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, 0));
        verifier.verify(0, r1.affine);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, maxRound + 1));
        verifier.verify(maxRound + 1, r1.affine);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, type(uint64).max));
        verifier.verify(type(uint64).max, r1.affine);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, 0));
        verifier.roundTime(0);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, maxRound + 1));
        verifier.roundTime(maxRound + 1);
        assertEq(verifier.roundTime(maxRound), genesisTime + 30 * (maxRound - 1));
        assertGt(
            uint256(verifier.roundTime(maxRound)) + 30, uint256(type(uint64).max), "T(maxRound + 1) overflows uint64"
        );

        // epoch gate: an unauthorized epoch cannot publish, but the pure check still verifies
        RoundVec memory r5761 = _vec(5761); // epoch 2, never authorized by the mock
        assertEq(verifier.verify(5761, r5761.affine), r5761.value);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.EpochNotAuthorized.selector, 2));
        verifier.submit(5761, r5761.affine);
        authority.set(networkId, 2, true);
        assertTrue(verifier.submit(5761, r5761.affine));
        // authority with no code fails closed: the STATICCALL to an empty account returns no data,
        // so the ABI decoder of the bool result reverts with empty revert data (finding 5)
        BeaconVerifier lone = new BeaconVerifier(networkId, genesisTime, key, address(0xBEEF));
        vm.expectRevert(bytes(""));
        lone.submit(5761, r5761.affine);
        assertTrue(lone.submit(1, r1.affine), "genesis epoch needs no authority");

        // early submission reverts exactly until T(r)
        RoundVec memory r2881 = _vec(2881);
        vm.warp(verifier.roundTime(2881) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(BeaconVerifier.RoundNotReleased.selector, 2881, verifier.roundTime(2881))
        );
        verifier.submit(2881, r2881.affine);
        vm.warp(verifier.roundTime(2881));
        assertTrue(verifier.submit(2881, r2881.affine));

        // descriptor zero values never install
        vm.expectRevert(BeaconVerifier.InvalidDescriptor.selector);
        new BeaconVerifier(bytes32(0), genesisTime, key, address(authority));
        vm.expectRevert(BeaconVerifier.InvalidDescriptor.selector);
        new BeaconVerifier(networkId, 0, key, address(authority));
        vm.expectRevert(BeaconVerifier.InvalidDescriptor.selector);
        new BeaconVerifier(networkId, genesisTime, key, address(0));
    }

    function test_RejectMissingPrecompile() public {
        RoundVec memory r1 = _vec(1);
        address[5] memory used = [address(0x02), address(0x05), address(0x0b), address(0x0f), address(0x10)];
        for (uint256 i = 0; i < used.length; i++) {
            // A missing precompile is an empty account: the STATICCALL succeeds with no return data.
            vm.mockCall(used[i], bytes(""), bytes(""));
            vm.expectRevert(abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, used[i]));
            verifier.verify(1, r1.affine);
            vm.clearMockedCalls();
        }
        // wrong return length from the pairing precompile fails closed
        vm.mockCall(address(0x0f), bytes(""), new bytes(31));
        vm.expectRevert(abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, address(0x0f)));
        verifier.verify(1, r1.affine);
        vm.clearMockedCalls();
        // a 32-byte zero means "not equal", not success
        vm.mockCall(address(0x0f), bytes(""), new bytes(32));
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.verify(1, r1.affine);
        vm.clearMockedCalls();
        // genesis fails on every missing precompile it depends on, each with its own error: the
        // group-key check (G2MSM, 0x0e) reports InvalidGroupKey, every other wrapper names the
        // precompile that returned nothing (finding 5)
        address[6] memory genesisUsed =
            [address(0x02), address(0x05), address(0x0b), address(0x0e), address(0x0f), address(0x10)];
        for (uint256 i = 0; i < genesisUsed.length; i++) {
            vm.mockCall(genesisUsed[i], bytes(""), bytes(""));
            vm.expectRevert(
                genesisUsed[i] == address(0x0e)
                    ? abi.encodeWithSelector(BLS12381.InvalidGroupKey.selector)
                    : _failure(genesisUsed[i])
            );
            new BeaconVerifier(networkId, genesisTime, key, address(authority));
            vm.clearMockedCalls();
        }
        // sanity: without mocks the same inputs pass
        assertEq(verifier.verify(1, r1.affine), r1.value);
    }

    function test_OutOfOrderRound() public {
        uint64[3] memory order = [uint64(5), 3, 4];
        for (uint256 i = 0; i < order.length; i++) {
            RoundVec memory v = _vec(order[i]);
            assertFalse(_isAvailable(v.round));
            assertTrue(verifier.submit(v.round, v.affine));
            (bool a, bytes32 val) = verifier.get(v.round);
            assertTrue(a);
            assertEq(val, v.value);
        }
        assertFalse(_isAvailable(1), "round 1 was never required");
        assertFalse(_isAvailable(2));
    }

    function test_NoDuplicateFee() public {
        RoundVec memory v = _vec(9);
        vm.expectEmit(true, true, true, true, address(verifier));
        emit IBeacon.RoundVerified(networkId, 0, 9, v.value, v.compressed);
        assertTrue(verifier.submit(9, v.affine), "first write");

        vm.recordLogs();
        assertFalse(verifier.submit(9, v.affine), "duplicate is a no-op");
        assertEq(vm.getRecordedLogs().length, 0, "duplicate emits nothing");
        (bool a, bytes32 val) = verifier.get(9);
        assertTrue(a);
        assertEq(val, v.value);

        // a different point for an available round is verified like a first submission: the negated
        // signature is a valid subgroup point that fails the pairing, so it is InvalidSignature,
        // not a value comparison (finding 1)
        bytes memory negated = _negativeBytes("negatedSignatureAffine"); // negation of the round-1 signature
        assertEq(negated, _negated(_vec(1).affine), "fixture is the negation of the round-1 signature");
        assertTrue(verifier.submit(1, _vec(1).affine));
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        verifier.submit(1, negated);
        // malformed duplicates still revert
        vm.expectRevert(BLS12381.InfinityPoint.selector);
        verifier.submit(1, _negativeBytes("infinityAffine"));
        // a duplicate from another sender is also a no-op
        vm.prank(address(0x1234));
        assertFalse(verifier.submit(1, _vec(1).affine));
    }

    /// @dev Finding 1 (audit round 2): once a round is available, a resubmission must go through the
    ///      full verification. Off-curve and non-subgroup points are rejected by the pairing
    ///      precompile exactly as on a first submission; a point with the signature's x and sign bit
    ///      but a different y (same compressed form, so the same hash) must not be mistaken for a
    ///      matching duplicate.
    function test_DuplicateRejectsInvalidPoint() public {
        RoundVec memory v = _vec(1);
        assertTrue(verifier.submit(1, v.affine));
        bytes memory off = _negativeBytes("offCurveG1Affine");
        bytes memory ns = _negativeBytes("nonSubgroupG1Affine");
        vm.expectRevert(_failure(address(0x0f)));
        verifier.submit(1, off);
        vm.expectRevert(_failure(address(0x0f)));
        verifier.submit(1, ns);

        // same x, same sign bit, y off the curve: the compressed form (hash preimage) is unchanged
        bytes memory yFlipped = bytes.concat(v.affine);
        yFlipped[95] = bytes1(uint8(yFlipped[95]) ^ 0x01);
        assertEq(harness.compress(yFlipped), v.compressed, "mutation keeps the compressed form");
        vm.expectRevert(_failure(address(0x0f)));
        verifier.verify(1, yFlipped);
        vm.recordLogs();
        vm.expectRevert(_failure(address(0x0f)));
        verifier.submit(1, yFlipped);
        assertEq(vm.getRecordedLogs().length, 0);
        (bool a, bytes32 val) = verifier.get(1);
        assertTrue(a);
        assertEq(val, v.value, "stored randomness changed");

        // the same inputs get the same errors before the round is published
        vm.expectRevert(_failure(address(0x0f)));
        verifier.submit(2, off);
        vm.expectRevert(_failure(address(0x0f)));
        verifier.submit(2, ns);
        _assertUnset(2);
    }

    /// @dev RoundValueMismatch is the comparison after a full verification. A BLS signature on
    ///      (PK, M) is unique, so with real SHA-256 a verified duplicate always matches; the branch is
    ///      reachable only by storing a different value first, here through the SHA-256 mock that
    ///      test_ZeroRandomnessAvailability is allowed to use.
    function test_DuplicateWithDifferentStoredValueReverts() public {
        RoundVec memory v = _vec(42);
        vm.mockCall(address(0x02), v.compressed, abi.encode(bytes32(0)));
        assertTrue(verifier.submit(42, v.affine));
        vm.clearMockedCalls();
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.RoundValueMismatch.selector, 42));
        verifier.submit(42, v.affine);
        (bool a, bytes32 val) = verifier.get(42);
        assertTrue(a);
        assertEq(val, bytes32(0), "mismatch must not overwrite");
    }

    function test_ZeroRandomnessAvailability() public {
        // Unavailable rounds read (false, 0).
        (bool a0, bytes32 v0) = verifier.get(42);
        assertFalse(a0);
        assertEq(v0, bytes32(0));
        // Mock only the final SHA256(compressed signature) call (allowed for this value-path
        // case). The real parser, hash-to-curve and pairing still run. This exercises an actual
        // first write of zero, rather than editing the value slot after storing a nonzero value.
        RoundVec memory v = _vec(42);
        vm.mockCall(address(0x02), v.compressed, abi.encode(bytes32(0)));
        assertEq(verifier.verify(42, v.affine), bytes32(0));
        vm.expectEmit(true, true, true, true, address(verifier));
        emit IBeacon.RoundVerified(networkId, 0, 42, bytes32(0), v.compressed);
        assertTrue(verifier.submit(42, v.affine));
        (bool a1, bytes32 v1) = verifier.get(42);
        assertTrue(a1, "all-zero R is available");
        assertEq(v1, bytes32(0));
        vm.recordLogs();
        assertFalse(verifier.submit(42, v.affine), "a zero-valued round must still be a duplicate");
        assertEq(vm.getRecordedLogs().length, 0);
        assertFalse(_isAvailable(41));
        assertFalse(_isAvailable(43));
        vm.clearMockedCalls();
    }

    // ------------------------------------------------------------------ fuzz (SPEC §10.3)

    /// @dev Finding 2 (audit round 2): every run is adversarial. The run picks one of the independent
    ///      signatures and one encoding class, builds the encoding, and checks the exact error on
    ///      `verify`, on a first `submit`, and on a duplicate `submit` after the genuine signature
    ///      has been published. Classes: x + p, y + p, p - y (the negated point), compressed-form
    ///      flag bits in x, infinity, a y change that keeps x and the sign bit (same compressed
    ///      form), trailing bytes, truncation, and a single random byte change.
    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_EncodingCannotChangeOutput(uint8 roundIdx, uint8 class, uint8 pos, uint8 mask, uint8 extra)
        public
    {
        RoundVec memory v = rounds[roundIdx % rounds.length];
        vm.warp(type(uint64).max); // every round, up to maxRound, is released
        authority.set(networkId, v.epoch, true);
        (bytes memory m, bytes memory err) = _adversarialEncoding(v, class % 9, pos, mask, extra);
        assertTrue(keccak256(m) != keccak256(v.affine), "encoding must differ from the signature");

        vm.expectRevert(err);
        verifier.verify(v.round, m);
        vm.expectRevert(err);
        verifier.submit(v.round, m);
        _assertUnset(v.round);

        assertTrue(verifier.submit(v.round, v.affine), "genuine signature publishes");
        vm.recordLogs();
        vm.expectRevert(err);
        verifier.submit(v.round, m);
        assertEq(vm.getRecordedLogs().length, 0, "rejected duplicate emitted");
        (bool available, bytes32 value) = verifier.get(v.round);
        assertTrue(available);
        assertEq(value, v.value, "rejected duplicate changed the stored value");
    }

    /// @dev Builds the adversarial encoding for `class` and the exact revert data it must produce.
    function _adversarialEncoding(RoundVec memory v, uint8 class, uint8 pos, uint8 mask, uint8 extra)
        internal
        view
        returns (bytes memory m, bytes memory err)
    {
        m = bytes.concat(v.affine);
        bytes memory nonCanonical = abi.encodeWithSelector(BLS12381.NonCanonicalFieldElement.selector);
        if (class == 0) {
            // x + p: same point modulo p, non-canonical x
            (uint256 hi, uint256 lo) = _coord(m, 0);
            (hi, lo) = _plusP(hi, lo);
            _setCoord(m, 0, hi, lo);
            err = nonCanonical;
        } else if (class == 1) {
            // y + p: same point modulo p, non-canonical y
            (uint256 hi, uint256 lo) = _coord(m, 48);
            (hi, lo) = _plusP(hi, lo);
            _setCoord(m, 48, hi, lo);
            err = nonCanonical;
        } else if (class == 2) {
            // p - y: the negated point, a valid subgroup point that fails the pairing
            m = _negated(v.affine);
            err = abi.encodeWithSelector(BeaconVerifier.InvalidSignature.selector);
        } else if (class == 3) {
            // compressed-form flag bits (any non-empty subset of 0x80, 0x40, 0x20) in the top byte
            // of x: x < p < 2^381, so every such x is >= 2^381 > p and therefore non-canonical
            uint8 flags = (mask & 0xe0) == 0 ? 0x80 : mask & 0xe0;
            m[0] = bytes1(uint8(m[0]) | flags);
            err = nonCanonical;
        } else if (class == 4) {
            m = new bytes(96);
            err = abi.encodeWithSelector(BLS12381.InfinityPoint.selector);
        } else if (class == 5) {
            // y changed in its low byte, x and the sign bit kept: the compressed form is unchanged,
            // the point is off the curve (finding 1's class). The pairing precompile rejects it.
            uint8 bit = uint8(1) << (mask % 8);
            m[95] = bytes1(uint8(m[95]) ^ bit);
            assertEq(harness.compress(m), v.compressed, "class 5 must keep the compressed form");
            err = _failure(address(0x0f));
        } else if (class == 6) {
            // extra trailing bytes, including zeros
            m = bytes.concat(v.affine, new bytes(uint256(extra % 64) + 1));
            err = abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, m.length);
        } else if (class == 7) {
            // truncation
            uint256 len = pos % 96;
            m = new bytes(len);
            for (uint256 i = 0; i < len; i++) {
                m[i] = v.affine[i];
            }
            err = abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, len);
        } else {
            // any single-byte change: non-canonical if it pushes a coordinate to p or above
            // (only possible in a top byte), otherwise an off-curve point for the pairing precompile
            uint8 flip = mask == 0 ? 1 : mask;
            m[pos % 96] = bytes1(uint8(m[pos % 96]) ^ flip);
            err = _expectedEncodingError(m);
            assertTrue(
                keccak256(err) == keccak256(nonCanonical) || keccak256(err) == keccak256(_failure(address(0x0f))),
                "a byte flip is non-canonical or off-curve"
            );
        }
    }

    /// @dev Finding 3 (audit round 2): mutated points and messages fail with exact errors, both on
    ///      `verify` and on `submit` after the mutated round's genuine signature has been published.
    ///      Modes: a changed coordinate (off-curve: PrecompileFailure(0x0f), or NonCanonicalFieldElement
    ///      when the change lands at or above p), another round for the same signature, swapped
    ///      coordinates, the negated point, sig + G1 and 2·sig (both valid subgroup points that
    ///      must fail the pairing with InvalidSignature).
    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_ModifiedSignatureFails(uint8 roundIdx, uint256 delta, bool onY, uint64 roundShift, uint8 mode)
        public
    {
        RoundVec memory v = rounds[roundIdx % rounds.length];
        vm.warp(type(uint64).max);
        authority.set(networkId, v.epoch, true);
        assertTrue(verifier.submit(v.round, v.affine), "genuine signature publishes");

        mode = mode % 6;
        uint64 round = v.round;
        bytes memory m = bytes.concat(v.affine);
        bytes memory err = abi.encodeWithSelector(BeaconVerifier.InvalidSignature.selector);
        if (mode == 0) {
            // modified coordinate: XOR a non-zero delta into the low word of x or y
            uint256 off = onY ? 48 : 0;
            (uint256 hi, uint256 lo) = _coord(m, off);
            _setCoord(m, off, hi, lo ^ (delta == 0 ? 1 : delta));
            err = _expectedEncodingError(m);
            assertTrue(
                keccak256(err) == keccak256(_failure(address(0x0f)))
                    || keccak256(err) == keccak256(abi.encodeWithSelector(BLS12381.NonCanonicalFieldElement.selector)),
                "a changed coordinate is off-curve or non-canonical"
            );
        } else if (mode == 1) {
            // modified message: the signature presented for another round, including other epochs
            round = uint64(bound(roundShift, 1, maxRound - 1));
            if (round >= v.round) round++;
            authority.set(networkId, verifier.epochOf(round), true);
        } else if (mode == 2) {
            // swapped coordinates: canonical, so the pairing precompile rejects the off-curve point
            m = new bytes(96);
            for (uint256 i = 0; i < 48; i++) {
                m[i] = v.affine[48 + i];
                m[48 + i] = v.affine[i];
            }
            assertEq(_expectedEncodingError(m), _failure(address(0x0f)), "swapped coordinates stay canonical");
            err = _failure(address(0x0f));
        } else if (mode == 3) {
            // negated point: valid encoding, in the subgroup, wrong signature
            m = _negated(v.affine);
        } else if (mode == 4) {
            // sig + G1: in the subgroup, not the signature
            m = _eipToAffine(harness.addG1(_affineToEip(v.affine), harness.g1Generator()));
        } else {
            // 2·sig: in the subgroup, not the signature
            m = _eipToAffine(harness.addG1(_affineToEip(v.affine), _affineToEip(v.affine)));
        }
        assertTrue(keccak256(m) != keccak256(v.affine) || round != v.round, "mutation must change the input");

        vm.expectRevert(err);
        verifier.verify(round, m);
        vm.recordLogs();
        vm.expectRevert(err);
        verifier.submit(round, m);
        assertEq(vm.getRecordedLogs().length, 0);
        (bool available, bytes32 value) = verifier.get(v.round);
        assertTrue(available);
        assertEq(value, v.value, "published value changed");
        if (round != v.round) _assertUnset(round);
    }

    // ------------------------------------------------------------------ gas (docs/verification-gas.md)

    // Every gas test runs isolated: each external call from the test is its own transaction, so a
    // warm slot or account can only come from a prior transaction and `vm.lastFrameGas()` reports
    // the transaction's gas, including intrinsic and calldata gas (finding 6). Without isolation
    // the warm-word case would be measured with the availability word still warm and dirty from
    // the same transaction and undercount the on-chain cost.

    /// forge-config: default.isolate = true
    function testGas_VerifySingleRound() public {
        RoundVec memory v = _vec(17);
        assertTrue(vm.isIsolateMode(), "gas tests need isolated calls");
        bytes32 out = verifier.verify(v.round, v.affine);
        uint256 used = vm.lastFrameGas().gasTotalUsed;
        assertEq(out, v.value);
        emit log_named_uint("verify execution gas (call frame)", used);
        assertLe(used, 170_000, "verify budget");
    }

    /// forge-config: default.isolate = true
    function testGas_SubmitFirstWrite() public {
        _submitReceipt(verifier, _vec(17), "epoch 0, fresh availability word", 250_000);
    }

    /// @dev The availability word is made non-zero by round 16 in a prior transaction, so round 17
    ///      pays a cold SLOAD and a non-zero-to-non-zero SSTORE (2,100 + 2,900) instead of the fresh
    ///      word's zero-to-non-zero write (2,100 + 20,000). The same round on a fresh instance
    ///      pins that difference exactly.
    /// forge-config: default.isolate = true
    function testGas_SubmitFirstWriteWarmWord() public {
        assertTrue(verifier.submit(16, _vec(16).affine));
        uint256 warm = _submitReceipt(verifier, _vec(17), "epoch 0, availability word already non-zero", 250_000);
        BeaconVerifier fresh = new BeaconVerifier(networkId, genesisTime, key, address(authority));
        uint256 cold = _submitReceipt(fresh, _vec(17), "epoch 0, fresh availability word (same round)", 250_000);
        assertEq(cold - warm, 17_100, "warm word must come from a prior transaction");
    }

    /// forge-config: default.isolate = true
    function testGas_SubmitFirstWriteWithEpochGate() public {
        _submitReceipt(verifier, _vec(2881), "epoch 1, authority consulted", 250_000);
    }

    /// @dev No budget applies to duplicates; the number is reported because the duplicate path now
    ///      runs the full verification (finding 1).
    /// forge-config: default.isolate = true
    function testGas_SubmitDuplicate() public {
        RoundVec memory v = _vec(17);
        assertTrue(vm.isIsolateMode(), "gas tests need isolated calls");
        assertTrue(verifier.submit(v.round, v.affine));
        bool first = verifier.submit(v.round, v.affine);
        uint256 receipt = vm.lastFrameGas().gasTotalUsed;
        assertFalse(first);
        emit log_named_uint("duplicate receipt gas (21000 + calldata + execution)", receipt);
        emit log_named_uint("duplicate execution gas", receipt - 21_000 - _calldataGas(v));
    }

    function _calldataGas(RoundVec memory v) internal pure returns (uint256 calldataGas) {
        bytes memory calldata_ = abi.encodeWithSelector(IBeacon.submit.selector, v.round, v.affine);
        for (uint256 i = 0; i < calldata_.length; i++) {
            calldataGas += calldata_[i] == 0 ? 4 : 16;
        }
    }

    function _submitReceipt(BeaconVerifier target, RoundVec memory v, string memory label, uint256 budget)
        internal
        returns (uint256 receipt)
    {
        assertTrue(vm.isIsolateMode(), "gas tests need isolated calls");
        uint256 calldataGas = _calldataGas(v);
        bool first = target.submit(v.round, v.affine);
        receipt = vm.lastFrameGas().gasTotalUsed; // the isolated transaction's gas: intrinsic + calldata + execution
        assertTrue(first);
        emit log_named_string("case", label);
        emit log_named_uint("calldata gas", calldataGas);
        emit log_named_uint("execution gas (receipt - 21000 - calldata)", receipt - 21_000 - calldataGas);
        emit log_named_uint("receipt gas (21000 + calldata + execution)", receipt);
        assertLe(receipt, budget, "submit receipt budget");
    }

    // ------------------------------------------------------------------ descriptor getters (§8.3)

    function test_DescriptorGetters() public view {
        assertEq(verifier.networkId(), networkId);
        assertEq(verifier.genesisTime(), genesisTime);
        assertEq(verifier.period(), 30);
        assertEq(verifier.epochLength(), 2880);
        assertEq(verifier.maxRound(), maxRound);
        assertEq(verifier.groupKey(), keyEip);
        assertEq(verifier.epochAuthority(), address(authority));
        assertEq(verifier.roundTime(1), genesisTime);
        assertEq(verifier.roundTime(2881), genesisTime + 30 * 2880);
        assertEq(verifier.epochOf(2880), 0);
        assertEq(verifier.epochOf(2881), 1);
        assertEq(verifier.roundAt(0), 1);
        assertEq(verifier.roundAt(genesisTime), 1);
        assertEq(verifier.roundAt(genesisTime + 1), 2);
        assertEq(verifier.roundAt(genesisTime + 30), 2);
        assertEq(verifier.roundAt(genesisTime + 31), 3);
        assertEq(verifier.roundAt(genesisTime + 3600), 121);
        assertEq(verifier.roundAt(verifier.roundTime(maxRound)), maxRound);
    }
}

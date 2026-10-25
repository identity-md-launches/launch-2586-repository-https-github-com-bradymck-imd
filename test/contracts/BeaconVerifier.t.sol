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

    function _pad64(bytes memory fp48) internal pure returns (bytes memory) {
        require(fp48.length == 48, "fp48");
        return bytes.concat(new bytes(16), fp48);
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
        // authority with no code fails closed
        BeaconVerifier lone = new BeaconVerifier(networkId, genesisTime, key, address(0xBEEF));
        vm.expectRevert();
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
        // genesis fails on every missing precompile it depends on
        address[6] memory genesisUsed =
            [address(0x02), address(0x05), address(0x0b), address(0x0e), address(0x0f), address(0x10)];
        for (uint256 i = 0; i < genesisUsed.length; i++) {
            vm.mockCall(genesisUsed[i], bytes(""), bytes(""));
            vm.expectRevert();
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

        // a mismatching submission for an available round reverts (negated point: valid encoding, different point)
        bytes memory negated = _negativeBytes("negatedSignatureAffine"); // negation of the round-1 signature
        assertTrue(verifier.submit(1, _vec(1).affine));
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.RoundValueMismatch.selector, 1));
        verifier.submit(1, negated);
        // malformed duplicates still revert
        vm.expectRevert(BLS12381.InfinityPoint.selector);
        verifier.submit(1, _negativeBytes("infinityAffine"));
        // a duplicate from another sender is also a no-op
        vm.prank(address(0x1234));
        assertFalse(verifier.submit(1, _vec(1).affine));
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

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_EncodingCannotChangeOutput(uint8 roundIdx, uint8 pos, uint8 mask, uint8 mode, uint8 extra)
        public
    {
        RoundVec memory v = rounds[roundIdx % rounds.length];
        mode = mode % 4;
        if (mode == 0) {
            // unmodified: output is exactly the independent value, however it is called
            assertEq(verifier.verify(v.round, v.affine), v.value);
            assertEq(harness.compress(v.affine), v.compressed);
        } else if (mode == 1) {
            // any single-byte change of the encoding is rejected
            mask = mask == 0 ? 1 : mask;
            bytes memory m = v.affine;
            m[pos % 96] = bytes1(uint8(m[pos % 96]) ^ mask);
            vm.expectRevert();
            verifier.verify(v.round, m);
        } else if (mode == 2) {
            // extra trailing bytes (even zeros) are rejected
            bytes memory m = bytes.concat(v.affine, new bytes(uint256(extra % 64) + 1));
            vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, m.length));
            verifier.verify(v.round, m);
        } else {
            // truncation is rejected
            uint256 len = pos % 96;
            bytes memory m = new bytes(len);
            for (uint256 i = 0; i < len; i++) {
                m[i] = v.affine[i];
            }
            vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, len));
            verifier.verify(v.round, m);
        }
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_ModifiedSignatureFails(uint8 roundIdx, uint256 delta, bool onY, uint64 roundShift, uint8 mode)
        public
    {
        RoundVec memory v = rounds[roundIdx % rounds.length];
        mode = mode % 4;
        if (mode == 0) {
            // modified point coordinate (kept canonical): off-curve or a different point
            bytes memory m = v.affine;
            uint256 off = onY ? 48 : 0;
            uint256 lo;
            assembly ("memory-safe") {
                lo := mload(add(add(m, 48), off))
            }
            lo = lo ^ (delta == 0 ? 1 : delta);
            assembly ("memory-safe") {
                mstore(add(add(m, 48), off), lo)
            }
            // keep the top byte canonical
            m[off] = bytes1(uint8(m[off]) & 0x1f);
            vm.expectRevert();
            verifier.verify(v.round, m);
        } else if (mode == 1) {
            // modified message: another round, including other epochs
            uint64 other = uint64(bound(roundShift, 1, maxRound - 1));
            if (other >= v.round) other++;
            vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
            verifier.verify(other, v.affine);
        } else if (mode == 2) {
            // swapped coordinates
            bytes memory m = new bytes(96);
            for (uint256 i = 0; i < 48; i++) {
                m[i] = v.affine[48 + i];
                m[48 + i] = v.affine[i];
            }
            vm.expectRevert();
            verifier.verify(v.round, m);
        } else {
            // negated point: valid encoding, in the subgroup, wrong signature
            bytes memory m = v.affine;
            uint256 yHi;
            uint256 yLo;
            assembly ("memory-safe") {
                yHi := shr(128, mload(add(m, 80)))
                yLo := mload(add(m, 96))
            }
            uint256 nLo;
            uint256 nHi;
            unchecked {
                nLo = BLS12381.P_LO - yLo;
                nHi = BLS12381.P_HI - yHi - (BLS12381.P_LO < yLo ? 1 : 0);
            }
            assembly ("memory-safe") {
                mstore(add(m, 96), nLo)
                // bytes 48..80: y's high 16 bytes || first 16 bytes of the new low word
                let w := mload(add(m, 80))
                w := or(shl(128, nHi), and(w, sub(shl(128, 1), 1)))
                mstore(add(m, 80), w)
            }
            vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
            verifier.verify(v.round, m);
        }
    }

    // ------------------------------------------------------------------ gas (docs/verification-gas.md)

    function testGas_VerifySingleRound() public {
        RoundVec memory v = _vec(17);
        verifier.networkId(); // warm the account, as a transaction's `to` is warm
        uint256 before = gasleft();
        bytes32 out = verifier.verify(v.round, v.affine);
        uint256 used = before - gasleft();
        assertEq(out, v.value);
        emit log_named_uint("verify execution gas (incl. CALL overhead)", used);
        assertLe(used, 170_000, "verify budget");
    }

    function testGas_SubmitFirstWrite() public {
        _submitReceipt(_vec(17), "epoch 0, fresh availability word", 250_000);
    }

    function testGas_SubmitFirstWriteWarmWord() public {
        assertTrue(verifier.submit(16, _vec(16).affine));
        _submitReceipt(_vec(17), "epoch 0, availability word already non-zero", 250_000);
    }

    function testGas_SubmitFirstWriteWithEpochGate() public {
        _submitReceipt(_vec(2881), "epoch 1, authority consulted", 250_000);
    }

    function _submitReceipt(RoundVec memory v, string memory label, uint256 budget) internal {
        bytes memory calldata_ = abi.encodeWithSelector(IBeacon.submit.selector, v.round, v.affine);
        uint256 calldataGas;
        for (uint256 i = 0; i < calldata_.length; i++) {
            calldataGas += calldata_[i] == 0 ? 4 : 16;
        }
        verifier.networkId(); // warm, as a transaction's `to` is warm
        uint256 before = gasleft();
        bool first = verifier.submit(v.round, v.affine);
        uint256 execution = before - gasleft();
        assertTrue(first);
        uint256 receipt = 21_000 + calldataGas + execution;
        emit log_named_string("case", label);
        emit log_named_uint("calldata bytes", calldata_.length);
        emit log_named_uint("calldata gas", calldataGas);
        emit log_named_uint("execution gas (incl. CALL overhead)", execution);
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

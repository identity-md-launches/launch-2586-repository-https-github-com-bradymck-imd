// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BeaconVerifierFixture, MockEpochAuthority, BlsHarness} from "./BeaconVerifier.t.sol";
import {BeaconVerifier} from "../../src/BeaconVerifier.sol";
import {IBeacon} from "../../src/interfaces/IBeacon.sol";
import {IEpochAuthority} from "../../src/interfaces/IEpochAuthority.sol";
import {BLS12381} from "../../src/bls/BLS12381.sol";
import {HashToCurveG1} from "../../src/bls/HashToCurveG1.sol";

/// @dev A failing external dependency, not a substitute for signature verification.
contract RevertingEpochAuthority is IEpochAuthority {
    error Unavailable();

    function isEpochAuthorized(bytes32, uint64) external pure returns (bool) {
        revert Unavailable();
    }
}

contract BlsBoundaryHarness is BlsHarness {
    function reduce(bytes calldata wide, uint256 offset) external view returns (bytes memory) {
        return BLS12381.reduceToFp(wide, offset);
    }

    function canonical(uint256 hi, uint256 lo) external pure returns (bool) {
        return BLS12381.isCanonicalFp(hi, lo);
    }

    function largerRoot(uint256 hi, uint256 lo) external pure returns (bool) {
        return BLS12381.isLargerRoot(hi, lo);
    }

    function strictCall(address target, uint256 outLen) external view returns (bytes memory) {
        return BLS12381.callPrecompile(target, bytes(""), outLen, 50_000);
    }
}

/// @notice Adversarial tests supplement the independently generated RFC/BLS fixtures.
///         No successful verification uses mocked cryptography. Precompile mocks below inject
///         faults only; they cannot make an invalid signature pass a positive test.
contract BeaconVerifierAdversarialTest is BeaconVerifierFixture {
    function _assertUnset(uint64 round) internal view {
        (bool available, bytes32 value) = verifier.get(round);
        assertFalse(available, "failed call made round available");
        assertEq(value, bytes32(0), "failed call left randomness behind");
    }

    function _failure(address target) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, target);
    }

    function test_FirstPublicationIsPermissionlessAndVerifyHasNoWrites() public {
        RoundVec memory v = _vec(17);
        address relayer = makeAddr("NON_PRODUCTION_RELAYER");
        vm.record();
        vm.prank(relayer);
        assertEq(verifier.verify(v.round, v.affine), v.value);
        (, bytes32[] memory writes) = vm.accesses(address(verifier));
        assertEq(writes.length, 0, "verify changed storage");
        _assertUnset(v.round);

        vm.expectEmit(true, true, true, true, address(verifier));
        emit IBeacon.RoundVerified(networkId, v.epoch, v.round, v.value, v.compressed);
        vm.prank(relayer);
        assertTrue(verifier.submit(v.round, v.affine));
        (bool available, bytes32 value) = verifier.get(v.round);
        assertTrue(available);
        assertEq(value, v.value);
    }

    function test_MatchingDuplicateDoesNotWriteOrEmit() public {
        RoundVec memory v = _vec(17);
        assertTrue(verifier.submit(v.round, v.affine));
        vm.record();
        vm.recordLogs();
        vm.prank(makeAddr("NON_PRODUCTION_SECOND_RELAYER"));
        assertFalse(verifier.submit(v.round, v.affine));
        (, bytes32[] memory writes) = vm.accesses(address(verifier));
        assertEq(writes.length, 0, "duplicate wrote storage");
        assertEq(vm.getRecordedLogs().length, 0, "duplicate emitted a reward-eligible event");
        (bool available, bytes32 value) = verifier.get(v.round);
        assertTrue(available);
        assertEq(value, v.value);
    }

    function test_FirstWriteUsesOnlyValueAndAvailabilitySlots() public {
        RoundVec memory v = _vec(17);
        vm.record();
        assertTrue(verifier.submit(v.round, v.affine));
        (, bytes32[] memory writes) = vm.accesses(address(verifier));
        assertEq(writes.length, 2, "unexpected storage side effects");
        bytes32 valueSlot = keccak256(abi.encode(uint256(v.round), uint256(0)));
        bytes32 availableSlot = keccak256(abi.encode(uint256(v.round) >> 8, uint256(1)));
        assertTrue(
            (writes[0] == valueSlot && writes[1] == availableSlot)
                || (writes[1] == valueSlot && writes[0] == availableSlot)
        );
        assertEq(vm.load(address(verifier), valueSlot), v.value);
        assertEq(uint256(vm.load(address(verifier), availableSlot)), uint256(1) << v.round);
    }

    function test_InvalidFirstSubmissionsAreAtomic() public {
        RoundVec memory goodNeighbor = _vec(2);
        assertTrue(verifier.submit(2, goodNeighbor.affine));
        bytes[9] memory invalid = [
            _negativeBytes("infinityAffine"),
            _negativeBytes("nonSubgroupG1Affine"),
            _negativeBytes("offCurveG1Affine"),
            _negativeBytes("nonCanonicalXAffine"),
            _negativeBytes("nonCanonicalYAffine"),
            _negativeBytes("negatedSignatureAffine"),
            vm.parseJsonBytes(json, ".negative.wrongKeyRound1.signatureAffine"),
            vm.parseJsonBytes(json, ".negative.otherNetworkRound1.signatureAffine"),
            vm.parseJsonBytes(json, ".negative.wrongEpochRound1.signatureAffine")
        ];
        for (uint256 i; i < invalid.length; ++i) {
            vm.record();
            vm.recordLogs();
            vm.expectRevert();
            verifier.submit(1, invalid[i]);
            (, bytes32[] memory writes) = vm.accesses(address(verifier));
            assertEq(writes.length, 0, "invalid input reached SSTORE");
            assertEq(vm.getRecordedLogs().length, 0);
            _assertUnset(1);
            (bool available, bytes32 value) = verifier.get(2);
            assertTrue(available, "invalid input cleared neighbor");
            assertEq(value, goodNeighbor.value, "invalid input changed neighbor");
        }
        assertTrue(verifier.submit(1, _vec(1).affine), "failed submissions must not poison retry");
    }

    function test_EpochAuthorizationIsBoundToPinnedNetworkAndDerivedEpoch() public {
        RoundVec memory v = _vec(5761);
        authority.set(vm.parseJsonBytes32(json, ".network.otherNetworkId"), 2, true);
        authority.set(networkId, 3, true);
        bytes memory gateCall = abi.encodeCall(IEpochAuthority.isEpochAuthorized, (networkId, uint64(2)));
        vm.expectCall(address(authority), gateCall);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.EpochNotAuthorized.selector, 2));
        verifier.submit(v.round, v.affine);
        _assertUnset(v.round);
        // Pure checking is deliberately independent of the destination's epoch mirror.
        assertEq(verifier.verify(v.round, v.affine), v.value);
        authority.set(networkId, 2, true);
        vm.expectEmit(true, true, true, true, address(verifier));
        emit IBeacon.RoundVerified(networkId, 2, v.round, v.value, v.compressed);
        assertTrue(verifier.submit(v.round, v.affine));
    }

    function test_EpochAuthorityFailureIsClosedAndGenesisRemainsUsable() public {
        RevertingEpochAuthority failing = new RevertingEpochAuthority();
        BeaconVerifier isolated = new BeaconVerifier(networkId, genesisTime, key, address(failing));
        RoundVec memory v = _vec(2881);
        vm.expectRevert(RevertingEpochAuthority.Unavailable.selector);
        isolated.submit(v.round, v.affine);
        (bool available, bytes32 value) = isolated.get(v.round);
        assertFalse(available);
        assertEq(value, bytes32(0));
        assertEq(isolated.verify(v.round, v.affine), v.value);
        assertTrue(isolated.submit(1, _vec(1).affine), "genesis epoch must not consult the authority");
    }

    function test_MalformedAuthorityReturnCannotAuthorizeAnEpoch() public {
        RoundVec memory v = _vec(2881);
        bytes memory gateCall = abi.encodeCall(IEpochAuthority.isEpochAuthorized, (networkId, uint64(1)));
        uint256[3] memory lengths = [uint256(0), 1, 31];
        for (uint256 i; i < lengths.length; ++i) {
            vm.mockCall(address(authority), gateCall, new bytes(lengths[i]));
            vm.expectRevert();
            verifier.submit(v.round, v.affine);
            _assertUnset(v.round);
            vm.clearMockedCalls();
        }
        vm.mockCall(address(authority), gateCall, abi.encode(uint256(2))); // invalid ABI bool
        vm.expectRevert();
        verifier.submit(v.round, v.affine);
        _assertUnset(v.round);
        vm.clearMockedCalls();
        assertTrue(verifier.submit(v.round, v.affine));
    }

    function test_StoredRandomnessSurvivesLaterAuthorityFailure() public {
        RoundVec memory v = _vec(2881);
        assertTrue(verifier.submit(v.round, v.affine));
        vm.mockCallRevert(address(authority), bytes(""), abi.encodeWithSignature("Unavailable()"));
        (bool available, bytes32 value) = verifier.get(v.round);
        assertTrue(available);
        assertEq(value, v.value);
        assertEq(verifier.verify(v.round, v.affine), v.value);
        // A not-yet-published round still fails closed; a broken mirror cannot replace the key.
        vm.expectRevert();
        verifier.submit(5760, _vec(5760).affine);
        _assertUnset(5760);
        vm.clearMockedCalls();
    }

    function test_GenesisReleaseBoundaryAndUnreleasedPureVerification() public {
        RoundVec memory v = _vec(1);
        vm.warp(genesisTime - 1);
        assertEq(verifier.verify(1, v.affine), v.value);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.RoundNotReleased.selector, 1, genesisTime));
        verifier.submit(1, v.affine);
        _assertUnset(1);
        vm.warp(genesisTime);
        assertTrue(verifier.submit(1, v.affine));
    }

    function test_ReceivingChainCallerAndTimestampDoNotChangeVerification() public {
        RoundVec memory v = _vec(2881);
        uint256[3] memory chains = [uint256(1), 8453, 4663];
        for (uint256 i; i < chains.length; ++i) {
            vm.chainId(chains[i]);
            vm.warp(i == 0 ? genesisTime - 1 : type(uint64).max);
            vm.prank(makeAddr(string.concat("NON_PRODUCTION_RELAYER_", vm.toString(i))));
            assertEq(verifier.verify(v.round, v.affine), v.value);
            _assertUnset(v.round);
        }
    }

    function test_ChangedNetworkOrGroupKeyRejectsOriginalSignature() public {
        bytes32 otherNetwork = vm.parseJsonBytes32(json, ".network.otherNetworkId");
        BeaconVerifier other = new BeaconVerifier(otherNetwork, genesisTime, key, address(authority));
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        other.verify(1, _vec(1).affine);
        assertEq(
            other.verify(1, vm.parseJsonBytes(json, ".negative.otherNetworkRound1.signatureAffine")),
            vm.parseJsonBytes32(json, ".negative.otherNetworkRound1.value")
        );
        BeaconVerifier otherKey =
            new BeaconVerifier(networkId, genesisTime, _keyFrom(".negative.otherGroupKeyWords"), address(authority));
        vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
        otherKey.verify(1, _vec(1).affine);
        assertEq(
            otherKey.verify(1, vm.parseJsonBytes(json, ".negative.wrongKeyRound1.signatureAffine")),
            vm.parseJsonBytes32(json, ".negative.wrongKeyRound1.value")
        );
    }

    function test_BitmapIsolationAtSparseAndExtremeRounds() public {
        uint64[10] memory order = [uint64(4294967296), 1, maxRound, maxRound - 1, 2880, 2881, 5760, 5761, 120, 100];
        vm.warp(type(uint64).max);
        for (uint256 i; i < order.length; ++i) {
            RoundVec memory v = _vec(order[i]);
            authority.set(networkId, v.epoch, true);
            assertTrue(verifier.submit(v.round, v.affine));
            for (uint256 j; j < order.length; ++j) {
                (bool available, bytes32 value) = verifier.get(order[j]);
                assertEq(available, j <= i, "availability bits leaked between rounds");
                assertEq(value, j <= i ? _vec(order[j]).value : bytes32(0));
            }
        }
        _assertUnset(0);
        _assertUnset(255);
        _assertUnset(256);
        _assertUnset(4294967295);
        _assertUnset(4294967297);
        _assertUnset(type(uint64).max);
    }

    function test_MaximumRoundReleaseAndOverflowEdges() public {
        RoundVec memory v = _vec(maxRound);
        uint64 lastTime = verifier.roundTime(maxRound);
        authority.set(networkId, v.epoch, true);
        vm.warp(lastTime - 1);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.RoundNotReleased.selector, maxRound, lastTime));
        verifier.submit(maxRound, v.affine);
        _assertUnset(maxRound);
        vm.warp(lastTime);
        assertTrue(verifier.submit(maxRound, v.affine));
        assertEq(verifier.roundAt(lastTime), maxRound);
        assertLt(lastTime, type(uint64).max, "fixture has a timestamp remainder");
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, type(uint64).max));
        verifier.roundAt(lastTime + 1);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, maxRound + 1));
        verifier.submit(maxRound + 1, v.affine);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, 0));
        verifier.submit(0, v.affine);
        vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, 0));
        verifier.epochOf(0);
    }

    function testFuzz_RoundAtSelectsEarliestSufficientRelease(uint64 timestamp) public {
        uint64 lastTime = verifier.roundTime(maxRound);
        if (timestamp > lastTime) {
            vm.expectRevert(abi.encodeWithSelector(BeaconVerifier.InvalidRound.selector, type(uint64).max));
            verifier.roundAt(timestamp);
        } else {
            uint64 round = verifier.roundAt(timestamp);
            assertGe(verifier.roundTime(round), timestamp);
            if (round > 1) assertLt(verifier.roundTime(round - 1), timestamp);
        }
    }

    function testFuzz_ScheduleAndEpochBoundaries(uint64 seed) public view {
        uint64 round = uint64(bound(seed, 1, maxRound - 1));
        assertEq(verifier.roundAt(verifier.roundTime(round)), round);
        assertEq(verifier.roundTime(round + 1) - verifier.roundTime(round), 30);
        uint64 epoch = verifier.epochOf(round);
        uint64 first = epoch * 2880 + 1;
        assertLe(first, round);
        assertLt(uint256(round), uint256(first) + 2880);
        assertEq(verifier.epochOf(first), epoch);
        if (first > 1) assertEq(verifier.epochOf(first - 1), epoch - 1);
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzz_MalformedDuplicateLengthsAreRejected(uint16 seed, uint8 fill) public {
        RoundVec memory v = _vec(1);
        assertTrue(verifier.submit(1, v.affine));
        uint256 len = bound(seed, 0, 320);
        if (len >= 96) ++len; // generate every selected length except the accepted one
        bytes memory malformed = new bytes(len);
        for (uint256 i; i < len; ++i) {
            malformed[i] = i < 96 ? v.affine[i] : bytes1(fill);
        }
        vm.expectRevert(abi.encodeWithSelector(BLS12381.InvalidSignatureLength.selector, len));
        verifier.submit(1, malformed);
        (bool available, bytes32 value) = verifier.get(1);
        assertTrue(available);
        assertEq(value, v.value);
    }

    function test_PrecompilesRejectShortOversizedAndRevertingResponses() public {
        RoundVec memory v = _vec(1);
        address[5] memory targets = [address(2), address(5), address(0x0b), address(0x0f), address(0x10)];
        uint256[5] memory sizes = [uint256(32), 48, 128, 32, 128];
        for (uint256 i; i < targets.length; ++i) {
            for (uint256 delta; delta < 2; ++delta) {
                uint256 length = delta == 0 ? sizes[i] - 1 : sizes[i] + 1;
                vm.mockCall(targets[i], bytes(""), new bytes(length));
                vm.expectRevert(_failure(targets[i]));
                verifier.verify(1, v.affine);
                vm.expectRevert(_failure(targets[i]));
                verifier.submit(1, v.affine);
                _assertUnset(1);
                vm.clearMockedCalls();
            }
            vm.mockCallRevert(targets[i], bytes(""), hex"aabbccdd");
            vm.expectRevert(_failure(targets[i]));
            verifier.submit(1, v.affine);
            _assertUnset(1);
            vm.clearMockedCalls();
        }
        assertTrue(verifier.submit(1, v.affine), "dependency failures cannot poison retry");
    }

    function test_PairingRequiresExactlyOneNotAnyNonzeroWord() public {
        uint256[3] memory words = [uint256(0), 2, type(uint256).max];
        for (uint256 i; i < words.length; ++i) {
            vm.mockCall(address(0x0f), bytes(""), abi.encode(words[i]));
            vm.expectRevert(BeaconVerifier.InvalidSignature.selector);
            verifier.submit(1, _vec(1).affine);
            _assertUnset(1);
            vm.clearMockedCalls();
        }
    }

    function test_FinalCompressedSignatureHashAlsoChecksReturnLength() public {
        RoundVec memory v = _vec(1);
        uint256[3] memory sizes = [uint256(0), 31, 33];
        for (uint256 i; i < sizes.length; ++i) {
            // Match just SHA256(compressed signature), after the real pairing succeeds.
            vm.mockCall(address(2), v.compressed, new bytes(sizes[i]));
            vm.expectRevert(_failure(address(2)));
            verifier.submit(1, v.affine);
            _assertUnset(1);
            vm.clearMockedCalls();
        }
        assertTrue(verifier.submit(1, v.affine));
    }

    function test_NonSubgroupFailurePreservesTheCallersRemainingGas() public {
        bytes memory invalid = _negativeBytes("nonSubgroupG1Affine");
        bytes memory input = abi.encodeCall(IBeacon.verify, (uint64(1), invalid));
        uint256 before = gasleft();
        (bool ok, bytes memory result) = address(verifier).staticcall{gas: 600_000}(input);
        uint256 used = before - gasleft();
        assertFalse(ok);
        // The pairing burns its forwarded cap but the verifier can still return its explicit
        // error. Forwarding all remaining gas instead would exhaust the outer call here.
        assertEq(result, _failure(address(0x0f)));
        assertLt(used, 500_000, "invalid point exhausted the outer call's gas allowance");
        _assertUnset(1);
    }

    function test_GenesisRejectsWrongLengthFromEveryRequiredPrecompile() public {
        address[6] memory targets = [address(2), address(5), address(0x0b), address(0x0e), address(0x0f), address(0x10)];
        uint256[6] memory sizes = [uint256(32), 48, 128, 256, 32, 128];
        for (uint256 i; i < targets.length; ++i) {
            for (uint256 delta; delta < 2; ++delta) {
                uint256 length = delta == 0 ? sizes[i] - 1 : sizes[i] + 1;
                vm.mockCall(targets[i], bytes(""), new bytes(length));
                bytes memory expected = targets[i] == address(0x0e)
                    ? abi.encodeWithSelector(BLS12381.InvalidGroupKey.selector)
                    : _failure(targets[i]);
                vm.expectRevert(expected);
                new BeaconVerifier(networkId, genesisTime, key, address(authority));
                vm.clearMockedCalls();
            }
            vm.mockCallRevert(targets[i], bytes(""), hex"aabbccdd");
            vm.expectRevert();
            new BeaconVerifier(networkId, genesisTime, key, address(authority));
            vm.clearMockedCalls();
        }
    }

    function test_GenesisRejectsIncorrectKnownAnswersEvenWithCorrectLength() public {
        // Correctly sized garbage must not pass genesis merely because STATICCALL succeeded.
        vm.mockCall(address(0x0e), bytes(""), new bytes(256));
        vm.expectRevert(BLS12381.InvalidGroupKey.selector);
        new BeaconVerifier(networkId, genesisTime, key, address(authority));
        vm.clearMockedCalls();
        vm.mockCall(address(0x0b), bytes(""), new bytes(128));
        vm.expectRevert(BeaconVerifier.GenesisSelfTestFailed.selector);
        new BeaconVerifier(networkId, genesisTime, key, address(authority));
        vm.clearMockedCalls();
        vm.mockCall(address(0x0f), bytes(""), abi.encode(uint256(2)));
        vm.expectRevert(BeaconVerifier.GenesisSelfTestFailed.selector);
        new BeaconVerifier(networkId, genesisTime, key, address(authority));
        vm.clearMockedCalls();
        BeaconVerifier healthy = new BeaconVerifier(networkId, genesisTime, key, address(authority));
        assertEq(healthy.verify(1, _vec(1).affine), _vec(1).value);
    }

    function test_GroupKeyRejectsPaddingBitsAndNonCanonicalInEveryCoefficient() public {
        // Each of x.c0, x.c1, y.c0, y.c1 is checked, including its 16-byte EIP padding.
        for (uint256 coordinate; coordinate < 4; ++coordinate) {
            for (uint256 mode; mode < 2; ++mode) {
                bytes memory malformed = bytes.concat(keyEip);
                if (mode == 0) {
                    malformed[coordinate * 64] = 0x01;
                } else {
                    uint256 offset = 32 + coordinate * 64;
                    uint256 hi = BLS12381.P_HI;
                    uint256 lo = BLS12381.P_LO;
                    assembly ("memory-safe") {
                        mstore(add(malformed, offset), hi)
                        mstore(add(malformed, add(offset, 32)), lo)
                    }
                }
                BeaconVerifier.GroupKeyWords memory bad = abi.decode(malformed, (BeaconVerifier.GroupKeyWords));
                vm.expectRevert(BLS12381.InvalidGroupKey.selector);
                new BeaconVerifier(networkId, genesisTime, bad, address(authority));
            }
        }
    }

    function test_LibraryFieldAndSignBoundaries() public {
        BlsBoundaryHarness h = new BlsBoundaryHarness();
        uint256 hi = BLS12381.P_HI;
        uint256 lo = BLS12381.P_LO;
        assertTrue(h.canonical(0, 0));
        assertTrue(h.canonical(hi, lo - 1));
        assertFalse(h.canonical(hi, lo));
        assertFalse(h.canonical(hi, lo + 1));
        assertTrue(h.canonical(hi - 1, type(uint256).max));
        assertFalse(h.canonical(hi + 1, 0));
        assertFalse(h.canonical(uint256(1) << 128, 0));
        assertFalse(h.largerRoot(BLS12381.HALF_P_HI, BLS12381.HALF_P_LO));
        assertTrue(h.largerRoot(BLS12381.HALF_P_HI, BLS12381.HALF_P_LO + 1));
        assertFalse(h.largerRoot(BLS12381.HALF_P_HI - 1, type(uint256).max));
        assertTrue(h.largerRoot(BLS12381.HALF_P_HI + 1, 0));
        // A genuinely absent account returns success + empty data on the EVM, not a digest.
        address empty = makeAddr("NON_PRODUCTION_MISSING_PRECOMPILE");
        assertEq(empty.code.length, 0);
        vm.expectRevert(_failure(empty));
        h.strictCall(empty, 32);
    }

    function test_ReduceToFieldAgainstIndependentIntegerVectors() public {
        BlsBoundaryHarness h = new BlsBoundaryHarness();
        string memory fields = vm.readFile("test/vectors/field-edges.json");
        uint256 n = vm.parseJsonUint(fields, ".count");
        assertGe(n, 10);
        for (uint256 i; i < n; ++i) {
            string memory path = string.concat(".cases[", vm.toString(i), "]");
            bytes memory wide = vm.parseJsonBytes(fields, string.concat(path, ".wide"));
            bytes memory reduced = vm.parseJsonBytes(fields, string.concat(path, ".paddedResult"));
            assertEq(h.reduce(wide, 0), reduced);
            assertEq(
                h.reduce(bytes.concat(hex"f00d", wide, hex"beef"), 2), reduced, "offset or neighboring bytes leaked"
            );
        }
    }

    function test_XmdRejectsInvalidLengthsAndDst() public {
        uint256[4] memory lengths = [uint256(0), 8161, 65535, 65536];
        for (uint256 i; i < lengths.length; ++i) {
            vm.expectRevert(HashToCurveG1.InvalidExpandLength.selector);
            harness.expandMessageXmd("abc", "DST", lengths[i]);
        }
        vm.expectRevert(HashToCurveG1.DstTooLong.selector);
        harness.expandMessageXmd("abc", new bytes(256), 128);
    }
}

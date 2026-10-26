// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BeaconVerifierFixture} from "./BeaconVerifier.t.sol";
import {IBeacon} from "../../src/interfaces/IBeacon.sol";
import {BLS12381} from "../../src/bls/BLS12381.sol";

/// @notice Proof of audit round 2, finding 1, kept as an ordinary regression test.
///         test/verification-notes.md of the previous delivery described this proof as a scratch
///         file (test/scratch/DuplicateOffCurveProof.t.sol) backed by .imd-findings.json; neither
///         was delivered. This is the proof: flip bit 0 of byte 95 (the low byte of y) of the
///         round-1 fixture. x and the compression sign bit are unchanged, so the compressed form,
///         and with it SHA256(compressed), is the stored value's exact preimage, while the point is
///         off the curve. `verify` rejected it; before the fix, a duplicate `submit` compared only
///         the hash and returned false instead of reverting.
contract DuplicateOffCurveProofTest is BeaconVerifierFixture {
    function test_DuplicateSubmitRejectsOffCurvePointWithStoredPreimage() public {
        RoundVec memory v = _vec(1);
        bytes memory offCurve = bytes.concat(v.affine);
        offCurve[95] = bytes1(uint8(offCurve[95]) ^ 0x01);
        assertEq(harness.compress(offCurve), v.compressed, "same x and sign bit: same compressed form");
        assertEq(sha256(v.compressed), v.value, "the stored value is SHA256 of that form");

        bytes memory expected = abi.encodeWithSelector(BLS12381.PrecompileFailure.selector, address(0x0f));
        vm.expectRevert(expected);
        verifier.verify(1, offCurve);
        vm.expectRevert(expected);
        verifier.submit(1, offCurve);
        _assertUnset(1);

        assertTrue(verifier.submit(1, v.affine), "genuine round-1 signature publishes");
        vm.recordLogs();
        (bool ok, bytes memory result) = address(verifier).call(abi.encodeCall(IBeacon.submit, (1, offCurve)));
        assertFalse(ok, "off-curve duplicate with the stored preimage was accepted");
        assertEq(result, expected, "off-curve duplicate must fail in the pairing precompile");
        assertEq(vm.getRecordedLogs().length, 0);
        (bool available, bytes32 value) = verifier.get(1);
        assertTrue(available);
        assertEq(value, v.value);
    }
}

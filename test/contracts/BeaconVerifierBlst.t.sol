// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BeaconVerifierFixture} from "./BeaconVerifier.t.sol";

/// @notice blst 0.3.16 (pyblst 0.3.15) is a second independent cryptographic oracle.
///         The generator and its native dependency are committed under test/vectors; tests
///         consume JSON only, with no FFI, native code, network, RPC, or generator invocation.
contract BeaconVerifierBlstTest is BeaconVerifierFixture {
    function _blstRound(string memory data, uint256 index) internal pure returns (RoundVec memory v) {
        string memory path = string.concat(".rounds[", vm.toString(index), "]");
        v.round = uint64(vm.parseJsonUint(data, string.concat(path, ".round")));
        v.epoch = uint64(vm.parseJsonUint(data, string.concat(path, ".epoch")));
        v.affine = vm.parseJsonBytes(data, string.concat(path, ".signatureAffine"));
        v.compressed = vm.parseJsonBytes(data, string.concat(path, ".signatureCompressed"));
        v.value = vm.parseJsonBytes32(data, string.concat(path, ".value"));
    }

    function _toEip(bytes memory affine) internal pure returns (bytes memory out) {
        require(affine.length == 96, "fixture length");
        out = new bytes(128);
        for (uint256 i; i < 48; ++i) {
            out[16 + i] = affine[i];
            out[80 + i] = affine[48 + i];
        }
    }

    function test_BlstIndependentlyMatchesEveryNobleSignatureAndHashPoint() public view {
        string memory data = vm.readFile("test/vectors/blst-crosscheck.json");
        uint256 originalCount = vm.parseJsonUint(data, ".originalCount");
        assertEq(originalCount, rounds.length);
        assertGe(originalCount, 100);
        assertEq(vm.parseJsonUint(data, ".count"), originalCount + 6);
        bytes memory dst = bytes(vm.parseJsonString(json, ".network.dst"));
        for (uint256 i; i < originalCount; ++i) {
            RoundVec memory v = _blstRound(data, i);
            assertEq(v.round, rounds[i].round);
            assertEq(v.affine, rounds[i].affine, "blst/noble affine disagreement");
            assertEq(v.compressed, rounds[i].compressed, "blst/noble compression disagreement");
            assertEq(v.value, rounds[i].value, "blst/noble randomness disagreement");
            assertEq(verifier.verify(v.round, v.affine), v.value, "Solidity/blst verification disagreement");
            string memory path = string.concat(".rounds[", vm.toString(i), "]");
            assertEq(
                harness.hashToG1(vm.parseJsonBytes(data, string.concat(path, ".message")), dst),
                _toEip(vm.parseJsonBytes(data, string.concat(path, ".hashToCurveAffine"))),
                "Solidity/blst hash-to-curve disagreement"
            );
        }
    }

    function test_BlstRfcAndThresholdFixtures() public view {
        string memory data = vm.readFile("test/vectors/blst-crosscheck.json");
        for (uint256 i; i < 5; ++i) {
            string memory path = string.concat(".rfc9380[", vm.toString(i), "]");
            assertEq(
                harness.hashToG1(
                    vm.parseJsonBytes(data, string.concat(path, ".message")),
                    bytes(vm.parseJsonString(data, string.concat(path, ".dst")))
                ),
                _toEip(vm.parseJsonBytes(data, string.concat(path, ".pointAffine")))
            );
        }
        assertEq(vm.parseJsonUint(data, ".threshold.subsetCount"), 4);
        assertEq(
            vm.parseJsonBytes(data, ".threshold.groupSignatureAffine"),
            vm.parseJsonBytes(json, ".threshold.groupSignatureAffine")
        );
        assertEq(
            vm.parseJsonBytes(data, ".threshold.groupSignatureCompressed"),
            vm.parseJsonBytes(json, ".threshold.groupSignatureCompressed")
        );
        uint64 round = uint64(vm.parseJsonUint(data, ".threshold.round"));
        assertEq(
            verifier.verify(round, vm.parseJsonBytes(data, ".threshold.groupSignatureAffine")),
            vm.parseJsonBytes32(json, ".threshold.value")
        );
    }

    function test_BitmapWordsAtBitsZeroOneAnd255UseIndependentValidSignatures() public {
        string memory data = vm.readFile("test/vectors/blst-crosscheck.json");
        uint256 offset = vm.parseJsonUint(data, ".originalCount");
        uint8[6] memory order = [uint8(1), 3, 0, 4, 2, 5]; // 256, 511, 255, 512, 257, 513
        bool[6] memory published;
        for (uint256 i; i < order.length; ++i) {
            uint256 index = order[i];
            RoundVec memory v = _blstRound(data, offset + index);
            assertEq(verifier.verify(v.round, v.affine), v.value);
            assertEq(harness.compress(v.affine), v.compressed);
            assertTrue(verifier.submit(v.round, v.affine));
            published[index] = true;
            for (uint256 j; j < published.length; ++j) {
                RoundVec memory expected = _blstRound(data, offset + j);
                (bool available, bytes32 value) = verifier.get(expected.round);
                assertEq(available, published[j], "word boundary corrupted another availability bit");
                assertEq(value, published[j] ? expected.value : bytes32(0));
            }
            assertFalse(verifier.submit(v.round, v.affine), "word boundary duplicate counted twice");
        }
        assertFalse(_isAvailable(254));
        assertFalse(_isAvailable(258));
        assertFalse(_isAvailable(510));
        assertFalse(_isAvailable(514));
        bytes32 word0 = keccak256(abi.encode(uint256(0), uint256(1)));
        bytes32 word1 = keccak256(abi.encode(uint256(1), uint256(1)));
        bytes32 word2 = keccak256(abi.encode(uint256(2), uint256(1)));
        assertEq(uint256(vm.load(address(verifier), word0)), uint256(1) << 255);
        assertEq(uint256(vm.load(address(verifier), word1)), (uint256(1) << 255) | 3);
        assertEq(uint256(vm.load(address(verifier), word2)), 3);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "../forge-std/src/Test.sol";
import {Vm} from "../forge-std/src/Vm.sol";
import {BeaconVerifierFixture, MockEpochAuthority} from "./BeaconVerifier.t.sol";
import {BeaconVerifier} from "../../src/BeaconVerifier.sol";
import {IBeacon} from "../../src/interfaces/IBeacon.sol";

/// @dev All actors and fixtures are NON-PRODUCTION. Only the test authority is mutable.
///      The model keeps its own publication history and uses release times/epochs from
///      independent JSON fixtures, rather than reading the verifier's availability as its oracle.
contract BeaconRoundHandler is Test {
    BeaconVerifier public immutable beacon;
    MockEpochAuthority public immutable authority;
    bytes32 public immutable network;
    BeaconVerifierFixture.RoundVec[] internal samples;
    uint64[] internal releaseTimes;
    address[3] internal actors;

    mapping(uint64 => bool) public published;
    mapping(uint64 => bool) public epochAuthorized;
    uint256 public firstWrites;
    uint256 public publicationEvents;
    uint256 public duplicateCalls;
    uint256 public rejectedCalls;
    uint256 public verifyCalls;

    constructor(
        BeaconVerifier beacon_,
        MockEpochAuthority authority_,
        BeaconVerifierFixture.RoundVec[] memory samples_,
        uint64[] memory releaseTimes_
    ) {
        beacon = beacon_;
        authority = authority_;
        network = beacon_.networkId();
        require(samples_.length == releaseTimes_.length, "fixture lengths");
        for (uint256 i; i < samples_.length; ++i) {
            samples.push(samples_[i]);
            releaseTimes.push(releaseTimes_[i]);
        }
        actors = [
            makeAddr("NON_PRODUCTION_RELAY_A"), makeAddr("NON_PRODUCTION_RELAY_B"), makeAddr("NON_PRODUCTION_RELAY_C")
        ];
        epochAuthorized[0] = true;
        epochAuthorized[1] = true; // fixture setUp activates epoch 1
    }

    function advanceToReleaseBoundary(uint256 sampleSeed, uint8 phaseSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        uint256 target = releaseTimes[i];
        uint256 phase = phaseSeed % 3;
        if (phase == 0) --target;
        if (phase == 2) ++target;
        // Chain time only moves forward; deterministic tests pin boundaries that a random
        // sequence may pass before choosing the corresponding round.
        if (target > block.timestamp) vm.warp(target);
    }

    function authorizeEpoch(uint256 sampleSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        uint64 epoch = samples[i].epoch;
        authority.set(network, epoch, true);
        epochAuthorized[epoch] = true;
    }

    function authorizeWrongNetwork(uint256 sampleSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        authority.set(keccak256(abi.encode(network, "OTHER_NON_PRODUCTION_NETWORK")), samples[i].epoch, true);
    }

    function publish(uint256 sampleSeed, uint256 actorSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        BeaconVerifierFixture.RoundVec memory sample = samples[i];
        bool wasPublished = published[sample.round];
        bool released = block.timestamp >= releaseTimes[i];
        bool allowed = epochAuthorized[sample.epoch];
        vm.recordLogs();
        vm.prank(actors[actorSeed % actors.length]);
        (bool ok, bytes memory result) =
            address(beacon).call(abi.encodeCall(IBeacon.submit, (sample.round, sample.affine)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        if (!released) {
            assertFalse(ok, "early publication succeeded");
            assertEq(
                result, abi.encodeWithSelector(BeaconVerifier.RoundNotReleased.selector, sample.round, releaseTimes[i])
            );
            assertEq(logs.length, 0);
            ++rejectedCalls;
        } else if (!wasPublished && !allowed) {
            assertFalse(ok, "wrong network or unauthorized epoch published");
            assertEq(result, abi.encodeWithSelector(BeaconVerifier.EpochNotAuthorized.selector, sample.epoch));
            assertEq(logs.length, 0);
            ++rejectedCalls;
        } else {
            assertTrue(ok, "eligible permissionless publication failed");
            assertEq(abi.decode(result, (bool)), !wasPublished, "firstWrite disagrees with independent history");
            if (wasPublished) {
                assertEq(logs.length, 0, "duplicate emitted an event");
                ++duplicateCalls;
            } else {
                assertEq(logs.length, 1, "first write must emit exactly one event");
                assertEq(logs[0].emitter, address(beacon));
                assertEq(logs[0].topics.length, 4);
                assertEq(logs[0].topics[0], keccak256("RoundVerified(bytes32,uint64,uint64,bytes32,bytes)"));
                assertEq(logs[0].topics[1], network);
                assertEq(logs[0].topics[2], bytes32(uint256(sample.epoch)));
                assertEq(logs[0].topics[3], bytes32(uint256(sample.round)));
                (bytes32 value, bytes memory compressed) = abi.decode(logs[0].data, (bytes32, bytes));
                assertEq(value, sample.value, "event value disagrees with independent BLS fixture");
                assertEq(compressed, sample.compressed, "event signature is not the canonical hash preimage");
                published[sample.round] = true;
                ++firstWrites;
                ++publicationEvents;
            }
        }
    }

    function verifyWithoutPublishing(uint256 sampleSeed, uint256 actorSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        BeaconVerifierFixture.RoundVec memory sample = samples[i];
        vm.recordLogs();
        vm.prank(actors[actorSeed % actors.length]);
        assertEq(beacon.verify(sample.round, sample.affine), sample.value);
        assertEq(vm.getRecordedLogs().length, 0);
        ++verifyCalls;
    }

    function rejectMalformedOrWrongSignature(uint256 sampleSeed, uint8 mutationSeed) public {
        uint256 i = bound(sampleSeed, 0, samples.length - 1);
        BeaconVerifierFixture.RoundVec memory sample = samples[i];
        bytes memory invalid = sample.affine;
        uint256 mutation = mutationSeed % 4;
        if (mutation == 0) invalid = bytes.concat(invalid, hex"00");
        else if (mutation == 1) invalid = new bytes(96); // infinity
        else if (mutation == 2) invalid[0] = bytes1(uint8(invalid[0]) | 0x80); // compressed flag in affine x
        else invalid[47] = bytes1(uint8(invalid[47]) ^ 1); // change x, hence also the compressed preimage
        // Same-x/same-sign off-curve duplicate inputs have a separate confirmed finding.
        // The failing proof is in .imd-findings.json; acceptance is never asserted here.
        vm.recordLogs();
        (bool ok,) = address(beacon).call(abi.encodeCall(IBeacon.submit, (sample.round, invalid)));
        assertFalse(ok, "invalid input published or matched an existing round");
        assertEq(vm.getRecordedLogs().length, 0);
        ++rejectedCalls;
    }

    function assertModel() external view {
        uint256 count;
        for (uint256 i; i < samples.length; ++i) {
            BeaconVerifierFixture.RoundVec storage sample = samples[i];
            (bool available, bytes32 value) = beacon.get(sample.round);
            assertEq(available, published[sample.round], "availability differs from successful first-write history");
            assertEq(value, published[sample.round] ? sample.value : bytes32(0), "stored randomness changed or leaked");
            if (published[sample.round]) ++count;
        }
        assertEq(count, firstWrites, "rounds were counted more than once");
        assertEq(publicationEvents, firstWrites, "fee-eligible events exceed first writes");
        uint64[8] memory untouched = [uint64(0), 254, 258, 510, 514, 4294967295, 4294967297, type(uint64).max];
        for (uint256 i; i < untouched.length; ++i) {
            (bool available, bytes32 value) = beacon.get(untouched[i]);
            assertFalse(available, "bitmap aliased an unrelated round");
            assertEq(value, bytes32(0));
        }
    }
}

/// @notice Stateful sequences of real BLS verification, competing relayers, epoch activation,
///         invalid submissions, duplicate submissions and advancing release boundaries.
/// forge-config: default.invariant.runs = 128
/// forge-config: default.invariant.depth = 64
/// forge-config: default.invariant.fail-on-revert = true
contract BeaconVerifierInvariantTest is BeaconVerifierFixture {
    BeaconRoundHandler internal handler;
    bytes32 internal descriptorHash;

    function setUp() public override {
        super.setUp();
        // Include nearby low rounds, epoch boundaries, an availability bit at index zero in a
        // distant word, and both last uint64-safe rounds. All signatures are independent vectors.
        uint64[20] memory chosen = [
            uint64(1),
            2,
            3,
            17,
            99,
            100,
            120,
            2880,
            2881,
            5760,
            5761,
            4294967296,
            maxRound - 1,
            maxRound,
            255,
            256,
            257,
            511,
            512,
            513
        ];
        RoundVec[] memory selected = new RoundVec[](chosen.length);
        uint64[] memory times = new uint64[](chosen.length);
        string memory blst = vm.readFile("test/vectors/blst-crosscheck.json");
        uint256 originalCount = vm.parseJsonUint(blst, ".originalCount");
        for (uint256 i; i < chosen.length; ++i) {
            if (i < 14) {
                selected[i] = _vec(chosen[i]);
                for (uint256 j; j < rounds.length; ++j) {
                    if (rounds[j].round == chosen[i]) {
                        times[i] =
                            uint64(vm.parseJsonUint(json, string.concat(".rounds[", vm.toString(j), "].roundTime")));
                        break;
                    }
                }
            } else {
                string memory path = string.concat(".rounds[", vm.toString(originalCount + i - 14), "]");
                selected[i] = RoundVec({
                    round: uint64(vm.parseJsonUint(blst, string.concat(path, ".round"))),
                    epoch: uint64(vm.parseJsonUint(blst, string.concat(path, ".epoch"))),
                    affine: vm.parseJsonBytes(blst, string.concat(path, ".signatureAffine")),
                    compressed: vm.parseJsonBytes(blst, string.concat(path, ".signatureCompressed")),
                    value: vm.parseJsonBytes32(blst, string.concat(path, ".value"))
                });
                times[i] = uint64(vm.parseJsonUint(blst, string.concat(path, ".roundTime")));
            }
            assertEq(selected[i].round, chosen[i], "wrong independent fixture selected");
            assertGt(times[i], 0, "missing independent release time");
        }
        handler = new BeaconRoundHandler(verifier, authority, selected, times);
        descriptorHash = _descriptorHash();
        vm.warp(genesisTime - 1);
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = handler.advanceToReleaseBoundary.selector;
        selectors[1] = handler.authorizeEpoch.selector;
        selectors[2] = handler.authorizeWrongNetwork.selector;
        selectors[3] = handler.publish.selector;
        selectors[4] = handler.verifyWithoutPublishing.selector;
        selectors[5] = handler.rejectMalformedOrWrongSignature.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function _descriptorHash() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                verifier.networkId(),
                verifier.genesisTime(),
                verifier.maxRound(),
                verifier.period(),
                verifier.epochLength(),
                verifier.groupKey(),
                verifier.epochAuthority()
            )
        );
    }

    function invariant_PublicationHistoryAndDescriptorRemainConsistent() public view {
        handler.assertModel();
        assertEq(_descriptorHash(), descriptorHash, "descriptor or key changed after genesis");
    }

    function test_HandlerExercisesFirstWritesDuplicatesEarlyAndEpochFailures() public {
        handler.publish(0, 0); // before genesis: rejected
        handler.verifyWithoutPublishing(0, 1); // early pure check is valid and does not publish
        handler.advanceToReleaseBoundary(0, 1); // exactly genesis
        handler.publish(0, 0);
        handler.publish(0, 2); // competing relayer cannot earn another first-write indication
        handler.rejectMalformedOrWrongSignature(0, 0);
        handler.rejectMalformedOrWrongSignature(0, 1);
        handler.rejectMalformedOrWrongSignature(0, 2);
        handler.rejectMalformedOrWrongSignature(0, 3);
        handler.advanceToReleaseBoundary(10, 1); // round 5761, epoch 2
        handler.authorizeWrongNetwork(10);
        handler.publish(10, 1); // correct signature but unauthorized destination epoch
        handler.authorizeEpoch(10);
        handler.publish(10, 1);
        handler.verifyWithoutPublishing(10, 2);
        handler.assertModel();
        assertEq(handler.firstWrites(), 2);
        assertEq(handler.publicationEvents(), 2);
        assertEq(handler.duplicateCalls(), 1);
        assertEq(handler.rejectedCalls(), 6);
        assertEq(handler.verifyCalls(), 2);
    }

    function test_HandlerExercisesAvailabilityWordBoundaries() public {
        handler.advanceToReleaseBoundary(19, 1); // release round 513
        handler.publish(15, 0); // 256, word 1 bit 0
        handler.publish(14, 1); // 255, word 0 bit 255
        handler.publish(18, 2); // 512, word 2 bit 0
        handler.publish(17, 0); // 511, word 1 bit 255
        handler.publish(16, 1); // 257, word 1 bit 1
        handler.publish(19, 2); // 513, word 2 bit 1
        handler.publish(14, 2); // duplicate after other words were populated
        handler.assertModel();
        assertEq(handler.firstWrites(), 6);
        assertEq(handler.duplicateCalls(), 1);
    }
}

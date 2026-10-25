// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS12381} from "./BLS12381.sol";

/// @title HashToCurveG1: RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ on top of EIP-2537
/// @notice hash_to_curve(msg) = clear_cofactor(map_to_curve(u0) + map_to_curve(u1)) where
///         (u0, u1) = hash_to_field(msg, 2) with expand_message_xmd(SHA-256) and L = 64.
///         expand_message_xmd and the modular reductions run on-chain; map_to_curve with the
///         11-isogeny and cofactor clearing is the MAP_FP_TO_G1 precompile, and the two mapped
///         points are added with G1ADD. Cofactor clearing is a group homomorphism, so clearing
///         each mapped point and adding equals adding and then clearing (EIP-2537 mapping note).
///         H(M) = hash(M)·G1 is never used (SPEC §4.3).
library HashToCurveG1 {
    uint256 internal constant SHA256_BLOCK_SIZE = 64;
    uint256 internal constant SHA256_OUTPUT_SIZE = 32;
    uint256 internal constant FIELD_ELEMENT_BYTES = 64; // L = ceil((381 + 128) / 8)

    error InvalidExpandLength();
    error DstTooLong();

    /// @notice RFC 9380 §5.3.1 expand_message_xmd with SHA-256.
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 lenInBytes)
        internal
        view
        returns (bytes memory uniform)
    {
        uint256 ell = (lenInBytes + SHA256_OUTPUT_SIZE - 1) / SHA256_OUTPUT_SIZE;
        if (ell > 255 || lenInBytes == 0 || lenInBytes > 65535) revert InvalidExpandLength();
        if (dst.length > 255) revert DstTooLong();

        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));
        bytes32 b0 = BLS12381.sha256Strict(
            bytes.concat(new bytes(SHA256_BLOCK_SIZE), message, bytes2(uint16(lenInBytes)), bytes1(0), dstPrime)
        );
        uniform = new bytes(ell * SHA256_OUTPUT_SIZE);
        bytes32 prev = BLS12381.sha256Strict(bytes.concat(b0, bytes1(uint8(1)), dstPrime));
        assembly ("memory-safe") {
            mstore(add(uniform, 32), prev)
        }
        for (uint256 i = 2; i <= ell; i++) {
            prev = BLS12381.sha256Strict(bytes.concat(b0 ^ prev, bytes1(uint8(i)), dstPrime));
            assembly ("memory-safe") {
                mstore(add(add(uniform, 32), mul(sub(i, 1), 32)), prev)
            }
        }
        assembly ("memory-safe") {
            mstore(uniform, lenInBytes)
        }
    }

    /// @notice hash_to_field(msg, 2) for Fp: returns two 64-byte padded canonical field elements.
    function hashToFieldFp2(bytes memory message, bytes memory dst)
        internal
        view
        returns (bytes memory u0, bytes memory u1)
    {
        bytes memory uniform = expandMessageXmd(message, dst, 2 * FIELD_ELEMENT_BYTES);
        u0 = BLS12381.reduceToFp(uniform, 0);
        u1 = BLS12381.reduceToFp(uniform, FIELD_ELEMENT_BYTES);
    }

    /// @notice hash_to_curve for the RO suite; returns the 128-byte EIP-form G1 point.
    function hashToG1(bytes memory message, bytes memory dst) internal view returns (bytes memory point) {
        (bytes memory u0, bytes memory u1) = hashToFieldFp2(message, dst);
        bytes memory q0 = BLS12381.mapFpToG1(u0);
        bytes memory q1 = BLS12381.mapFpToG1(u1);
        point = BLS12381.addG1(q0, q1);
    }
}

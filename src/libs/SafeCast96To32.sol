// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SafeCast96To32
/// @dev Wrappers over Solidity's uintXX casting operators with added overflow
/// checks specifically for uint96 <-> uint32 conversions.
library SafeCast96To32 {
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /// @dev Returns the downcasted uint32 from uint96, reverting on
    /// overflow (when the input is greater than largest uint32).
    ///
    /// Requirements:
    /// - input must fit into 32 bits
    function toUint32(uint96 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, uint256(value));
        }
        return uint32(value);
    }

    /// @dev Converts uint32 to uint96. This is always safe as it's an upcast.
    /// Included for completeness and clarity in the codebase.
    function toUint96(uint32 value) internal pure returns (uint96) {
        return uint96(value);
    }

    /// @dev Converts an array of uint32 to an array of uint96.
    /// This is always safe as it's an upcast.
    /// @param values Array of uint32 values to convert
    /// @return result Array of converted uint96 values
    function toUint96Array(uint32[] memory values)
        internal
        pure
        returns (uint96[] memory result)
    {
        result = new uint96[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            result[i] = toUint96(values[i]);
        }
        return result;
    }

    /// @dev Converts an array of uint96 to an array of uint32.
    /// Reverts if any value in the array doesn't fit in uint32.
    /// @param values Array of uint96 values to convert
    /// @return result Array of converted uint32 values
    function toUint32Array(uint96[] memory values)
        internal
        pure
        returns (uint32[] memory result)
    {
        result = new uint32[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            result[i] = toUint32(values[i]);
        }
        return result;
    }
}

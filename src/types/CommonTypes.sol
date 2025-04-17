// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { ISlasher } from "@urc/ISlasher.sol";

enum PreconfRequestStatus {
    NonInitiated, // default value
    Exhausted,
    Executed,
    Collected
}

/// @title DelegationStore
/// @notice Common storage struct for delegations used across multiple contracts
struct DelegationStore {
    mapping(bytes32 => ISlasher.SignedDelegation) delegations;
    EnumerableMapLib.Uint256ToBytes32Map delegationMap;
}

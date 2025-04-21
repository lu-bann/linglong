// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { EnumerableMapLib } from "@solady/utils/EnumerableMapLib.sol";
import { ISlasher } from "@urc/ISlasher.sol";

/// @title PreconfRequestStatus
/// @notice Enum representing the status of a preconf request
enum PreconfRequestStatus {
    NonInitiated, // default value
    Exhausted,
    Executed,
    Collected
}

/// @title DelegationStore
/// @notice Common storage struct for delegations used across multiple contracts
struct DelegationStore {
    // validator pubKey Hash -> SignedDelegation
    mapping(bytes32 => ISlasher.SignedDelegation) delegations;
    // index -> validator pubKey Hash
    EnumerableMapLib.Uint256ToBytes32Map delegationMap;
}

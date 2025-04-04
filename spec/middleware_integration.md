# Middleware Integration Design

## Overview

This document outlines the design and implementation plan for integrating `SymbioticNetworkMiddleware` with the existing architecture alongside `EigenLayerMiddleware`. The goal is to create a unified infrastructure that allows both middleware systems to work together with shared components like `TaiyiRegistryCoordinator` and `LinglongSlasher`.

## Architectural Design

### 1. Unified Registry Coordinator

The `TaiyiRegistryCoordinator` will be enhanced to support both middleware implementations by:

- Adding a new enum type to identify the middleware protocol (EigenLayer or Symbiotic)
- Implementing protocol-specific routing for operations
- Supporting both operator set (EigenLayer) and subnetwork (Symbiotic) paradigms

### 2. Operator Registration Flow

#### For EigenLayer:
- Operators register through `TaiyiRegistryCoordinator` specifying operator sets
- Operators allocate stake via EigenLayer's allocation system
- Registration information is stored in operator sets

#### For Symbiotic:
- Operators register through `TaiyiRegistryCoordinator` specifying subnetworks
- Registration process maps subnetwork IDs to appropriate operator sets internally
- `SymbioticNetworkMiddleware` handles the subnetwork-specific logic

### 3. Core Components Integration

#### Registry Coordinator Enhancements
- Add protocol type tracking for each registration
- Implement middleware-specific function routing
- Group protocol-specific functions under clear sections

#### Slashing Integration
- Enhance `LinglongSlasher` to handle both protocols
- For EigenLayer: Continue using `AllocationManager.slashOperator()`
- For Symbiotic: Implement slashing via Symbiotic's vault mechanism

#### Rewards Distribution
- Each middleware handles its own rewards distribution
- `EigenLayerRewardsHandler` continues handling EigenLayer rewards
- Add a new `SymbioticRewardsHandler` for Symbiotic rewards

### 4. Protocol-Specific Implementations

#### Symbiotic Implementation Needs
- Implement validator registration via `Registry` similar to EigenLayer
- Adapt the subnetwork model to work with `TaiyiRegistryCoordinator`
- Implement Symbiotic-specific slashing mechanisms
- Add rewards distribution for Symbiotic operators

#### EigenLayer Compatibility
- Maintain all existing EigenLayer functionality
- Ensure EigenLayer operations are not affected by Symbiotic integration

## Detailed Component Design

### TaiyiRegistryCoordinator Changes

```solidity
enum RestakingProtocol {
    NONE,
    EIGENLAYER,
    SYMBIOTIC
}

// Map middleware addresses to their protocol type
mapping(address => RestakingProtocol) public restakingProtocol;

// EnumerableSet to track middleware addresses
EnumerableSet.AddressSet internal restakingMiddleware;

// Protocol-specific function routing
function registerOperatorWithServiceType(
    address operator,
    uint32 serviceTypeId,
    bytes calldata data
) external {
    // Route based on msg.sender's protocol type
    if (restakingProtocol[msg.sender] == RestakingProtocol.SYMBIOTIC) {
        // Handle Symbiotic-specific logic
        // Map subnetwork ID to operator sets
    } else {
        // Handle EigenLayer logic (existing implementation)
    }
}
```

### SymbioticNetworkMiddleware Changes

```solidity
// Add Registry integration for validator registration
function registerValidators(
    IRegistry.Registration[] calldata registrations,
    BLS.G2Point[] calldata delegationSignatures,
    BLS.G1Point calldata delegateePubKey,
    address delegateeAddress,
    bytes[] calldata data
) external payable returns (bytes32 registrationRoot) {
    // Implement similar to EigenLayerMiddleware.registerValidators
}

// Add Slashing integration
function handleSlashing(
    address operator,
    uint96 subnetwork,
    uint256 slashAmount,
    string memory reason
) external {
    // Implement Symbiotic-specific slashing
}

// Add Rewards distribution
function distributeRewards(
    address token,
    uint256 amount,
    uint96 subnetwork
) external {
    // Implement Symbiotic rewards distribution
}
```

### LinglongSlasher Enhancements

```solidity
function slashFromOptIn(
    ISlasher.Commitment calldata commitment,
    bytes calldata evidence,
    address challenger
) external override returns (uint256 slashAmountGwei) {
    // Extract middleware address from commitment
    address middleware = _extractMiddlewareFromCommitment(commitment);
    
    // Determine protocol and handle accordingly
    if (restakingProtocol[middleware] == RestakingProtocol.SYMBIOTIC) {
        // Call Symbiotic-specific slashing mechanism
        return _slashSymbioticOperator(...);
    } else {
        // Existing EigenLayer slashing implementation
        return _slashEigenLayerOperator(...);
    }
}
```

## Implementation Plan

### Phase 1: TaiyiRegistryCoordinator Enhancements
1. Add protocol type tracking
2. Implement middleware address management
3. Modify operator registration to support both protocols
4. Group protocol-specific functions

### Phase 2: SymbioticNetworkMiddleware Integration
1. Add Registry integration for validator registration
2. Implement subnetwork to operator set mapping
3. Add rewards distribution for Symbiotic
4. Implement Symbiotic-specific slashing mechanisms

### Phase 3: LinglongSlasher Adaptation
1. Enhance slashing to support both protocols
2. Implement protocol detection and routing
3. Add Symbiotic-specific slashing implementations

### Phase 4: Testing and Validation
1. Unit tests for each component
2. Integration tests for cross-protocol functionality
3. End-to-end testing of operator flows

## Backward Compatibility

The design ensures that all existing EigenLayer functionality continues to work without interruption. New protocol-specific paths are added alongside existing ones rather than replacing them.

## Security Considerations

1. Proper access control between protocols
2. Clear separation of assets and slashing mechanisms
3. Careful handling of cross-protocol interactions
4. Thorough audit of all new code paths

## Conclusion

This integration design allows for a unified infrastructure that supports both EigenLayer and Symbiotic protocols while maintaining the unique characteristics of each system. The implementation plan provides a structured approach to adding the necessary functionality without disrupting existing operations. 
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import { BN254 } from "../libs/BN254.sol";

import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title ITaiyiRegistryCoordinator
/// @notice Interface for the TaiyiRegistryCoordinator contract
interface ITaiyiRegistryCoordinator {
    /// @notice Represents the registration state of an operator.
    /// @dev Used to track an operator's lifecycle in the system.
    /// @custom:enum NEVER_REGISTERED The operator has never registered with the system.
    /// @custom:enum REGISTERED The operator is currently registered and active.
    /// @custom:enum DEREGISTERED The operator was previously registered but has since deregistered.
    enum OperatorStatus {
        NEVER_REGISTERED,
        REGISTERED,
        DEREGISTERED
    }

    /// @notice Core data structure for tracking operator information.
    /// @dev Links an operator's unique identifier with their current registration status.
    /// @param operatorId Unique identifier for the operator, typically derived from their BLS public key.
    /// @param status Current registration state of the operator in the system.
    struct OperatorInfo {
        bytes32 operatorId;
        OperatorStatus status;
    }

    /// @notice Struct to hold both types of operator set IDs
    struct AllocatedOperatorSets {
        uint32[] eigenLayerSets; // EigenLayer operator set IDs
        uint96[] symbioticSets; // Symbiotic operator set IDs
    }

    /// @notice Defines the type of restaking service used by the protocol
    /// @dev Used to specify which restaking mechanism an operator is using
    /// @custom:enum NONE No restaking protocol assigned yet
    /// @custom:enum EIGENLAYER The operator is using EigenLayer for restaking
    /// @custom:enum SYMBIOTIC The operator is using Symbiotic for restaking
    enum RestakingProtocol {
        NONE,
        EIGENLAYER,
        SYMBIOTIC
    }

    /// @notice Defines the type of restaking service used by the protocol
    /// @dev Used to specify which restaking mechanism an operator is using
    /// @custom:enum EIGENLAYER_VALIDATOR The operator is using EigenLayer for restaking
    /// @custom:enum EIGENLAYER_UNDERWRITER The operator is using EigenLayer for restaking
    /// @custom:enum SYMBIOTIC_VALIDATOR The operator is using Symbiotic for restaking
    /// @custom:enum SYMBIOTIC_UNDERWRITER The operator is using Symbiotic for restaking
    enum RestakingServiceTypes {
        EIGENLAYER_VALIDATOR,
        EIGENLAYER_UNDERWRITER,
        SYMBIOTIC_VALIDATOR,
        SYMBIOTIC_UNDERWRITER
    }

    /// @notice Error thrown when an operator is not registered
    error NotRegistered();

    /// @notice Error thrown when an operator is not in a specific operator set
    error OperatorNotInSet(address operator, uint96 operatorSetId);

    /// @notice Error thrown when an operator is not registered during ejection
    error OperatorNotRegistered();

    /// @notice Error thrown when an invalid operator set ID is provided
    error InvalidOperatorSetId();

    /// @notice Error thrown when a caller is not the ejector
    error OnlyEjector();

    /// @notice Error thrown when a caller is not the allocation manager
    error OnlyAllocationManager();

    /// @notice Error thrown when a caller is not the restaking middleware
    error OnlyRestakingMiddleware();

    /// @notice Error thrown when a caller is not the EigenLayer middleware
    error OnlyEigenlayerMiddleware();

    /// @notice Error thrown when a caller is not the symbiotic middleware
    error OnlySymbioticMiddleware();

    /// @notice Error thrown when an operator is not registered
    error OperatorNotDeregistered();

    /// @notice Error thrown when an operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error thrown when an operator set is not found
    error OperatorSetNotFound(uint32 operatorSetId);

    /// @notice Emitted when a new middleware is added or updated
    event RestakingMiddlewareUpdated(
        RestakingProtocol restakingProtocol, address newMiddleware
    );

    /// @notice Emitted when an allocation query is performed
    /// @param operator The operator queried
    /// @param operatorSetId The operator set ID
    /// @param strategy The strategy address
    /// @param amount The allocation amount
    /// @param reason A description of the allocation status
    event OperatorAllocationQuery(
        address indexed operator,
        uint96 indexed operatorSetId,
        address indexed strategy,
        uint256 amount,
        string reason
    );

    /// @notice Emitted when an operator's socket is updated
    /// @param operatorId The operator's unique identifier
    /// @param socket The new socket value
    event OperatorSocketUpdate(bytes32 indexed operatorId, string socket);

    /// @notice Emitted when the ejector address is updated
    /// @param previousEjector The previous ejector address
    /// @param newEjector The new ejector address
    event EjectorUpdated(address indexed previousEjector, address indexed newEjector);

    /// @notice Emitted when the restaking middleware address is updated
    /// @param previousMiddleware The previous middleware address
    /// @param newMiddleware The new middleware address
    event RestakingMiddlewareUpdated(
        address indexed previousMiddleware, address indexed newMiddleware
    );

    /// @notice Updates the socket address for the calling operator
    /// @param socket The new socket address to set
    function updateSocket(string memory socket) external;

    /// @notice Register an operator with the specified operator set IDs
    /// @param operator The address of the operator to register
    /// @param operatorSetIds The operator set IDs to register the operator with
    /// @param data Additional data required for registration
    function registerOperator(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        external;

    /// @notice Deregister an operator from the specified operator set IDs
    /// @param operator The address of the operator to deregister
    /// @param operatorSetIds The operator set IDs to deregister the operator from
    function deregisterOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        external;

    /// @notice Create a new operator set with the specified strategies
    /// @param subnetworkId The ID of the subnetwork
    /// @param minStake The minimum stake required for the subnetwork
    function createSubnetwork(uint96 subnetworkId, uint256 minStake) external;

    /// @notice Create a new operator set with the specified strategies
    /// @param operatorSetId The ID of the operator set
    /// @param minStake The minimum stake required for the operator set
    function createOperatorSet(uint32 operatorSetId, uint256 minStake) external;

    /// @notice Gets the protocol type for a middleware address
    /// @param middleware The middleware address to query
    /// @return The protocol type associated with the middleware
    function getMiddlewareProtocol(address middleware)
        external
        view
        returns (RestakingProtocol);

    /// @notice Checks if a middleware is a restaking middleware
    /// @param middleware The middleware address to check
    /// @return True if the middleware is a restaking middleware, false otherwise
    function isRestakingMiddleware(address middleware) external view returns (bool);

    /// @notice Get the operators in the specified subnetwork
    /// @param baseSubnetworkId The ID of the subnetwork
    /// @return Array of operator addresses in the subnetwork
    function getSymbioticSubnetworkOperators(uint96 baseSubnetworkId)
        external
        view
        returns (address[] memory);

    /// @notice Get the operators in the specified operator set
    /// @param baseOperatorSetId The ID of the operator set
    /// @return Array of operator addresses in the set
    function getEigenLayerOperatorSetOperators(uint32 baseOperatorSetId)
        external
        view
        returns (address[] memory);

    /// @notice Get all symbiotic operator sets
    /// @return Array of operator set IDs
    function getSymbioticSubnetworks() external view returns (uint96[] memory);

    /// @notice Get all eigenlayer operator sets
    /// @return Array of operator set IDs
    function getEigenLayerOperatorSets() external view returns (uint32[] memory);

    /// @notice Get the operator set with the specified ID
    /// @param operatorSetId The ID of the operator set
    /// @param operator The address of the operator
    /// @return Array of operator addresses in the set
    function getEigenLayerOperatorFromOperatorSet(
        uint32 operatorSetId,
        address operator
    )
        external
        view
        returns (bool);

    /// @notice Get the operator set with the specified ID
    /// @param operatorSetId The ID of the operator set
    /// @param operator The address of the operator
    /// @return Array of operator addresses in the set
    function getSymbioticOperatorFromOperatorSet(
        uint96 operatorSetId,
        address operator
    )
        external
        view
        returns (bool);

    /// @notice Get all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @param protocol The protocol to query
    /// @return allocatedSetsIdes Array of operator set IDs that the operator has allocated magnitude to
    function getOperatorAllocatedOperatorSets(
        address operator,
        RestakingProtocol protocol
    )
        external
        view
        returns (AllocatedOperatorSets memory allocatedSetsIdes);

    /// @notice Get all strategies that an operator has allocated magnitude to in a specific operator set
    /// @param operator The operator whose allocated strategies to fetch
    /// @param baseOperatorSetId The ID of the operator set to query
    /// @return allocatedStrategies Array of strategy addresses that the operator has allocated magnitude to in the operator set
    function getEigenLayerOperatorAllocatedStrategies(
        address operator,
        uint32 baseOperatorSetId
    )
        external
        view
        returns (address[] memory allocatedStrategies);

    /// @notice Get all strategies that an operator has allocated magnitude to in a specific symbiotic subnetwork
    /// @param operator The operator whose allocated strategies to fetch
    /// @param baseSubnetworkId The ID of the subnetwork to query
    /// @return allocatedStrategies Array of strategy addresses that the operator has allocated magnitude to in the subnetwork
    function getSymbioticOperatorAllocatedStrategies(
        address operator,
        uint96 baseSubnetworkId
    )
        external
        view
        returns (address[] memory allocatedStrategies);

    function getEigenLayerOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 baseOperatorSetId,
        IStrategy strategy
    )
        external
        returns (uint256);

    function getSymbioticOperatorAllocatedStrategiesAmount(
        address operator,
        uint96 baseSubnetworkId,
        IStrategy strategy
    )
        external
        returns (uint256);

    /// @notice Get the information for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's information
    function getOperator(address operator) external view returns (OperatorInfo memory);

    /// @notice Get the operator ID for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's unique identifier
    function getOperatorId(address operator) external view returns (bytes32);

    /// @notice Get the operator address for a specific operator ID
    /// @param operatorId The operator's unique identifier
    /// @return The operator's address
    function getOperatorFromId(bytes32 operatorId) external view returns (address);

    /// @notice Get the registration status for a specific operator
    /// @param operator The address of the operator
    /// @return The operator's registration status
    function getOperatorStatus(address operator) external view returns (OperatorStatus);

    /// @notice Get the total count of operator sets
    /// @return The total count of operator sets
    function getOperatorSetCount() external view returns (uint32);

    /// @notice Returns the message hash that an operator must sign to register their BLS public key
    /// @param operator The address of the operator
    /// @return The hash to sign as a BN254.G1Point
    function pubkeyRegistrationMessageHash(address operator)
        external
        view
        returns (BN254.G1Point memory);

    /// @notice Calculates the message hash that an operator must sign to register their BLS public key
    /// @param operator The address of the operator
    /// @return The calculated hash
    function calculatePubkeyRegistrationMessageHash(address operator)
        external
        view
        returns (bytes32);

    /// @notice Checks if an operator is in a specific operator set
    /// @param operatorSetId The operator set ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function isEigenLayerOperatorInSet(
        uint32 operatorSetId,
        address operator
    )
        external
        view
        returns (bool);

    /// @notice Checks if an operator is in a specific symbiotic operator set
    /// @param baseSubnetworkId The ID of the subnetwork
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function isSymbioticOperatorInSubnetwork(
        uint96 baseSubnetworkId,
        address operator
    )
        external
        view
        returns (bool);
}

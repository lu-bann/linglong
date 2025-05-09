// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import { BN254 } from "../libs/BN254.sol";

import { IPubkeyRegistry } from "./IPubkeyRegistry.sol";
import { IAllocationManagerTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { ISignatureUtilsMixinTypes } from
    "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtilsMixin.sol";
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

    /// @notice Error thrown when a caller is not the middleware
    error OnlyMiddleware();

    /// @notice Error thrown when an operator is not registered
    error OperatorNotDeregistered();

    /// @notice Error thrown when an operator is already registered
    error OperatorAlreadyRegistered();

    /// @notice Error thrown when an operator set is not found
    error OperatorSetNotFound(uint32 operatorSetId);

    /// @notice Error thrown when an invalid subset ID is provided
    error OnlySymbioticSubsetId();

    /// @notice Error thrown when an invalid subset ID is provided
    error OnlyEigenlayerSubsetId();

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

    /// @notice Updates the socket address for the calling operator
    /// @param socket The new socket address to set
    function updateSocket(string memory socket) external;

    /// @notice Register an operator with the specified operator set IDs
    /// @param operator The address of the operator to register
    /// @param avs The AVS address
    /// @param operatorSetIds The operator set IDs to register the operator with
    /// @param data Additional data required for registration
    function registerOperator(
        address operator,
        address avs,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        external;

    /// @notice Deregister an operator from the specified operator set IDs
    /// @param operator The address of the operator to deregister
    /// @param avs The AVS address
    /// @param operatorSetIds The operator set IDs to deregister the operator from
    function deregisterOperator(
        address operator,
        address avs,
        uint32[] memory operatorSetIds
    )
        external;

    /// @notice Create a new operator set with the specified strategies
    /// @param linglongSubsetId The ID of the operator set
    /// @param minStake The minimum stake required for the operator set
    function createLinglongSubset(uint32 linglongSubsetId, uint256 minStake) external;

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

    /// @notice Get the operators in the specified operator set
    /// @param linglongSubsetId The ID of the operator set
    /// @return Array of operator addresses in the set
    function getLinglongSubsetOperators(uint32 linglongSubsetId)
        external
        view
        returns (address[] memory);

    /// @notice Get the size of a specific operator set
    /// @param linglongSubsetId The ID of the operator set
    /// @return The size of the operator set
    function getLinglongSubsetSize(uint32 linglongSubsetId)
        external
        view
        returns (uint256);

    /// @notice Get all operator sets
    /// @return Array of operator set IDs
    function getLinglongSubnets() external view returns (uint32[] memory);

    /// @notice Get all middleware addresses for a specific protocol
    /// @param protocol The protocol type to filter by
    /// @return Array of middleware addresses for the specified protocol
    function getRestakingMiddlewareByProtocol(RestakingProtocol protocol)
        external
        view
        returns (address[] memory);

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
    /// @param linglongSubsetId The ID of the operator set to query
    /// @return allocatedStrategies Array of strategy addresses that the operator has allocated magnitude to in the operator set
    function getEigenLayerOperatorAllocatedStrategies(
        address operator,
        uint32 linglongSubsetId
    )
        external
        view
        returns (address[] memory allocatedStrategies);

    /// @notice Get all strategies that an operator has allocated magnitude to in a specific symbiotic subnetwork
    /// @param operator The operator whose allocated strategies to fetch
    /// @param linglongSubsetId The ID of the subnetwork to query
    /// @return allocatedStrategies Array of strategy addresses that the operator has allocated magnitude to in the subnetwork
    function getSymbioticOperatorAllocatedStrategies(
        address operator,
        uint32 linglongSubsetId
    )
        external
        view
        returns (address[] memory allocatedStrategies);

    /// @notice Get the amount of strategy allocation for an operator in an EigenLayer operator set
    /// @param operator The operator to query
    /// @param linglongSubsetId The operator set ID
    /// @param strategy The strategy to query
    /// @return The amount of allocation
    function getEigenLayerOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 linglongSubsetId,
        IStrategy strategy
    )
        external
        returns (uint256);

    /// @notice Get the amount of strategy allocation for an operator in a Symbiotic subnetwork
    /// @param operator The operator to query
    /// @param linglongSubsetId The subnetwork ID
    /// @param strategy The strategy to query
    /// @return The amount of allocation
    function getSymbioticOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 linglongSubsetId,
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

    /// @notice whether the operator set Id is set
    /// @param linglongSubsetId operator Id
    /// @return yes or no
    function isLinglongSubsetExist(uint32 linglongSubsetId)
        external
        view
        returns (bool);

    /// @notice Checks if an operator is in a specific operator set
    /// @param linglongSubsetId The operator set ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function isOperatorInLinglongSubset(
        uint32 linglongSubsetId,
        address operator
    )
        external
        view
        returns (bool);

    /// @notice External function to decode operator data
    /// @param data The data to decode
    /// @return socket The socket string
    /// @return params The PubkeyRegistrationParams
    function decodeOperatorData(bytes calldata data)
        external
        pure
        returns (
            string memory socket,
            IPubkeyRegistry.PubkeyRegistrationParams memory params
        );
}

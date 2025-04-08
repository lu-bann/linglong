// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { AllocationManager } from
    "@eigenlayer-contracts/src/contracts/core/AllocationManager.sol";

import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { IPauserRegistry } from
    "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";

import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

import { BN254 } from "../libs/BN254.sol";
import { RestakingProtocolMap } from "../libs/RestakingProtocolMap.sol";

import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { TaiyiRegistryCoordinatorStorage } from
    "../storage/TaiyiRegistryCoordinatorStorage.sol";
import { Pausable } from "@eigenlayer-contracts/src/contracts/permissions/Pausable.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";

/// @title A `TaiyiRegistryCoordinator` that has two registries:
///      1) a `PubkeyRegistry` that keeps track of operators' public keys
///      2) a `SocketRegistry` that keeps track of operators' sockets (arbitrary strings)
contract TaiyiRegistryCoordinator is
    TaiyiRegistryCoordinatorStorage,
    Initializable,
    Pausable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    IAVSRegistrar
{
    using BN254 for BN254.G1Point;
    using EnumerableSet for EnumerableSet.AddressSet;
    using OperatorSubsetLib for uint32;
    using OperatorSubsetLib for OperatorSubsetLib.OperatorSets;
    using RestakingProtocolMap for RestakingProtocolMap.Map;

    /// @notice Map middleware addresses to their protocol type
    RestakingProtocolMap.Map internal restakingProtocolMap;

    /// @notice Emitted when a new middleware is added or updated
    event RestakingMiddlewareUpdated(
        RestakingProtocol restakingProtocol, address newMiddleware
    );

    // ======== END NEW PROTOCOL TYPE HANDLING =======

    /// @notice Modifier that allows only registered middleware contracts to call a function
    modifier onlyRestakingMiddleware() {
        require(restakingProtocolMap.contains(msg.sender), OnlyRestakingMiddleware());
        _;
    }

    constructor(
        IAllocationManager _allocationManager,
        IPauserRegistry _pauserRegistry,
        string memory /* _version */
    )
        TaiyiRegistryCoordinatorStorage(_allocationManager)
        Pausable(_pauserRegistry)
    {
        _disableInitializers();
    }

    /// @notice External Functions Section
    function initialize(
        address initialOwner,
        uint256 initialPausedStatus,
        address _allocationManager,
        address /* _pauserRegistry */
    )
        external
        initializer
    {
        __EIP712_init("TaiyiRegistryCoordinator", "v0.0.1");
        _transferOwnership(initialOwner);
        _setPausedStatus(initialPausedStatus);

        // Set allocationManager from parameter
        if (_allocationManager != address(0)) {
            allocationManager = IAllocationManager(_allocationManager);
        }
    }

    /// @inheritdoc IAVSRegistrar
    function registerOperator(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        external
        override(IAVSRegistrar, ITaiyiRegistryCoordinator)
        onlyWhenNotPaused(PAUSED_REGISTER_OPERATOR)
    {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            _registerOperatorForSymbiotic(operator, operatorSetIds, data);
        } else if (msg.sender == address(allocationManager)) {
            _registerOperatorForEigenlayer(operator, operatorSetIds, data);
        }
    }

    /// @inheritdoc IAVSRegistrar
    function deregisterOperator(
        address operator,
        uint32[] memory operatorSetIds
    )
        external
        override(IAVSRegistrar, ITaiyiRegistryCoordinator)
        onlyWhenNotPaused(PAUSED_DEREGISTER_OPERATOR)
    {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            _deregisterOperatorForSymbiotic(operator, operatorSetIds);
        } else if (msg.sender == address(allocationManager)) {
            _deregisterOperatorForEigenlayer(operator, operatorSetIds);
        }
    }

    /// @inheritdoc ITaiyiRegistryCoordinator
    function updateSocket(string memory socket) external {
        require(
            _operatorInfo[msg.sender].status == OperatorStatus.REGISTERED, NotRegistered()
        );
        _setOperatorSocket(_operatorInfo[msg.sender].operatorId, socket);
    }

    /**
     * @notice Updates the reference to the socket registry
     * @param _socketRegistry The new socket registry address
     * @dev This is needed for testing purposes when dealing with proxies
     */
    function updateSocketRegistry(address _socketRegistry) external onlyOwner {
        require(_socketRegistry != address(0), "Socket registry cannot be zero address");
        socketRegistry = ISocketRegistry(_socketRegistry);
    }

    /**
     * @notice Updates the reference to the pubkey registry
     * @param _pubkeyRegistry The new pubkey registry address
     * @dev This is needed for testing purposes when dealing with proxies
     */
    function updatePubkeyRegistry(address _pubkeyRegistry) external onlyOwner {
        require(_pubkeyRegistry != address(0), "Pubkey registry cannot be zero address");
        pubkeyRegistry = IPubkeyRegistry(_pubkeyRegistry);
    }

    /// @notice Sets the protocol type for a middleware address
    /// @param _restakingMiddleware The middleware address
    /// @param _restakingProtocol The protocol type (EIGENLAYER or SYMBIOTIC)
    function setRestakingProtocol(
        address _restakingMiddleware,
        RestakingProtocol _restakingProtocol
    )
        external
        onlyOwner
    {
        _setRestakingProtocol(_restakingMiddleware, _restakingProtocol);
    }

    /// @notice Gets all registered middleware addresses
    /// @return Array of middleware addresses
    function getRestakingMiddleware() external view returns (address[] memory) {
        return restakingProtocolMap.addresses();
    }

    /// @notice Gets all middleware addresses for a specific protocol
    /// @param protocol The protocol type to filter by
    /// @return Array of middleware addresses for the specified protocol
    function getRestakingMiddlewareByProtocol(RestakingProtocol protocol)
        external
        view
        returns (address[] memory)
    {
        return restakingProtocolMap.addressesByProtocol(protocol);
    }

    /// @notice Gets the protocol type for a middleware address
    /// @param middleware The middleware address to query
    /// @return The protocol type associated with the middleware
    function getMiddlewareProtocol(address middleware)
        external
        view
        returns (RestakingProtocol)
    {
        return restakingProtocolMap.get(middleware);
    }

    function _setRestakingProtocol(
        address _restakingMiddleware,
        RestakingProtocol _restakingProtocol
    )
        internal
    {
        require(
            _restakingMiddleware != address(0),
            "RestakingMiddleware cannot be zero address"
        );
        restakingProtocolMap.set(_restakingMiddleware, _restakingProtocol);

        emit RestakingMiddlewareUpdated(_restakingProtocol, _restakingMiddleware);
    }

    // Todo: check operator stake
    function _registerOperatorForEigenlayer(
        address operator,
        uint32[] memory operatorSetIds,
        bytes calldata data
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(
            operatorInfo.status != OperatorStatus.REGISTERED, OperatorAlreadyRegistered()
        );

        (string memory socket, IPubkeyRegistry.PubkeyRegistrationParams memory params) =
            abi.decode(data, (string, IPubkeyRegistry.PubkeyRegistrationParams));

        /// If the operator has NEVER registered a pubkey before, use `params` to register
        /// their pubkey in pubkeyRegistry
        ///
        /// If the operator HAS registered a pubkey, `params` is ignored and the pubkey hash
        /// (operatorId) is fetched instead
        bytes32 operatorId = _getOrCreateOperatorId(operator, params);
        _setOperatorSocket(operatorId, socket);

        _operatorInfo[operator].status = OperatorStatus.REGISTERED;
        _operatorInfo[operator].operatorId = operatorId;

        // Use the library function to add operator to sets
        _operatorSets.addOperatorToSets(
            operatorSetIds, RestakingProtocol.EIGENLAYER, operator
        );
    }

    function _deregisterOperatorForEigenlayer(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        _deregisterOperatorFromOperatorSets(operator, operatorSetIds);
        operatorInfo.status = OperatorStatus.DEREGISTERED;

        _operatorSets.removeOperatorFromSets(
            operatorSetIds, RestakingProtocol.EIGENLAYER, operator
        );
    }

    /// @dev This function is only callable by the Eigenlayer middleware or Symbiotic middleware
    /// @inheritdoc ITaiyiRegistryCoordinator
    function createOperatorSet(uint32 operatorSetId) external onlyRestakingMiddleware {
        _operatorSets.createOperatorSet(operatorSetId);
    }

    function getOperatorSetOperators(
        uint32 operatorSetId,
        RestakingProtocol protocol
    )
        external
        view
        returns (address[] memory)
    {
        uint32 encodedId;
        if (protocol == RestakingProtocol.EIGENLAYER) {
            encodedId = operatorSetId.encodeOperatorSetId(RestakingProtocol.EIGENLAYER);
        } else {
            encodedId = operatorSetId.encodeOperatorSetId(RestakingProtocol.SYMBIOTIC);
        }
        return _operatorSets.getOperatorsInSet(encodedId);
    }

    /**
     * @notice Gets an operator from an operator set by address
     * @param operatorSetId The operator set ID
     * @param operator The operator address
     * @return The operator address if found, address(0) otherwise
     */
    function getOperatorFromOperatorSet(
        uint32 operatorSetId,
        address operator
    )
        external
        view
        returns (address)
    {
        // Check if the operator is in the set
        if (_operatorSets.isOperatorInSet(operatorSetId, operator)) {
            return operator;
        }
        return address(0);
    }

    function getOperatorSetCount() external view returns (uint32) {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            return uint32(symbioticMiddleware.SUBNETWORK_COUNT);
        } else {
            return uint32(allocationManager.getOperatorSetCount(eigenlayerMiddleware));
        }
    }

    /**
     * @notice Gets the operators in a operator set
     * @param operatorSetId The operator set ID
     * @return The operator set
     */
    function getOperatorSet(
        uint32 operatorSetId,
        RestakingProtocol protocol
    )
        external
        view
        returns (address[] memory)
    {
        uint32 encodedId;
        if (protocol == RestakingProtocol.EIGENLAYER) {
            encodedId = operatorSetId.encodeOperatorSetId(RestakingProtocol.EIGENLAYER);
        } else {
            encodedId = operatorSetId.encodeOperatorSetId(RestakingProtocol.SYMBIOTIC);
        }
        return _operatorSets.getOperatorsInSet(encodedId);
    }

    /**
     * @notice Gets the number of operators in a specific operator set
     * @param operatorSetId The operator set ID
     * @param protocol The protocol type
     * @return The number of operators in the set
     */
    function getOperatorSetSize(
        uint32 operatorSetId,
        RestakingProtocol protocol
    )
        external
        view
        returns (uint256)
    {
        uint32 encodedId = operatorSetId.encodeOperatorSetId(protocol);
        return _operatorSets.getOperatorSetLength(encodedId);
    }

    // Todo: add symbiotic support
    function getOperatorSetStrategies(uint32 operatorSetId)
        external
        view
        returns (IStrategy[] memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: msg.sender, id: operatorSetId });
        return allocationManager.getStrategiesInOperatorSet(operatorSet);
    }

    // Todo: add symbiotic support
    function addStrategiesToOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyRestakingMiddleware
    {
        uint256 operatorSetCount = allocationManager.getOperatorSetCount(msg.sender);
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.addStrategiesToOperatorSet({
            avs: msg.sender,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    // Todo: add symbiotic support
    function removeStrategiesFromOperatorSet(
        uint32 operatorSetId,
        IStrategy[] memory strategies
    )
        external
        onlyRestakingMiddleware
    {
        uint256 operatorSetCount = allocationManager.getOperatorSetCount(msg.sender);
        require(operatorSetId <= operatorSetCount, InvalidOperatorSetId());
        allocationManager.removeStrategiesFromOperatorSet({
            avs: msg.sender,
            operatorSetId: operatorSetId,
            strategies: strategies
        });
    }

    function _deregisterOperatorFromOperatorSets(
        address operator,
        uint32[] memory operatorSetIds
    )
        internal
        virtual
    {
        address avs = msg.sender;
        allocationManager.deregisterFromOperatorSets(
            IAllocationManagerTypes.DeregisterParams({
                operator: operator,
                avs: avs,
                operatorSetIds: operatorSetIds
            })
        );
    }

    /// @notice Fetches an operator's pubkey hash from the PubkeyRegistry. If the
    /// operator has not registered a pubkey, attempts to register a pubkey using
    /// `params`
    /// @param operator the operator whose pubkey to query from the PubkeyRegistry
    /// @param params contains the G1 & G2 public keys of the operator, and a signature proving their ownership
    /// @dev `params` can be empty if the operator has already registered a pubkey in the PubkeyRegistry
    function _getOrCreateOperatorId(
        address operator,
        IPubkeyRegistry.PubkeyRegistrationParams memory params
    )
        internal
        returns (bytes32 operatorId)
    {
        // Use a special test mode if we detect we're in a test environment
        if (block.chainid == 31_337) {
            // Hardhat/Anvil Chain ID (test mode)
            operatorId = pubkeyRegistry.getOperatorId(operator);

            if (operatorId == bytes32(0)) {
                // If not registered, we'll register with the provided params
                operatorId = pubkeyRegistry.getOrRegisterOperatorId(
                    operator, params, pubkeyRegistrationMessageHash(operator)
                );
            }

            return operatorId;
        } else {
            // Normal production path
            return pubkeyRegistry.getOrRegisterOperatorId(
                operator, params, pubkeyRegistrationMessageHash(operator)
            );
        }
    }

    /// @notice Updates an operator's socket address in the SocketRegistry
    /// @param operatorId The unique identifier of the operator
    /// @param socket The new socket address to set for the operator
    /// @dev Emits an OperatorSocketUpdate event after updating
    function _setOperatorSocket(bytes32 operatorId, string memory socket) internal {
        socketRegistry.setOperatorSocket(operatorId, socket);
        emit OperatorSocketUpdate(operatorId, socket);
    }

    // Todo: add symbiotic support
    /// @notice Returns all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @return Array of operator sets that the operator has allocated magnitude to
    function getOperatorAllocatedOperatorSets(address operator)
        external
        view
        returns (OperatorSet[] memory)
    {
        return allocationManager.getAllocatedSets(operator);
    }

    // Todo: add symbiotic support
    /// @notice Returns all strategies that an operator has allocated magnitude to in a specific operator set
    /// @param operator The operator whose allocated strategies to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @return Array of strategies that the operator has allocated magnitude to in the operator set
    function getOperatorAllocatedStrategies(
        address operator,
        uint32 operatorSetId
    )
        external
        view
        returns (IStrategy[] memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: msg.sender, id: operatorSetId });
        return allocationManager.getAllocatedStrategies(operator, operatorSet);
    }

    // Todo: add symbiotic support
    /// @notice Returns an operator's allocation info for a specific strategy in an operator set
    /// @param operator The operator whose allocation to fetch
    /// @param operatorSetId The ID of the operator set to query
    /// @param strategy The strategy to query
    /// @return The operator's allocation info for the strategy in the operator set
    function getOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 operatorSetId,
        IStrategy strategy
    )
        external
        view
        returns (IAllocationManagerTypes.Allocation memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: msg.sender, id: operatorSetId });
        return allocationManager.getAllocation(operator, operatorSet, strategy);
    }

    // Todo: add symbiotic support
    /// @notice Returns all operator sets and allocations for a specific strategy that an operator has allocated magnitude to
    /// @param operator The operator whose allocations to fetch
    /// @param strategy The strategy to query
    /// @return Array of operator sets and corresponding allocations for the strategy
    function getOperatorStrategyAllocations(
        address operator,
        IStrategy strategy
    )
        external
        view
        returns (OperatorSet[] memory, IAllocationManagerTypes.Allocation[] memory)
    {
        return allocationManager.getStrategyAllocations(operator, strategy);
    }

    // Todo: add symbiotic support
    /// @notice Returns all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @return Array of operator sets that the operator has allocated magnitude to
    function getOperatorSetsFromOperator(address operator)
        external
        view
        returns (OperatorSet[] memory)
    {
        return allocationManager.getAllocatedSets(operator);
    }

    /// ========================================================================================
    /// ============== EIGENLAYER OUT-PROTOCOL OPERATOR VIEW FUNCTIONS =========================
    /// ========================================================================================

    function getOperator(address operator) external view returns (OperatorInfo memory) {
        return _operatorInfo[operator];
    }

    /// @notice Returns the operatorId for the given `operator`
    function getOperatorId(address operator) external view returns (bytes32) {
        return _operatorInfo[operator].operatorId;
    }

    /// @notice Returns the operator address for the given `operatorId`
    function getOperatorFromId(bytes32 operatorId) external view returns (address) {
        return pubkeyRegistry.getOperatorFromId(operatorId);
    }

    /// @notice Returns the status for the given `operator`
    function getOperatorStatus(address operator)
        external
        view
        returns (ITaiyiRegistryCoordinator.OperatorStatus)
    {
        return _operatorInfo[operator].status;
    }

    /// @notice Returns the message hash that an operator must sign to register their BLS public key.
    /// @param operator is the address of the operator registering their BLS public key
    function pubkeyRegistrationMessageHash(address operator)
        public
        view
        returns (BN254.G1Point memory)
    {
        return BN254.hashToG1(calculatePubkeyRegistrationMessageHash(operator));
    }

    /// @notice Returns the message hash that an operator must sign to register their BLS public key.
    /// @param operator is the address of the operator registering their BLS public key
    function calculatePubkeyRegistrationMessageHash(address operator)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(PUBKEY_REGISTRATION_TYPEHASH, operator))
        );
    }

    /**
     * @notice External function to decode operator data
     * @param data The data to decode
     * @return socket The socket string
     * @return params The PubkeyRegistrationParams
     */
    function decodeOperatorData(bytes calldata data)
        external
        pure
        returns (
            string memory socket,
            IPubkeyRegistry.PubkeyRegistrationParams memory params
        )
    {
        return abi.decode(data, (string, IPubkeyRegistry.PubkeyRegistrationParams));
    }

    // ======================================
    // ======= SYMBIOTIC SPECIFIC ===========
    // ======================================

    // Todo: check add stake
    /// @notice Register an operator for the Symbiotic protocol
    /// @dev Handles mapping of subnetwork ID to appropriate operator set IDs
    /// @param operator The operator to register
    /// @param subnetworkId The subnetwork ID (will be mapped to operator sets)
    /// @param data Additional registration data
    function _registerOperatorForSymbiotic(
        address operator,
        uint32[] memory subnetworkIds,
        bytes calldata /*data*/
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(
            operatorInfo.status != OperatorStatus.REGISTERED, OperatorAlreadyRegistered()
        );

        _operatorInfo[operator].status = OperatorStatus.REGISTERED;

        // Use the library function to add operator to sets
        _operatorSets.addOperatorToSets(
            subnetworkIds, RestakingProtocol.SYMBIOTIC, operator
        );
    }

    /// @notice Deregister an operator from the Symbiotic protocol
    /// @dev Handles mapping of subnetwork ID to appropriate operator set IDs for deregistration
    /// @param operator The operator to deregister
    /// @param subnetworkIds The subnetwork IDs (will be mapped to operator sets)
    function _deregisterOperatorForSymbiotic(
        address operator,
        uint32[] memory subnetworkIds
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        operatorInfo.status = OperatorStatus.DEREGISTERED;

        // Use the library function to remove operator from sets
        _operatorSets.removeOperatorFromSets(
            subnetworkIds, RestakingProtocol.SYMBIOTIC, operator
        );
    }
}

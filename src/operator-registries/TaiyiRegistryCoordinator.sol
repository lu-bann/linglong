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
import { RestakingProtocolMapLib } from "../libs/RestakingProtocolMapLib.sol";

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

import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";
import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";

import { SafeCast96To32Lib } from "../libs/SafeCast96To32Lib.sol";

/// @title A `TaiyiRegistryCoordinator` that has two registries:
///      1) a `PubkeyRegistry` that keeps track of operators' public keys
///      2) a `SocketRegistry` that keeps track of operators' sockets (arbitrary strings)
contract TaiyiRegistryCoordinator is
    ITaiyiRegistryCoordinator,
    TaiyiRegistryCoordinatorStorage,
    Initializable,
    Pausable,
    OwnableUpgradeable,
    EIP712Upgradeable,
    IAVSRegistrar
{
    using BN254 for BN254.G1Point;
    using EnumerableSet for EnumerableSet.AddressSet;
    using OperatorSubsetLib for OperatorSubsetLib.OperatorSets;
    using RestakingProtocolMapLib for RestakingProtocolMapLib.Map;
    using OperatorSubsetLib for uint96;
    using OperatorSubsetLib for uint32;
    using SafeCast96To32Lib for uint96;
    using SafeCast96To32Lib for uint32;
    using SafeCast96To32Lib for uint96[];
    using SafeCast96To32Lib for uint32[];

    // ==============================================================================================
    // ================================= MODIFIERS =================================================
    // ==============================================================================================

    /// @notice Modifier that allows only registered middleware contracts to call a function
    modifier onlyRestakingMiddleware() {
        require(restakingProtocolMap.contains(msg.sender), OnlyRestakingMiddleware());
        _;
    }

    modifier onlyEigenLayerMiddleware() {
        require(msg.sender == eigenLayerMiddleware, OnlyEigenlayerMiddleware());
        _;
    }

    modifier onlySymbioticMiddleware() {
        require(msg.sender == symbioticMiddleware, OnlySymbioticMiddleware());
        _;
    }

    // ==============================================================================================
    // ================================= CONSTRUCTOR & INITIALIZER =================================
    // ==============================================================================================

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

    /// @notice Initialize the contract
    /// @param initialOwner Address of contract owner
    /// @param initialPausedStatus Initial paused status
    /// @param _allocationManager Address of allocation manager
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

    // ==============================================================================================
    // ================================= EXTERNAL WRITE FUNCTIONS ==================================
    // ==============================================================================================

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
            _registerOperatorForSymbiotic(operator, operatorSetIds.toUint96Array(), data);
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
            _deregisterOperatorForSymbiotic(operator, operatorSetIds.toUint96Array());
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

    /// @dev This function is only callable by the Symbiotic middleware
    /// @inheritdoc ITaiyiRegistryCoordinator
    function createSubnetwork(uint96 operatorSetId) external onlySymbioticMiddleware {
        _operatorSets.createOperatorSet96(operatorSetId);
    }

    /// @dev This function is only callable by the Eigenlayer middleware
    /// @inheritdoc ITaiyiRegistryCoordinator
    function createOperatorSet(uint32 operatorSetId) external onlyEigenLayerMiddleware {
        _operatorSets.createOperatorSet32(operatorSetId);
    }

    // ==============================================================================================
    // ================================= OWNER/ADMIN FUNCTIONS =====================================
    // ==============================================================================================

    /// @notice Updates the reference to the socket registry
    /// @param _socketRegistry The new socket registry address
    /// @dev This is needed for testing purposes when dealing with proxies
    function updateSocketRegistry(address _socketRegistry) external onlyOwner {
        require(_socketRegistry != address(0), "Socket registry cannot be zero address");
        socketRegistry = ISocketRegistry(_socketRegistry);
    }

    /// @notice Updates the reference to the pubkey registry
    /// @param _pubkeyRegistry The new pubkey registry address
    /// @dev This is needed for testing purposes when dealing with proxies
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

    // ==============================================================================================
    // ================================= EXTERNAL VIEW FUNCTIONS ===================================
    // ==============================================================================================

    /// @notice Gets all registered middleware addresses
    /// @return Array of middleware addresses
    function getRestakingMiddleware() external view returns (address[] memory) {
        return restakingProtocolMap.addresses();
    }

    /// @notice Gets all operator sets
    /// @return Array of operator set IDs
    function getSymbioticSubnetworks() external view returns (uint96[] memory) {
        return _operatorSets.getOperatorSets96();
    }

    /// @notice Gets all operator sets
    /// @return Array of operator set IDs
    function getEigenLayerOperatorSets() external view returns (uint32[] memory) {
        return _operatorSets.getOperatorSets32();
    }

    /// @notice Checks if a middleware is a restaking middleware
    /// @param middleware The middleware address to check
    /// @return True if the middleware is a restaking middleware, false otherwise
    function isRestakingMiddleware(address middleware) external view returns (bool) {
        return restakingProtocolMap.contains(middleware);
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

    /// @notice Gets an operator from an operator set by address
    /// @param baseOperatorSetId The base operator set ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function getEigenLayerOperatorFromOperatorSet(
        uint32 baseOperatorSetId,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _operatorSets.isOperatorInSet32(
            baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER),
            operator
        );
    }

    /// @notice Gets an operator from a subnetwork by address
    /// @param baseSubnetworkId The base subnetwork ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function getSymbioticOperatorFromOperatorSet(
        uint96 baseSubnetworkId,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _operatorSets.isOperatorInSet96(
            baseSubnetworkId.encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC), operator
        );
    }

    /// @notice Checks if an operator is in a specific operator set
    /// @param baseOperatorSetId The base operator set ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function isEigenLayerOperatorInSet(
        uint32 baseOperatorSetId,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _operatorSets.isOperatorInSet32(
            baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER),
            operator
        );
    }

    /// @notice Checks if an operator is in a specific symbiotic operator set
    /// @param baseSubnetworkId The base subnetwork ID
    /// @param operator The operator address
    /// @return True if the operator is in the set, false otherwise
    function isSymbioticOperatorInSubnetwork(
        uint96 baseSubnetworkId,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _operatorSets.isOperatorInSet96(
            baseSubnetworkId.encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC), operator
        );
    }

    function getOperatorSetCount() external view returns (uint32) {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            return uint32(
                ISymbioticNetworkMiddleware(symbioticMiddleware).getSubnetworkCount()
            );
        } else {
            return uint32(allocationManager.getOperatorSetCount(eigenLayerMiddleware));
        }
    }

    /// @notice Gets the operators in a specific eigenlayer operator set
    /// @param baseOperatorSetId The base operator set ID
    /// @return The operator set
    function getEigenLayerOperatorSetOperators(uint32 baseOperatorSetId)
        external
        view
        returns (address[] memory)
    {
        return _operatorSets.getOperatorsInSet32(
            baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER)
        );
    }

    /// @notice Gets the operators in a specific symbiotic subnetwork
    /// @param baseSubnetworkId The base subnetwork ID
    /// @return The operator set
    function getSymbioticSubnetworkOperators(uint96 baseSubnetworkId)
        external
        view
        returns (address[] memory)
    {
        return _operatorSets.getOperatorsInSet96(
            baseSubnetworkId.encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC)
        );
    }

    /// @notice Gets the size of a specific eigenlayer operator set
    /// @param baseOperatorSetId The base operator set ID
    /// @return The size of the operator set
    function getEigenLayerOperatorSetSize(uint32 baseOperatorSetId)
        external
        view
        returns (uint256)
    {
        return _operatorSets.getOperatorSetLength32(
            baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER)
        );
    }

    /// @notice Gets the size of a specific symbiotic subnetwork
    /// @param baseSubnetworkId The base subnetwork ID
    /// @return The size of the subnetwork
    function getSymbioticSubnetworkSize(uint96 baseSubnetworkId)
        external
        view
        returns (uint256)
    {
        return _operatorSets.getOperatorSetLength96(
            baseSubnetworkId.encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC)
        );
    }

    /// @notice Returns all operator sets that an operator has allocated magnitude to
    /// @param operator The operator whose allocated sets to fetch
    /// @return sets The allocated operator sets
    function getOperatorAllocatedOperatorSets(
        address operator,
        RestakingProtocol protocol
    )
        external
        view
        returns (AllocatedOperatorSets memory sets)
    {
        if (protocol == RestakingProtocol.SYMBIOTIC) {
            // Get Symbiotic subnetwork (uint96)
            uint96[] memory symbioticSubnetworkIds = ISymbioticNetworkMiddleware(
                symbioticMiddleware
            ).getOperatorAllocatedSubnetworks(operator);

            // Initialize the symbioticSets array
            sets.symbioticSets = new uint96[](symbioticSubnetworkIds.length);
            for (uint256 i = 0; i < symbioticSubnetworkIds.length; i++) {
                sets.symbioticSets[i] = symbioticSubnetworkIds[i];
            }
        } else if (protocol == RestakingProtocol.EIGENLAYER) {
            // Get EigenLayer operator sets (uint32)
            OperatorSet[] memory eigenLayerSets =
                allocationManager.getAllocatedSets(operator);

            // Initialize the eigenLayerSets array
            sets.eigenLayerSets = new uint32[](eigenLayerSets.length);
            for (uint256 i = 0; i < eigenLayerSets.length; i++) {
                sets.eigenLayerSets[i] = eigenLayerSets[i].id;
            }
        }

        return sets;
    }

    /// @notice Returns all strategies that an operator has allocated magnitude to in a specific operator set
    /// @param operator The operator whose allocated strategies to fetch
    /// @param baseOperatorSetId The ID of the operator set to query
    function getEigenLayerOperatorAllocatedStrategies(
        address operator,
        uint32 baseOperatorSetId
    )
        external
        view
        returns (address[] memory)
    {
        OperatorSet memory operatorSet = OperatorSet({
            avs: msg.sender,
            id: baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER)
        });
        IStrategy[] memory strategies =
            allocationManager.getAllocatedStrategies(operator, operatorSet);
        address[] memory allocatedStrategies = new address[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            allocatedStrategies[i] = address(strategies[i]);
        }
        return allocatedStrategies;
    }

    /// @notice Returns all strategies that an operator has allocated magnitude to in a specific symbiotic subnetwork
    /// @param operator The operator whose allocated strategies to fetch
    /// @param baseSubnetworkId The ID of the subnetwork to query
    function getSymbioticOperatorAllocatedStrategies(
        address operator,
        uint96 baseSubnetworkId
    )
        external
        view
        returns (address[] memory allocatedStrategies)
    {
        (, allocatedStrategies,) = ISymbioticNetworkMiddleware(symbioticMiddleware)
            .getOperatorCollaterals(
            operator, baseSubnetworkId.encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC)
        );
    }

    function getSymbioticOperatorAllocatedStrategiesAmount(
        address operator,
        uint96 baseSubnetworkId,
        IStrategy strategy
    )
        external
        returns (uint256)
    {
        // 1. Get the operator's collaterals for this subnetwork
        (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        ) = ISymbioticNetworkMiddleware(symbioticMiddleware).getOperatorCollaterals(
            operator, baseSubnetworkId
        );

        // 2. Find the matching strategy and return its allocation
        address strategyAddress = address(strategy);

        // Check if operator has any vaults/collaterals
        if (collateralTokens.length == 0) {
            // Operator has no registered collaterals in this subnetwork
            emit OperatorAllocationQuery(
                operator, baseSubnetworkId, address(strategy), 0, "No collaterals found"
            );
            return 0;
        }

        for (uint256 i = 0; i < collateralTokens.length; i++) {
            if (collateralTokens[i] == strategyAddress) {
                if (stakedAmounts[i] > 0) {
                    // Found a matching strategy with allocation
                    emit OperatorAllocationQuery(
                        operator,
                        baseSubnetworkId,
                        address(strategy),
                        stakedAmounts[i],
                        "Allocation found"
                    );
                    return stakedAmounts[i];
                } else {
                    // Strategy exists but has zero allocation
                    emit OperatorAllocationQuery(
                        operator,
                        baseSubnetworkId,
                        address(strategy),
                        0,
                        "Zero allocation"
                    );
                    return 0;
                }
            }
        }

        // Strategy not found among operator's collaterals
        emit OperatorAllocationQuery(
            operator, baseSubnetworkId, address(strategy), 0, "Strategy not found"
        );
        return 0;
    }

    /// @dev Returns 0 if the operator has no allocation for this strategy
    function getEigenLayerOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 baseOperatorSetId,
        IStrategy strategy
    )
        external
        returns (uint256)
    {
        OperatorSet memory operatorSet = OperatorSet({
            avs: msg.sender,
            id: baseOperatorSetId.encodeOperatorSetId32(RestakingProtocol.EIGENLAYER)
        });
        IAllocationManagerTypes.Allocation memory allocation =
            allocationManager.getAllocation(operator, operatorSet, strategy);

        // Log the query result
        emit OperatorAllocationQuery(
            operator,
            baseOperatorSetId,
            address(strategy),
            allocation.currentMagnitude,
            allocation.effectBlock >= block.number
                ? "Confirmed allocation"
                : "Unconfirmed allocation"
        );

        return allocation.currentMagnitude;
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
        return keccak256(abi.encode(PUBKEY_REGISTRATION_TYPEHASH, operator));
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

    // ==============================================================================================
    // ================================= INTERNAL FUNCTIONS ========================================
    // ==============================================================================================

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

        // Update the specific middleware references for easier access
        if (_restakingProtocol == RestakingProtocol.SYMBIOTIC) {
            symbioticMiddleware = _restakingMiddleware;
        } else if (_restakingProtocol == RestakingProtocol.EIGENLAYER) {
            eigenLayerMiddleware = _restakingMiddleware;
        }

        emit RestakingMiddlewareUpdated(_restakingProtocol, _restakingMiddleware);
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
        return pubkeyRegistry.getOrRegisterOperatorId(operator, params);
    }

    /// @notice Updates an operator's socket address in the SocketRegistry
    /// @param operatorId The unique identifier of the operator
    /// @param socket The new socket address to set for the operator
    /// @dev Emits an OperatorSocketUpdate event after updating
    function _setOperatorSocket(bytes32 operatorId, string memory socket) internal {
        socketRegistry.setOperatorSocket(operatorId, socket);
        emit OperatorSocketUpdate(operatorId, socket);
    }

    // ==============================================================================================
    // ================================= PROTOCOL-SPECIFIC FUNCTIONS ===============================
    // ==============================================================================================

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
        _operatorSets.addOperatorToSets32(
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

        _operatorSets.removeOperatorFromSets32(
            operatorSetIds, RestakingProtocol.EIGENLAYER, operator
        );
    }

    /// @notice Register an operator for the Symbiotic protocol
    /// @dev Handles mapping of base subnetwork ID to appropriate operator set IDs
    /// @param operator The operator to register
    /// @param baseSubnetworkIds The base subnetwork ID (will be mapped to operator sets)
    function _registerOperatorForSymbiotic(
        address operator,
        uint96[] memory baseSubnetworkIds,
        bytes calldata /*data*/
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(
            operatorInfo.status != OperatorStatus.REGISTERED, OperatorAlreadyRegistered()
        );

        _operatorInfo[operator].status = OperatorStatus.REGISTERED;

        uint96[] memory operatorSetIds = new uint96[](baseSubnetworkIds.length);
        for (uint256 i = 0; i < baseSubnetworkIds.length; i++) {
            operatorSetIds[i] =
                baseSubnetworkIds[i].encodeOperatorSetId96(RestakingProtocol.SYMBIOTIC);
        }

        _operatorSets.addOperatorToSets96(
            operatorSetIds, RestakingProtocol.SYMBIOTIC, operator
        );
    }

    /// @notice Deregister an operator from the Symbiotic protocol
    /// @dev Handles mapping of subnetwork ID to appropriate operator set IDs for deregistration
    /// @param operator The operator to deregister
    /// @param subnetworkIds The subnetwork IDs (will be mapped to operator sets)
    function _deregisterOperatorForSymbiotic(
        address operator,
        uint96[] memory subnetworkIds
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        operatorInfo.status = OperatorStatus.DEREGISTERED;

        // Use the library function to remove operator from sets
        _operatorSets.removeOperatorFromSets96(
            subnetworkIds, RestakingProtocol.SYMBIOTIC, operator
        );
    }
}

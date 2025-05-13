// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IPubkeyRegistry } from "../interfaces/IPubkeyRegistry.sol";
import { ISocketRegistry } from "../interfaces/ISocketRegistry.sol";

import { IEigenLayerMiddleware } from "../interfaces/IEigenLayerMiddleware.sol";
import { ISymbioticNetworkMiddleware } from
    "../interfaces/ISymbioticNetworkMiddleware.sol";
import { ITaiyiRegistryCoordinator } from "../interfaces/ITaiyiRegistryCoordinator.sol";
import { BN254 } from "../libs/BN254.sol";
import { OperatorSubsetLib } from "../libs/OperatorSubsetLib.sol";
import { RestakingProtocolMapLib } from "../libs/RestakingProtocolMapLib.sol";
import { SafeCast96To32Lib } from "../libs/SafeCast96To32Lib.sol";
import { TaiyiRegistryCoordinatorStorage } from
    "../storage/TaiyiRegistryCoordinatorStorage.sol";
import { AllocationManager } from
    "@eigenlayer-contracts/src/contracts/core/AllocationManager.sol";
import { IAVSRegistrar } from
    "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";

import { IDelegationManager } from
    "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {
    ISignatureUtilsMixin,
    ISignatureUtilsMixinTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/ISignatureUtilsMixin.sol";
import { IStrategy } from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { OperatorSet } from
    "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { Pausable } from "@eigenlayer-contracts/src/contracts/permissions/Pausable.sol";
import { OwnableUpgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import { Initializable } from
    "@openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { EIP712Upgradeable } from
    "@openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";
import { EnumerableSet } from
    "@openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import { IPauserRegistry } from
    "eigenlayer-contracts/src/contracts/interfaces/IPauserRegistry.sol";
import "forge-std/console.sol";

/// @title TaiyiRegistryCoordinator
/// @notice A registry coordinator that manages operator registrations for both EigenLayer and Symbiotic protocols
/// @dev Maintains two registries:
///      1) PubkeyRegistry: Tracks operators' public keys
///      2) SocketRegistry: Tracks operators' socket addresses
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
    using EnumerableSet for EnumerableSet.UintSet;
    using OperatorSubsetLib for OperatorSubsetLib.LinglongSubsets;
    using RestakingProtocolMapLib for RestakingProtocolMapLib.Map;
    using SafeCast96To32Lib for uint96;
    using SafeCast96To32Lib for uint32;
    using SafeCast96To32Lib for uint96[];
    using SafeCast96To32Lib for uint32[];

    // ==============================================================================================
    // ================================= MODIFIERS =================================================
    // ==============================================================================================

    /// @notice Restricts function access to registered restaking middleware contracts
    modifier onlyRestakingMiddleware() {
        require(restakingProtocolMap.contains(msg.sender), OnlyRestakingMiddleware());
        _;
    }

    modifier onlyMiddleware() {
        require(
            msg.sender == eigenLayerMiddleware || msg.sender == symbioticMiddleware,
            OnlyMiddleware()
        );
        _;
    }

    /// @notice Restricts function access to Symbiotic protocol subset IDs
    modifier onlySymbioticSubsetId(uint32 linglongSubsetId) {
        require(
            OperatorSubsetLib.isSymbioticProtocolID(linglongSubsetId),
            OnlySymbioticSubsetId()
        );
        _;
    }

    /// @notice Restricts function access to EigenLayer protocol subset IDs
    modifier onlyEigenLayerSubsetId(uint32 linglongSubsetId) {
        require(
            OperatorSubsetLib.isEigenlayerProtocolID(linglongSubsetId),
            OnlyEigenlayerSubsetId()
        );
        _;
    }

    // ==============================================================================================
    // ================================= CONSTRUCTOR & INITIALIZER =================================
    // ==============================================================================================

    /// @notice Constructor for the TaiyiRegistryCoordinator
    /// @param _allocationManager Address of the allocation manager contract
    /// @param _pauserRegistry Address of the pauser registry contract
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

    /// @notice Initializes the contract with required parameters
    /// @param initialOwner Address of the contract owner
    /// @param initialPausedStatus Initial paused status for the contract
    /// @param _allocationManager Address of the allocation manager contract
    /// @param _eigenLayerMiddleware Address of the EigenLayer middleware contract
    function initialize(
        address initialOwner,
        uint256 initialPausedStatus,
        address _allocationManager,
        address _eigenLayerMiddleware,
        address /* _pauserRegistry */
    )
        external
        initializer
    {
        __EIP712_init("TaiyiRegistryCoordinator", "v0.0.1");
        _transferOwnership(initialOwner);
        _setPausedStatus(initialPausedStatus);

        if (_allocationManager != address(0)) {
            allocationManager = IAllocationManager(_allocationManager);
        }

        if (_eigenLayerMiddleware != address(0)) {
            eigenLayerMiddleware = _eigenLayerMiddleware;
        }
    }

    // ==============================================================================================
    // ================================= EXTERNAL WRITE FUNCTIONS ==================================
    // ==============================================================================================

    /// @notice Registers an operator for either EigenLayer or Symbiotic protocol
    /// @param operator Address of the operator to register
    /// @param linglongSubsetIds Array of subset IDs to register the operator for
    /// @param data Additional registration data including socket and pubkey information
    function registerOperator(
        address operator,
        address, /*avs*/
        uint32[] memory linglongSubsetIds,
        bytes calldata data
    )
        external
        override(IAVSRegistrar, ITaiyiRegistryCoordinator)
        onlyWhenNotPaused(PAUSED_REGISTER_OPERATOR)
    {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            _registerOperatorForSymbiotic(operator, linglongSubsetIds);
        } else if (msg.sender == address(allocationManager)) {
            _registerOperatorForEigenlayer(operator, linglongSubsetIds, data);
        }
    }

    /// @notice Deregisters an operator from either EigenLayer or Symbiotic protocol
    /// @param operator Address of the operator to deregister
    /// @param linglongSubsetIds Array of subset IDs to deregister the operator from
    function deregisterOperator(
        address operator,
        address, /*avs*/
        uint32[] memory linglongSubsetIds
    )
        external
        override(IAVSRegistrar, ITaiyiRegistryCoordinator)
        onlyWhenNotPaused(PAUSED_DEREGISTER_OPERATOR)
    {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            _deregisterOperatorForSymbiotic(operator);
        } else if (msg.sender == address(allocationManager)) {
            _deregisterOperatorForEigenlayer(operator, linglongSubsetIds);
        }
    }

    /// @notice Updates an operator's socket address
    /// @param socket New socket address for the operator
    function updateSocket(string memory socket) external {
        require(
            _operatorInfo[msg.sender].status == OperatorStatus.REGISTERED, NotRegistered()
        );
        _setOperatorSocket(_operatorInfo[msg.sender].operatorId, socket);
    }

    /// @notice Creates a new Linglong subset for the Symbiotic protocol
    /// @param linglongSubsetId ID of the new subset
    /// @param minStake Minimum stake required for the subset
    function createLinglongSubset(
        uint32 linglongSubsetId,
        uint256 minStake
    )
        external
        onlyMiddleware
    {
        _linglongSubsets.createLinglongSubset(linglongSubsetId, minStake);
    }

    // ==============================================================================================
    // ================================= OWNER/ADMIN FUNCTIONS =====================================
    // ==============================================================================================

    /// @notice Updates the socket registry address
    /// @param _socketRegistry New socket registry address
    function updateSocketRegistry(address _socketRegistry) external onlyOwner {
        require(_socketRegistry != address(0), "Socket registry cannot be zero address");
        socketRegistry = ISocketRegistry(_socketRegistry);
    }

    /// @notice Updates the pubkey registry address
    /// @param _pubkeyRegistry New pubkey registry address
    function updatePubkeyRegistry(address _pubkeyRegistry) external onlyOwner {
        require(_pubkeyRegistry != address(0), "Pubkey registry cannot be zero address");
        pubkeyRegistry = IPubkeyRegistry(_pubkeyRegistry);
    }

    /// @notice Sets the protocol type for a middleware address
    /// @param _restakingMiddleware Middleware address to set protocol for
    /// @param _restakingProtocol Protocol type (EIGENLAYER or SYMBIOTIC)
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

    /// @notice Checks if the contract supports a specific AVS
    /// @param avs Address of the AVS to check
    /// @return bool True if the AVS is supported
    function supportsAVS(address avs) external view returns (bool) {
        return avs == eigenLayerMiddleware;
    }

    /// @notice Gets all registered middleware addresses
    /// @return Array of middleware addresses
    function getRestakingMiddleware() external view returns (address[] memory) {
        return restakingProtocolMap.addresses();
    }

    /// @notice Gets all Linglong subset IDs
    /// @return Array of subset IDs
    function getLinglongSubnets() external view returns (uint32[] memory) {
        uint256[] memory subnetIds = _linglongSubsets.linglongSubsetIds.values();
        uint32[] memory subsetIds = new uint32[](subnetIds.length);
        for (uint256 i = 0; i < subnetIds.length; i++) {
            subsetIds[i] = uint32(subnetIds[i]);
        }
        return subsetIds;
    }

    /// @notice Checks if an address is a registered middleware
    /// @param middleware Address to check
    /// @return bool True if the address is a registered middleware
    function isRestakingMiddleware(address middleware) external view returns (bool) {
        return restakingProtocolMap.contains(middleware);
    }

    /// @notice Gets all middleware addresses for a specific protocol
    /// @param protocol Protocol type to filter by
    /// @return Array of middleware addresses for the specified protocol
    function getRestakingMiddlewareByProtocol(RestakingProtocol protocol)
        external
        view
        returns (address[] memory)
    {
        return restakingProtocolMap.addressesByProtocol(protocol);
    }

    /// @notice Gets the protocol type for a middleware address
    /// @param middleware Middleware address to query
    /// @return Protocol type associated with the middleware
    function getMiddlewareProtocol(address middleware)
        external
        view
        returns (RestakingProtocol)
    {
        return restakingProtocolMap.get(middleware);
    }

    /// @notice Checks if an operator is in a specific Linglong subset
    /// @param linglongSubsetId ID of the subset to check
    /// @param operator Address of the operator to check
    /// @return bool True if the operator is in the subset
    function isOperatorInLinglongSubset(
        uint32 linglongSubsetId,
        address operator
    )
        external
        view
        returns (bool)
    {
        return _linglongSubsets.isOperatorInLinglongSubset(linglongSubsetId, operator);
    }

    /// @notice Checks if a Linglong subset exists
    /// @param linglongSubsetId ID of the subset to check
    /// @return bool True if the subset exists
    function isLinglongSubsetExist(uint32 linglongSubsetId)
        external
        view
        returns (bool)
    {
        return _linglongSubsets.linglongSubsetIds.contains(linglongSubsetId);
    }

    /// @notice Gets the count of operator sets
    /// @return uint32 Number of operator sets
    function getOperatorSetCount() external view returns (uint32) {
        if (restakingProtocolMap.get(msg.sender) == RestakingProtocol.SYMBIOTIC) {
            return uint32(
                ISymbioticNetworkMiddleware(symbioticMiddleware).getSubnetworkCount()
            );
        } else {
            return uint32(allocationManager.getOperatorSetCount(eigenLayerMiddleware));
        }
    }

    /// @notice Gets all operators in a specific Linglong subset
    /// @param linglongSubsetId ID of the subset to query
    /// @return Array of operator addresses in the subset
    function getLinglongSubsetOperators(uint32 linglongSubsetId)
        external
        view
        returns (address[] memory)
    {
        return _linglongSubsets.getOperatorsInLinglongSubset(linglongSubsetId);
    }

    /// @notice Gets the size of a specific Linglong subset
    /// @param linglongSubsetId ID of the subset to query
    /// @return uint256 Number of operators in the subset
    function getLinglongSubsetSize(uint32 linglongSubsetId)
        external
        view
        returns (uint256)
    {
        return _linglongSubsets.getOperatorsInLinglongSubset(linglongSubsetId).length;
    }

    /// @notice Gets all operator sets that an operator has allocated magnitude to
    /// @param operator Address of the operator to query
    /// @param protocol Protocol type to filter by
    /// @return sets Allocated operator sets for the operator
    function getOperatorAllocatedOperatorSets(
        address operator,
        RestakingProtocol protocol
    )
        external
        view
        returns (AllocatedOperatorSets memory sets)
    {
        if (protocol == RestakingProtocol.SYMBIOTIC) {
            uint96[] memory symbioticSubnetworkIds = ISymbioticNetworkMiddleware(
                symbioticMiddleware
            ).getOperatorAllocatedSubnetworks(operator);

            sets.symbioticSets = new uint96[](symbioticSubnetworkIds.length);
            for (uint256 i = 0; i < symbioticSubnetworkIds.length; i++) {
                sets.symbioticSets[i] = symbioticSubnetworkIds[i];
            }
        } else if (protocol == RestakingProtocol.EIGENLAYER) {
            OperatorSet[] memory eigenLayerSets =
                allocationManager.getAllocatedSets(operator);

            sets.eigenLayerSets = new uint32[](eigenLayerSets.length);
            for (uint256 i = 0; i < eigenLayerSets.length; i++) {
                sets.eigenLayerSets[i] = eigenLayerSets[i].id;
            }
        }

        return sets;
    }

    /// @notice Gets all strategies that an operator has allocated magnitude to in a specific EigenLayer subset
    /// @param operator Address of the operator to query
    /// @param linglongSubsetId ID of the subset to query
    /// @return Array of strategy addresses
    function getEigenLayerOperatorAllocatedStrategies(
        address operator,
        uint32 linglongSubsetId
    )
        external
        view
        onlyEigenLayerSubsetId(linglongSubsetId)
        returns (address[] memory)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: eigenLayerMiddleware, id: linglongSubsetId });
        IStrategy[] memory strategies =
            allocationManager.getAllocatedStrategies(operator, operatorSet);
        address[] memory allocatedStrategies = new address[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            allocatedStrategies[i] = address(strategies[i]);
        }
        return allocatedStrategies;
    }

    /// @notice Gets all strategies that an operator has allocated magnitude to in a specific Symbiotic subset
    /// @param operator Address of the operator to query
    /// @param linglongSubsetId ID of the subset to query
    /// @return allocatedStrategies of strategy addresses
    function getSymbioticOperatorAllocatedStrategies(
        address operator,
        uint32 linglongSubsetId
    )
        external
        view
        onlySymbioticSubsetId(linglongSubsetId)
        returns (address[] memory allocatedStrategies)
    {
        (, allocatedStrategies,) = ISymbioticNetworkMiddleware(symbioticMiddleware)
            .getOperatorCollaterals(operator, linglongSubsetId);
    }

    /// @notice Gets the amount of a specific strategy allocated by an operator in a Symbiotic subset
    /// @param operator Address of the operator to query
    /// @param linglongSubsetId ID of the subset to query
    /// @param strategy Strategy to query allocation for
    /// @return uint256 Amount of the strategy allocated
    function getSymbioticOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 linglongSubsetId,
        IStrategy strategy
    )
        external
        onlySymbioticSubsetId(linglongSubsetId)
        returns (uint256)
    {
        (
            address[] memory vaults,
            address[] memory collateralTokens,
            uint256[] memory stakedAmounts
        ) = ISymbioticNetworkMiddleware(symbioticMiddleware).getOperatorCollaterals(
            operator, linglongSubsetId
        );

        address strategyAddress = address(strategy);

        if (collateralTokens.length == 0) {
            emit OperatorAllocationQuery(
                operator, linglongSubsetId, address(strategy), 0, "No collaterals found"
            );
            return 0;
        }

        for (uint256 i = 0; i < collateralTokens.length; i++) {
            if (collateralTokens[i] == strategyAddress) {
                if (stakedAmounts[i] > 0) {
                    emit OperatorAllocationQuery(
                        operator,
                        linglongSubsetId,
                        address(strategy),
                        stakedAmounts[i],
                        "Allocation found"
                    );
                    return stakedAmounts[i];
                } else {
                    emit OperatorAllocationQuery(
                        operator,
                        linglongSubsetId,
                        address(strategy),
                        0,
                        "Zero allocation"
                    );
                    return 0;
                }
            }
        }

        emit OperatorAllocationQuery(
            operator, linglongSubsetId, address(strategy), 0, "Strategy not found"
        );
        return 0;
    }

    /// @notice Gets the amount of a specific strategy allocated by an operator in an EigenLayer subset
    /// @param operator Address of the operator to query
    /// @param linglongSubsetId ID of the subset to query
    /// @param strategy Strategy to query allocation for
    /// @return uint256 Amount of the strategy allocated
    function getEigenLayerOperatorAllocatedStrategiesAmount(
        address operator,
        uint32 linglongSubsetId,
        IStrategy strategy
    )
        external
        onlyEigenLayerSubsetId(linglongSubsetId)
        returns (uint256)
    {
        OperatorSet memory operatorSet =
            OperatorSet({ avs: eigenLayerMiddleware, id: linglongSubsetId });
        IAllocationManagerTypes.Allocation memory allocation =
            allocationManager.getAllocation(operator, operatorSet, strategy);

        emit OperatorAllocationQuery(
            operator,
            linglongSubsetId,
            address(strategy),
            allocation.currentMagnitude,
            allocation.effectBlock >= block.number
                ? "Confirmed allocation"
                : "Unconfirmed allocation"
        );

        return allocation.currentMagnitude;
    }

    // ==============================================================================================
    // ================================= OPERATOR VIEW FUNCTIONS ===================================
    // ==============================================================================================

    /// @notice Gets information about an operator
    /// @param operator Address of the operator to query
    /// @return OperatorInfo Information about the operator
    function getOperator(address operator) external view returns (OperatorInfo memory) {
        return _operatorInfo[operator];
    }

    /// @notice Gets the operator ID for an operator address
    /// @param operator Address of the operator to query
    /// @return bytes32 Operator ID
    function getOperatorId(address operator) external view returns (bytes32) {
        return _operatorInfo[operator].operatorId;
    }

    /// @notice Gets the operator address for an operator ID
    /// @param operatorId ID of the operator to query
    /// @return address Operator address
    function getOperatorFromId(bytes32 operatorId) external view returns (address) {
        return pubkeyRegistry.getOperatorFromId(operatorId);
    }

    /// @notice Gets the status of an operator
    /// @param operator Address of the operator to query
    /// @return OperatorStatus Status of the operator
    function getOperatorStatus(address operator)
        external
        view
        returns (ITaiyiRegistryCoordinator.OperatorStatus)
    {
        return _operatorInfo[operator].status;
    }

    /// @notice Gets the message hash for pubkey registration
    /// @param operator Address of the operator registering their pubkey
    /// @return BN254.G1Point Message hash for pubkey registration
    function pubkeyRegistrationMessageHash(address operator)
        public
        view
        returns (BN254.G1Point memory)
    {
        return BN254.hashToG1(calculatePubkeyRegistrationMessageHash(operator));
    }

    /// @notice Calculates the message hash for pubkey registration
    /// @param operator Address of the operator registering their pubkey
    /// @return bytes32 Message hash for pubkey registration
    function calculatePubkeyRegistrationMessageHash(address operator)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(PUBKEY_REGISTRATION_TYPEHASH, operator));
    }

    /// @notice Decodes operator registration data
    /// @param data Data to decode
    /// @return socket Socket address
    /// @return params Pubkey registration parameters
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

    /// @notice Sets the protocol type for a middleware address
    /// @param _restakingMiddleware Middleware address to set protocol for
    /// @param _restakingProtocol Protocol type to set
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

        if (_restakingProtocol == RestakingProtocol.SYMBIOTIC) {
            symbioticMiddleware = _restakingMiddleware;
        } else if (_restakingProtocol == RestakingProtocol.EIGENLAYER) {
            eigenLayerMiddleware = _restakingMiddleware;
        }

        emit RestakingMiddlewareUpdated(_restakingProtocol, _restakingMiddleware);
    }

    /// @notice Gets or creates an operator ID
    /// @param operator Address of the operator
    /// @param params Pubkey registration parameters
    /// @return operatorId Operator ID
    function _getOrCreateOperatorId(
        address operator,
        IPubkeyRegistry.PubkeyRegistrationParams memory params
    )
        internal
        returns (bytes32 operatorId)
    {
        return pubkeyRegistry.getOrRegisterOperatorId(operator, params);
    }

    /// @notice Sets an operator's socket address
    /// @param operatorId ID of the operator
    /// @param socket New socket address
    function _setOperatorSocket(bytes32 operatorId, string memory socket) internal {
        socketRegistry.setOperatorSocket(operatorId, socket);
        emit OperatorSocketUpdate(operatorId, socket);
    }

    // ==============================================================================================
    // ================================= PROTOCOL-SPECIFIC FUNCTIONS ===============================
    // ==============================================================================================

    /// @notice Registers an operator for the EigenLayer protocol
    /// @param operator Address of the operator to register
    /// @param _linglongSubsetIds Array of subset IDs to register for
    /// @param data Additional registration data
    function _registerOperatorForEigenlayer(
        address operator,
        uint32[] memory _linglongSubsetIds,
        bytes calldata data
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        bool operatorRegisteredBefore =
            _operatorInfo[operator].status == OperatorStatus.REGISTERED;

        (
            string memory socket,
            IPubkeyRegistry.PubkeyRegistrationParams memory params,
            ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry memory operatorSignature
        ) = abi.decode(
            data,
            (
                string,
                IPubkeyRegistry.PubkeyRegistrationParams,
                ISignatureUtilsMixinTypes.SignatureWithSaltAndExpiry
            )
        );
        bytes32 operatorId = _getOrCreateOperatorId(operator, params);
        _operatorInfo[operator].status = OperatorStatus.REGISTERED;
        _operatorInfo[operator].operatorId = operatorId;

        uint256[] memory stakes = _checkInitialEigenStake(operator, _linglongSubsetIds);
        for (uint256 i = 0; i < stakes.length; ++i) {
            require(
                OperatorSubsetLib.isEigenlayerProtocolID(_linglongSubsetIds[i]),
                "Invalid eigenlayer subset ID"
            );
            uint256 minStake = _linglongSubsets.getMinStake(_linglongSubsetIds[i]);
            require(stakes[i] >= minStake, "Stake below set minimum");
        }

        if (!operatorRegisteredBefore) {
            IEigenLayerMiddleware(eigenLayerMiddleware).registerOperatorToAVS(
                operator, operatorSignature
            );
        }

        _linglongSubsets.addOperatorToLinglongSubsets(_linglongSubsetIds, operator);
    }

    /// @notice Deregisters an operator from the EigenLayer protocol
    /// @param operator Address of the operator to deregister
    /// @param _linglongSubsetIds Array of subset IDs to deregister from

    function _deregisterOperatorForEigenlayer(
        address operator,
        uint32[] memory _linglongSubsetIds
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        for (uint256 i = 0; i < _linglongSubsetIds.length; i++) {
            require(
                OperatorSubsetLib.isEigenlayerProtocolID(_linglongSubsetIds[i]),
                "Invalid eigenlayer subset ID"
            );
        }

        _linglongSubsets.removeOperatorFromLinglongSubsets(_linglongSubsetIds, operator);
        // Check if the operator is still in any Linglong subset
        bool stillInAnySubset = false;
        uint256[] memory allSubsetIds = _linglongSubsets.linglongSubsetIds.values();
        for (uint256 i = 0; i < allSubsetIds.length; i++) {
            uint32 subsetId = uint32(allSubsetIds[i]);
            if (_linglongSubsets.isOperatorInLinglongSubset(subsetId, operator)) {
                stillInAnySubset = true;
                break;
            }
        }

        // Only set status to DEREGISTERED if not in any subset
        if (!stillInAnySubset) {
            operatorInfo.status = OperatorStatus.DEREGISTERED;
        }
    }

    /// @notice Registers an operator for the Symbiotic protocol
    /// @param operator Address of the operator to register
    /// @param linglongSubsetIds Array of subset IDs to register for
    function _registerOperatorForSymbiotic(
        address operator,
        uint32[] memory linglongSubsetIds
    )
        internal
    {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(
            operatorInfo.status != OperatorStatus.REGISTERED, OperatorAlreadyRegistered()
        );

        _operatorInfo[operator].status = OperatorStatus.REGISTERED;
        for (uint256 i = 0; i < linglongSubsetIds.length; i++) {
            require(
                OperatorSubsetLib.isSymbioticProtocolID(linglongSubsetIds[i]),
                "Invalid symbiotic subset ID"
            );
        }

        _linglongSubsets.addOperatorToLinglongSubsets(linglongSubsetIds, operator);
    }

    /// @notice Deregisters an operator from the Symbiotic protocol
    /// @param operator Address of the operator to deregister
    function _deregisterOperatorForSymbiotic(address operator) internal {
        OperatorInfo storage operatorInfo = _operatorInfo[operator];
        require(operatorInfo.status == OperatorStatus.REGISTERED, OperatorNotRegistered());

        uint32[] memory linglongSubsetIds = new uint32[](2);
        linglongSubsetIds[0] = OperatorSubsetLib.SYMBIOTIC_VALIDATOR_SUBSET_ID;
        linglongSubsetIds[1] = OperatorSubsetLib.SYMBIOTIC_UNDERWRITER_SUBSET_ID;

        _linglongSubsets.removeOperatorFromLinglongSubsets(linglongSubsetIds, operator);

        // Check if the operator is still in any Linglong subset
        bool stillInAnySubset = false;
        uint256[] memory allSubsetIds = _linglongSubsets.linglongSubsetIds.values();
        for (uint256 i = 0; i < allSubsetIds.length; i++) {
            uint32 subsetId = uint32(allSubsetIds[i]);
            if (_linglongSubsets.isOperatorInLinglongSubset(subsetId, operator)) {
                stillInAnySubset = true;
                break;
            }
        }

        // Only set status to DEREGISTERED if not in any subset
        if (!stillInAnySubset) {
            operatorInfo.status = OperatorStatus.DEREGISTERED;
        }
    }

    /// @notice Checks the initial EigenLayer stake for an operator
    /// @param operator Address of the operator to check
    /// @param _linglongSubsetIds Array of subset IDs to check
    /// @return stakesPerSet Array of stake amounts per subset
    function _checkInitialEigenStake(
        address operator,
        uint32[] memory _linglongSubsetIds
    )
        internal
        view
        returns (uint256[] memory stakesPerSet)
    {
        stakesPerSet = new uint256[](_linglongSubsetIds.length);

        IDelegationManager deleg =
            AllocationManager(address(allocationManager)).delegation();

        for (uint256 k = 0; k < _linglongSubsetIds.length; ++k) {
            uint32 subsetId = _linglongSubsetIds[k];
            OperatorSet memory opSet =
                OperatorSet({ avs: eigenLayerMiddleware, id: subsetId });

            IStrategy[] memory strategies =
                allocationManager.getAllocatedStrategies(operator, opSet);
            if (strategies.length == 0) {
                stakesPerSet[k] = 0;
                continue;
            }

            uint256[] memory shares = deleg.getOperatorShares(operator, strategies);

            uint256 stakeForSet;
            for (uint256 i = 0; i < strategies.length; ++i) {
                IAllocationManagerTypes.Allocation memory alloc =
                    allocationManager.getAllocation(operator, opSet, strategies[i]);
                if (alloc.currentMagnitude == 0) continue;

                uint64 maxMag = allocationManager.getMaxMagnitude(operator, strategies[i]);
                if (maxMag == 0) continue;

                uint256 stakePortion =
                    (shares[i] * uint256(alloc.currentMagnitude)) / uint256(maxMag);
                stakeForSet += stakePortion;
            }

            stakesPerSet[k] = stakeForSet;
        }
    }
}

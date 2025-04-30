# OperatorSubsetLib – ID Encoding Scheme

| File | Notes |
| ---- | ----- |
| [`OperatorSubsetLib.sol`](../src/libs/OperatorSubsetLib.sol) | Utility library that **embeds the restaking-protocol type into operator-set IDs**. |

---

## Why Encode the Protocol in the ID?
Both EigenLayer and Symbiotic maintain *collections* of operators (operator **sets** for EigenLayer, **subnetworks** for Symbiotic).  
To keep a single, protocol-agnostic registry (`TaiyiRegistryCoordinator`) we need a **unique primary key** for each collection *and* a quick way to know which protocol it belongs to.

By dedicating the **top 5 bits** of the ID to a `RestakingProtocol` enum we get:

* A single integer key that can be stored in mappings & events.
* **O(1)** protocol detection using bit-masks instead of extra storage.
* Compatibility with EigenLayer's `IAVSRegistrar` (expects `uint32` IDs) as well as larger `uint96` IDs used on-chain by Symbiotic.

---

## Bit Layout

| Width | Purpose | Range |
| ----- | ------- | ----- |
| 5 bits | `protocol` | `RestakingProtocol` enum (max 32 values) |
| 27 / 91 bits | `baseId` | Raw operator-set / sub-network id |

Two helper variants exist:

| Function | Return type | Layout |
| -------- | ----------- | ------ |
| `encodeOperatorSetId32(baseId, protocol)` | `uint32` | 5-bit protocol  + 27-bit baseId (EigenLayer / IAVSRegistrar) |
| `encodeOperatorSetId96(baseId, protocol)` | `uint96` | 5-bit protocol  + 91-bit baseId (Symbiotic & internal) |

### Constants
```solidity
uint8  private constant PROTOCOL_BITS    = 5;
uint8  private constant PROTOCOL_SHIFT_32 = 27; // 32 - 5
uint8  private constant PROTOCOL_SHIFT_96 = 91; // 96 - 5
```

### Example
```solidity
uint32 id32 = OperatorSubsetLib.encodeOperatorSetId32(7, RestakingProtocol.EIGENLAYER);
// 0b00001_00000000000000000000000111 -> protocol=1   baseId=7

uint96 id96 = OperatorSubsetLib.encodeOperatorSetId96(42, RestakingProtocol.SYMBIOTIC);
// 0b00010...0101010                 -> protocol=2   baseId=42
```

The reverse helpers `decodeOperatorSetId32/96` split the integer back into `(protocol, baseId)`.

---

## Helper Methods
Besides encoding/decoding, the library provides:

* `encodeOperatorSetIdForIAVS` – forces the encoded id to fit into 32 bits for EigenLayer callbacks.
* `getProtocolType32/96` and `getBaseId32/96` – faster extraction without the struct.
* Set management helpers (`OperatorSets` struct) that store members & minStake for both variants.

---

## Usage Across the Codebase
* `EigenLayerMiddleware` encodes **operator-set IDs** before sending them to the coordinator.
* `SymbioticNetworkMiddleware` generates **subnetwork IDs** via `encodeOperatorSetId96`.
* `TaiyiRegistryCoordinator` accepts *both* 32-bit and 96-bit encoded IDs and can instantly determine the protocol by masking the top 5 bits.

See those contracts for concrete examples.  
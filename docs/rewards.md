# Reward Distribution Flow

This note explains how **UnderwriterAVS** and **ValidatorAVS** cooperate to produce operator-directed rewards using EigenLayer's `RewardsCoordinator`.

See the sequence diagram below and the implementation pointers.

```mermaid
sequenceDiagram
    actor Initiator as Reward Initiator
    participant Underwriter as UnderwriterAVS
    participant Validator as ValidatorAVS
    participant Rewards as RewardsCoordinator
    participant Operator as Operators / Stakers

    Initiator->>Underwriter: createOperatorDirectedAVSRewardsSubmission()
    Underwriter->>Rewards: createOperatorDirectedAVSRewardsSubmission() (underwriter portion)
    Underwriter->>Validator: handleValidatorRewards(validator portion)
    Validator->>Rewards: createOperatorDirectedAVSRewardsSubmission()
    Rewards-->>Operator: Merkle root for claiming
```

## Implementation Pointers
* Underwriter: [`UnderwriterAVS.sol`](../src/eigenlayer-avs/UnderwriterAVS.sol)  →
  * `_createOperatorDirectedAVSRewardsSubmission`
  * `_handleUnderwriterSubmission`
* Validator: [`ValidatorAVS.sol`](../src/eigenlayer-avs/ValidatorAVS.sol)  →
  * `handleValidatorRewards`

### Example Split
1. Underwriter receives `1000` tokens. Suppose it allocates `700` to its own operators and forwards `300` to ValidatorAVS.
2. ValidatorAVS splits the `300` among validator operators pro-rata by validator count.

Reward calculation happens **on-chain** so anyone can trigger distribution without special permissions. 
# LingLong

![2025-03-31 23 37 34](https://github.com/user-attachments/assets/898f073f-c7e4-46ce-8261-b43c355da8d6)


> 🚧 **NOTICE** 🔨 This repository is under active development. Features may change, interfaces are not stable, and the codebase is evolving rapidly. 


LingLong is a flexible proposer commitment framework that enables Ethereum validators to trustlessly delegate commitment generation to specialized entities, without transferring operational control. Through its modular design, LingLong orchestrates commitment generation, data availability management, and auxiliary functions to create a streamlined process for variety of proposer commitment, such as preconfirmation, data availability, and more.


---

## Quick Start

#### 1. Clone & install
```bash
$ git clone https://github.com/luban/linglong.git
$ cd linglong && forge install
```

#### 2. Run tests
```bash
$ forge test
```

---

## Repository Layout

| Path | Description |
| ---- | ----------- |
| `src/` | All solidity contracts (middleware, registries, slasher, Taiyi service) |
| `lib/` | Git submodules & third-party deps (EigenLayer, Symbiotic, URC, …) |
| `test/` | Foundry test-suite |
| `docs/` | Extended markdown docs (architecture, contract guides) |

Key docs:

* [`docs/TaiyiRegistryCoordinator.md`](docs/TaiyiRegistryCoordinator.md) – unified operator registry
* [`docs/OperatorSubsetLib.md`](docs/OperatorSubsetLib.md) – ID encoding scheme
* [`docs/EigenLayerMiddleware.md`](docs/EigenLayerMiddleware.md)
* [`docs/SymbioticNetworkMiddleware.md`](docs/SymbioticNetworkMiddleware.md)
* [`docs/LinglongSlasher.md`](docs/LinglongSlasher.md)

Developer how-tos:

* [`docs/registration.md`](docs/registration.md) – register an operator & stake
* [`docs/rewards.md`](docs/rewards.md) – create rewards submissions

---

## Contributing

Pull-requests are welcome! Please open an issue first if you plan a large change.

1. Fork → feature branch → PR.  
2. Run `forge test`, then `forge fmt`.
3. Ensure new docs are added under `docs/`.

By contributing you agree to license your work under the Apache 2.0 license 

---



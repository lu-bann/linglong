# LingLong Documentation

---

## Index

| Topic | File |
| ----- | ---- |
| 📜 Architecture Overview | [README (root)](../README.md) |
| 🗄️ Registry | [TaiyiRegistryCoordinator.md](TaiyiRegistryCoordinator.md) |
| 🆔 ID Encoding | [OperatorSubsetLib.md](OperatorSubsetLib.md) |
| 🔌 EigenLayer Middleware | [EigenLayerMiddleware.md](EigenLayerMiddleware.md) |
| 🔌 Symbiotic Middleware | [SymbioticNetworkMiddleware.md](SymbioticNetworkMiddleware.md) |
| ⚔️ Slashing Dispatcher | [LinglongSlasher.md](LinglongSlasher.md) |
| 👷 Operator How-To | [registration.md](registration.md) |
| 💰 Reward Flow | [rewards.md](rewards.md) |
| 🚨 Slashing Flow | [slashing.md](slashing.md) |

---

## Conventions

* All contract-centric docs live as `*.md` siblings in this folder.  
  File names match the primary contract/library for easy discovery.
* Diagrams are written in **Mermaid** where helpful.  GitHub renders them automatically.
* Relative links use short paths (`./file.md`) so they work on GitHub **and** inside static-site generators.

---

## Contributing

Have a fix or new doc to add?

1. Place the markdown file in `docs/`.  
2. Add a row to the *Index* table above.  
3. PR with a clear description – screenshots of diagrams appreciated.

All documentation is licensed Apache 2.0, identical to the codebase. 
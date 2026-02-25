# i-dont-like-api-abuse

Anti-abuse pipeline: cryptographically random bytecode VM, ChaCha-encrypted WASM delivery, entropy validation, and JWT-backed challenge verification.

## Quick start

```bash
npm run build    # Compiler → copy assets → build site
npm run dev      # Compiler → copy assets → dev server
npm run start    # Production site (after build)
```

## Requirements

- [Node 18+](https://nodejs.org/en/download/archive/v18.20.8)
- [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-10.0.103-windows-x64-installer)
- [Clang](https://releases.llvm.org/download.html) with wasm32 target
- [Redis](https://redis.io/downloads/) (for challenge verification)
- `CHALLENGE_VERIFY_SECRET` env var (min 32 chars)
- `REDIS_URL` (optional, defaults to redis://localhost:6379)

## Project layout

```
├── compiler/microsoft.botsay/   C# bytecode generator + WASM compiler
├── site/                       Next.js app + VM lib
├── docs/                       Architecture and API docs
└── package.json                Root scripts
```

## Documentation

- [Architecture](docs/architecture.md) — Pipeline overview and data flow
- [Compiler](docs/compiler.md) — Bytecode generation and WASM build
- [VM](docs/vm.md) — Operations, bytecodes, and vm_run
- [Site](docs/site.md) — APIs, pages, and configuration
- [Entropy](docs/entropy.md) — Fingerprint and behaviour validation


## Developer Message

This project is a recreation of an old concept i had that created a list of operations and a vm runs these operations to prevent api abuse.
The concept i had is currently implamented in https://qyzar.eu this one is a tad bit diffrent with stronger encryption and more encoding types.
The docs where made by AI and im not bothering to check them so if you dont understand create an issue or message me directly if you can find me.
TLDR: docs are made by ai and this is a recreation of the anti api abuse system on my website https://qyzar.eu


https://github.com/user-attachments/assets/cb176525-0e81-4002-ab03-d8bf0edbb507


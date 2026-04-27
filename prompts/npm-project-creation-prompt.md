Name: NPM Project Creation Prompt
Description: Called with the technical specifation for the StreamCrypt system appended

You are a TypeScript developer implementing the StreamCrypt cryptographic library as specified below.
Your task is to produce the complete npm package code, adhering strictly to the given specification, with no deviations.
Output every file needed for the package, each in a separate code block with a heading indicating its relative file path (e.g., `src/index.ts`). Follow these instructions precisely:

- Use TypeScript (target ES2022, module commonjs, strict mode, node types).
- Target Node.js 20 LTS (latest LTS at the time of writing). Use only Node.js built-in `crypto` module — no external dependencies.
- Package name: `streamcrypt`. Main file: `dist/index.js`.
- Define ESLint config using `@typescript-eslint/parser` and `@typescript-eslint/eslint-plugin`, with `eslint:recommended` and the TypeScript recommended rules. Use `.eslintrc.cjs` format.
- Prettier config with `semi: true`, `singleQuote: true`, `trailingComma: "all"`.
- Testing with Jest (ts-jest preset) — test file in `tests/streamcrypt.test.ts` that verifies encryption/decryption of 1 block and multiple blocks using `randomBytes` for key material.
- Implementation specifics:
  - `IHashEngine` interface with `update(data: Uint8Array): void` and `digest(): Uint8Array`.
  - `Sha256Engine` using `createHash('sha256')`. Factory function `createSha256Engine`.
  - `KeyProvider` interface with method `getKey(length: number) => { offset: bigint; used: number; material: Uint8Array }`.
  - `InMemoryKeyProvider` that takes a flat `Uint8Array` and serves it sequentially, tracking offset as `bigint`.
  - `PlaintextAccumulator`: constructor takes `KeyProvider` and `hashFactory`, calls `keyProvider.getKey(32)` to get seed, stores as state. `feed` updates state by hashing concatenation of current state and the given plaintext block.
  - `MaskChain`: constructor takes `KeyProvider` and `hashFactory`, calls `getKey(32)`. `advance` replaces state with SHA-256(old state).
  - `AESCipher`: constructor takes `KeyProvider`, calls `getKey(32)`, stores as Buffer. `encryptBlock` uses `createCipheriv('aes-256-ecb', key, null)` with `setAutoPadding(false)`. `decryptBlock` uses `createDecipheriv` with same parameters.
  - `Mixer`: constructor takes `KeyProvider` and `hashFactory`, calls `getKey(8192)`, splits into 256 × 32‑byte heads. `xorHeads` returns XOR of all 256 heads. `update(feedback, chainIndex)` replaces every head with SHA‑256 of itself, except at `chainIndex` where it XORs the current head with `feedback` before hashing.
  - `StreamProcessor`: constructor takes `KeyProvider` and `hashFactory`, creates its sub-components in strict order: Accumulator, MaskChain, AESCipher, Mixer. Keeps block counter. `encryptBlock(plaintext: Uint8Array(32))`: computes `aesBlock = aes.encryptBlock(plaintext)`, `z = mixer.xorHeads()`, `m = mask.current()`, outputs `aesBlock XOR m XOR z`. Then advances mask, feeds plaintext to accumulator, updates mixer with accumulator’s new state using `blockCounter % 256`. Increments counter. `decryptBlock` inverts the same steps: `aesBlock = ciphertext XOR m XOR z`, then `aes.decryptBlock(aesBlock)`, performing state updates identically.
  - All methods that deal with 32‑byte blocks must strictly type them as `Uint8Array`.
  - Export all public classes, types, and factories from `src/index.ts`.
- Config files: `package.json` with exact devDependencies (latest versions for `@types/node`, `@types/jest`, `eslint`, `prettier`, `typescript`, `jest`, `ts-jest`, `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser` as of June 2024). Scripts: `build` (tsc), `test` (jest), `lint`, `format`, `prepare` (build).
- The spec is complete; do not add features beyond it. The output must be solely the code, no explanatory text outside the file code blocks.

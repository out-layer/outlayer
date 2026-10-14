# Host interfaces (WIT)

The interfaces a guest component imports from the worker: `near:storage`,
`near:rpc`, `near:payment`, `near:vrf`, `outlayer:wallet`,
`outlayer:signing-keys`, `outlayer:encryption-keys`, `outlayer:tasks`.

* `deps/*.wit` are the current version of each package.
* A subdirectory such as `storage-v0_1/` holds an older published version that
  the worker still serves.

## A published version is an ABI

A deployed component carries the name, version and exact types of every
function it imports (`near:storage/api@0.1.0` with `has: func(key: string) ->
bool`), and nothing else. It does not carry the SDK crate's version. The
worker's linker finds the interface by name and version, then compares the
types. One mismatch fails the whole run with `Failed to instantiate
component`, before the guest starts. Binaries of projects we do not own
cannot be rebuilt, so a published version must link forever.

## Which change needs what

| Change | Same version? | What to do |
|---|---|---|
| Add a function | yes | Edit `deps/<pkg>.wit` in place. Old binaries do not import it. |
| Edit doc comments | yes | Edit in place. Comments are not part of the type. |
| Change a parameter, a result, a record field, a variant or an enum | **no** | New package version, see below |
| Remove or rename a function | **no** | New package version, see below |

## A new version, step by step

The worked example is `near:storage` `@0.1.0` → `@0.2.0` (`has`/`delete` went
from `bool` to `tuple<bool, string>`). The code is in
`src/outlayer_storage/host_functions.rs`.

1. **Freeze the published version.**
   * Copy the published file into `wit/<pkg>-vX_Y/` verbatim, taken from git
     at the last commit that shipped it, and never edit it again.
   * It goes in a subdirectory of `wit/`, not in `deps/`: the main bindgen
     reads only `wit/*.wit` and `wit/deps/`, so it never sees two versions of
     one package. Both worker Dockerfiles copy `worker/wit` whole, so this
     needs no Dockerfile change.
2. **Bump the current file.** Change `package <ns>:<pkg>@X.Y.Z` in
   `deps/<pkg>.wit` to the new version and make the change there. Update the
   `import` lines in `world.wit`.
   * A 0.x version bumps the MINOR digit: `0.1.0` → `0.2.0`. wasmtime treats
     `0.1.*` as one compatible family: when an import names a `0.1.*` version
     that is not registered, the linker binds it to the `0.1.*` that is. A
     patch bump would therefore read as compatible. A different minor is
     never substituted.
3. **Bind the frozen version.**
   * Add a second `bindgen!` in its own module (`mod v0_1`) pointing at the
     frozen directory.
   * Implement its `Host` for the same state type. Old functions keep their
     old behaviour exactly. Every function whose shape did not change
     delegates to the current impl
     (`<Self as current::Host>::f(self, …)`), so no logic is duplicated.
4. **Register both.** The package's `add_*_to_linker` calls both generated
   `add_to_linker`s. Different versions are different names, so there is no
   conflict.
5. **Test.**
   * The frozen shapes answer as published.
   * A linking test against the real linker: a WAT component importing each
     version in its own shape links, and each shape under the other version
     does not (`each_published_version_links_in_its_own_shape`). Check that
     the test fails when the frozen registration is removed.
6. **SDK** (`sdk/outlayer`).
   * Its `wit/deps/<pkg>.wit` is a COPY of the worker's: `cp` it, never hand
     edit.
   * Update `wit/world.wit` and the `with:` key in `src/lib.rs` to the new
     version.
   * Bump the crate's PATCH version (`0.2.0` → `0.2.1`) when the Rust API is
     unchanged. A user on `outlayer = "0.2"` then gets the new interface from
     `cargo update`.
7. **Other copies.**
   * `wasi-examples/signing-key-probe/wit-storage/` and anything else that
     `build.sh` drift-checks against `worker/wit/deps/`: `cp`, then run the
     builds.
   * Connectors take the SDK as a path dependency and pick up the change on
     rebuild.
8. **Docs.** Name the current version (PROJECT.md, the SDK and example
   READMEs, the dashboard and skills pages that show the WIT). Docs describe
   the final state.

## Rollout order

1. **Survey** the imports of every active version on both networks before
   the worker deploy:
   * download each wasm and run `wasm-tools component wit <file>`;
   * nothing may import a shape that the new worker no longer serves.
2. **Worker on testnet.** Old binaries must still run. Rebuild and republish
   our own fixtures on the new interface.
3. **Worker on mainnet.**
4. **Only then** publish the SDK to crates.io (`cargo publish` in
   `sdk/outlayer`):
   * a build on the new SDK imports the new version, which only the new
     worker serves;
   * yank an SDK release whose build imports a shape no worker serves.
5. Docs (dashboard, skills) go out with or after the mainnet worker.

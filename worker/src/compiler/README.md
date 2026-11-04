# WASM Compiler Module

Prepares the wasm a task runs: downloads a published `WasmUrl` and checks its
sha256, or — on a builder worker where builds are enabled — compiles a GitHub
repository. Builds are off by default on the worker (`COMPILATION_ENABLED`)
and on the coordinator (`BUILDS_ENABLED`); see the worker
[README](../../README.md#roles).

## `WasmUrl` download

`download_wasm_from_url` / `download_and_cache_wasm` (`mod.rs`): `https://` on
port 443 to a public address only, 10 MB cap; the file is refused when its
sha256 does not match the task's `hash`, then uploaded to the coordinator's
cache under that hash.

## GitHub builds

### Targets

| Target | Module | Post-processing | Output |
|---|---|---|---|
| `wasm32-wasip1`, `wasm32-wasi` | `wasm32_wasip1.rs` | `wasm-opt` (Binaryen) | WASI P1 module |
| `wasm32-wasip2` | `wasm32_wasip2.rs` | `wasm-tools strip --delete …` removes debug info and build metadata by name, keeping `outlayer.manifest`; the build then fails if any custom section other than `name`, `component-type*`, `dylink.0` or `outlayer.manifest` survived, naming it | WASI P2 component |

Any other `build_target` is refused (`validate_build_target`).

### Files

```
compiler/
├── mod.rs            - orchestration: cache check, lock, checksum, WasmUrl download
├── docker.rs         - Docker container operations (COMPILATION_MODE=docker)
├── native.rs         - build without Docker (COMPILATION_MODE=native)
├── wasm32_wasip1.rs  - WASI P1 build script
└── wasm32_wasip2.rs  - WASI P2 build script
```

### Flow

1. Checksum = sha256 of (repo, commit, build_target); return if that wasm is cached
2. Acquire the coordinator lock for the checksum, so one worker builds it
3. Validate the repo URL and git ref (`native::validate_repo_url`,
   `native::validate_git_ref`) — both backends interpolate them into a shell
4. Build in a container from `DOCKER_IMAGE` (docker mode) or in a temporary
   directory with `env -i` and `ulimit` (native mode). The build is bounded by
   the contract's `max_compilation_seconds`, less when the request's payment
   covers fewer seconds; the native backend also applies `COMPILE_TIMEOUT_SECONDS`
5. Extract the wasm (tar stream from the container), upload it, release the lock

The same commit compiles to the same bytes only for a given compiler image:
deployments pin `DOCKER_IMAGE` by digest ([docker/BUILD.md](../../../docker/BUILD.md)),
and `scripts/build_github_wasm.sh` runs the same recipe to learn a project's
hash before publishing it. The native backend remaps paths and holds a project
to its `Cargo.lock` for the same reason (`native.rs` header).

### Security

A build runs the repository's own code: cargo executes any `build.rs`, the
build scripts of every dependency and every proc-macro, and no manifest check
stops that. Neither backend contains it:

- docker: the container runs as root on the `bridge` network (the host's
  docker0 listeners and the internet reachable), alive for `sleep 600`;
- native: the build has the network and the worker's host.

That is why builds are off by default and compilation never runs in a TEE
execution worker. What must hold before builds are enabled for arbitrary
repositories is listed on `Compiler::compile_from_github` (`mod.rs`).

## Shared Docker operations (`docker.rs`)

- `ensure_image()` — pull the image (runs on every job, hence the digest pin)
- `create_container()` — create and start the build container
- `exec_in_container()` — run a script in it
- `extract_wasm()` — copy the wasm out
- `cleanup_container()` — stop and remove it

## Adding a build target

1. A module `src/compiler/<target>.rs` with
   `pub async fn compile(docker: &Docker, container_id: &str, build_target: &str) -> Result<Vec<u8>>`,
   running its script through `docker::exec_in_container` and returning
   `docker::extract_wasm(...)`.
2. A match arm in `compile_in_container()` and the target in
   `validate_build_target()` (`mod.rs`).
3. The native backend (`native.rs`), so both modes accept it.
4. An executor that runs the output ([executor README](../executor/README.md)).

## Testing

```bash
cargo test --lib compiler
```

To build a repository the way the worker does, without the worker:
`scripts/test_compiler.sh <repo_url> <commit> <build_target> [output_file]`.

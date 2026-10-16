# Changelog

## 0.2.1

**Rebuild required if your module was built on 0.2.0 and uses storage.**

0.2.0 changed the types of `has` and `delete` (`bool` → `(bool, error)`)
without changing the version of the host interface. Its builds therefore
import `near:storage/api@0.1.0` with types that differ from the published
`@0.1.0`. A worker serves one set of types per interface version. Workers
from this release serve `@0.1.0` as published (`has`/`delete` → `bool`) and
the new types as `near:storage/api@0.2.0`. A 0.2.0 build that imports `has`
or `delete` (through `storage::has`, `storage::delete`, `storage::sealed` or
the raw bindings) fails to start on them with `Failed to instantiate
component`.

What to do:

1. Update the dependency: `cargo update -p outlayer` (any `outlayer = "0.2"`
   requirement resolves to 0.2.1).
2. Rebuild the module.
3. Publish the new build as a project version and make it active.

Modules built on 0.1.x keep running unchanged. 0.2.0 builds that never touch
`has` or `delete` keep running unchanged too. The Rust API is the same as
0.2.0: no code changes are needed.

To see what a built module imports:
`wasm-tools component wit <file.wasm> | grep near:storage`. The rebuilt module
imports `near:storage/api@0.2.0`.

- The storage interface is `near:storage/api@0.2.0`.

# Contributing to OutLayer

## Contributor License Agreement — required

Every contributor must sign the [Contributor License Agreement](CLA.md) before a pull
request can be merged. There is no bot — a maintainer checks this before merging, so
please sign in your pull request without being asked.

Signing takes one comment. What it does is give OutLayer, Inc. a broad license
to your contribution, including the right to relicense it. Without that right the
project could never change its own licensing terms, so this is not negotiable.

If your employer owns the IP you create, get their permission first, or ask us about a
Corporate CLA at outlayer.ai@gmail.com.

## Licensing of contributions

Your contribution is released under the license that governs the directory you are
editing. See [LICENSING.md](LICENSING.md) — most of this repository is Apache-2.0,
while `sdk/outlayer/` and `wasi-examples/` are `MIT OR Apache-2.0`.

Do not add a dependency licensed under GPL, AGPL, SSPL, BUSL, or any
source-available/non-OSI license without raising it in an issue first. The dependency
tree is currently free of all of these and CI is intended to keep it that way. If a
dependency offers a choice of licenses, record the elected license in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

If you copy code from another project, say so: keep the original copyright header,
add the source to the relevant `NOTICE`, and mention it in the pull request. Copied
code without attribution is the single most expensive thing to unwind later.

## Development

See [CLAUDE.md](CLAUDE.md) for component layout and build commands, and
[PROJECT.md](PROJECT.md) for the technical specification.

<!--
  ~ Copyright (c) 2023-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Making a release

One tag releases both packages, with no stored token: PyPI and npm trust
`.github/workflows/release.yaml` through OIDC (trusted publishing).

| Package                  | Registry | Version from                 | GitHub environment |
| ------------------------ | -------- | ---------------------------- | ------------------ |
| `datalayer-agent-shield`  | PyPI     | `agent_shield/__version__.py` | `pypi`             |
| `@datalayer/agent-shield` | npm      | `package.json`               | `npm`              |

Both carry **one version**, the one the tag names.

## Steps

1. Bump the version in both files (`agent_shield/__version__.py`,
   `package.json`) and write the `CHANGELOG.md` entry, on `main` or on a
   branch merged into it.

1. With `Py Tests` green on that head of `main`, tag it and push the tag:

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   gh run watch   # the Release workflow
   ```

1. The `Release` workflow checks that the tag names both versions, builds the
   wheel, the sdist and the npm tarball, publishes what is not on the
   registries yet, and creates a GitHub release with generated notes.

## Trusted publishing

- PyPI project `datalayer-agent-shield` (the import stays `agent_shield`; PyPI
  refused `agent-shield` as too close to an existing name): owner `datalayer`,
  repository `agent-shield`, workflow `release.yaml`, environment `pypi`.
  Registered on 15 October 2026. 0.1.0, the name reservation, was uploaded by
  hand before that; 0.1.1 is the first release through the workflow.
- npm package `@datalayer/agent-shield`: GitHub Actions, organization
  `datalayer`, repository `agent-shield`, workflow filename `release.yaml`,
  environment `npm`. npm's trusted publishing is configured on an existing
  package: the first version is published by hand (or the package created
  on npmjs.com), the workflow publishes the next ones. The repository is private, so npm publishes without a
  provenance statement (npm refuses one from a private repository); it
  attaches provenance by itself once the repository is public, and
  provenance then checks `package.json`'s `repository.url`, which names
  this repository.

The registry matches the repository, the workflow filename and the
environment exactly; renaming any of them means re-registering.

# Repository source SBOM

Every published GitHub Release, including patch, minor, major and prerelease versions,
receives this repository's own `SBOM.cdx.json` (CycloneDX 1.6) and readable
`SBOM.md`. The release description automatically links both reports.

The release workflow also reconciles missing reports daily and supports manual
backfill of an existing release. Complete existing report pairs are preserved.
No release or version is created by this workflow.

The generator inventories the exact tagged tracked source and package manifests.
`.sbom.json` declares nested source, vendored code, models and conditional external
requirements. Unknown origin stays unknown; evidence hashes identify exact bytes,
not proof that vendored code equals its upstream. Reference, GUI, example and test
source remains represented rather than inheriting another project's exclusions.

This is a **source inventory with UNKNOWN completeness**, not proof of installed
OS packages, static linkage, resolved build dependencies or release binary closure.
Generation failures are visible and never published as successful release reports.
Private sources and reports remain in their owning private repository.

Local generation (Python 3, Git, GitHub CLI and Syft 1.55.0):

```sh
python3 scripts/repository_sbom.py --root . --tag EXISTING_RELEASE_TAG --output-dir build/sbom
```

Upstream mirror branches and tags are never rewritten by this automation.

Mirrored Git tags alone are not GitHub Release objects and do not trigger release-asset publication. This workflow never creates releases or version tags.

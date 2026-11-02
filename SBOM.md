# Source SBOM

**Initial source snapshot, not a release report.** Source commit `a7c92289b569afbe4259dc556d749405ebc008f5` predates the tooling commit. Future release reports use exact published tags.

Source repository inventory only; completeness is UNKNOWN. Syft inventories tracked source/package manifests. Gitlinks and declared vendored/model evidence are inspected at immutable pins. CMake declarations are conditional requirements, not resolved installations. This is NOT proof of operating-system packages, static-link closure, build-time resolution, or the contents of release binaries.

Generation: **success**

## Source identity

wave-owl/ardop `a7c92289b569afbe4259dc556d749405ebc008f5`

- sbom:role: source-root
- sbom:git-commit: a7c92289b569afbe4259dc556d749405ebc008f5
- sbom:git-tree: b040775e8a918b75da063ab300a2c2e444fe6954
- sbom:source-repository: https://github.com/wave-owl/ardop
- sbom:release-tags: []
- sbom:license-evidence: [{"path": "LICENSE", "sha256": "922f73954f218b99e8cb1dca0bba2aee0bc062d71d446edcfeada5b85de03e7f"}]
- sbom:license-resolution: unresolved; manual review required

## Generation errors

None.

## Components and unresolved licenses

| Component | Version | Role | License |
| --- | --- | --- | --- |
| wave-owl/ardop | a7c92289b569afbe4259dc556d749405ebc008f5 | source-root | unresolved; manual review required |
| Threads | unresolved | conditional-build-requirement | unresolved |
| PythonInterp | unresolved | conditional-build-requirement | unresolved |
| spdlog_ep | unresolved | conditional-build-requirement | unresolved |
| easylog_ep | unresolved | conditional-build-requirement | unresolved |
| g3log_ep | unresolved | conditional-build-requirement | unresolved |
| glog_ep | unresolved | conditional-build-requirement | unresolved |
| lib | unresolved | declared-vendored-source | unresolved; manual review required |
| Conditional source requirements declared by Makefile | unresolved | conditional-build-runtime-requirement | unresolved |
| Conditional source requirements declared by lib/zf_log/CMakeLists.txt | unresolved | conditional-build-runtime-requirement | unresolved |
| Conditional source requirements declared by lib/zf_log/examples/CMakeLists.txt | unresolved | conditional-build-runtime-requirement | unresolved |
| Conditional source requirements declared by lib/zf_log/tests/CMakeLists.txt | unresolved | conditional-build-runtime-requirement | unresolved |
| Conditional source requirements declared by lib/zf_log/tests/perf/CMakeLists.txt | unresolved | conditional-build-runtime-requirement | unresolved |
| Conditional source requirements declared by lib/zf_log/zf_log/CMakeLists.txt | unresolved | conditional-build-runtime-requirement | unresolved |
| Makefile platform audio/thread libraries; socket-audio branch has separate build path | unresolved | conditional-build-runtime-requirement | unresolved |

License evidence paths/hashes, source manifests, model hashes and conditional
CMake declarations are recorded in SBOM.cdx.json. Declared upstream pins do not
prove vendored equivalence. No dependency installation or build was performed.

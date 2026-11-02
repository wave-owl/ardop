#!/usr/bin/env python3
"""Generate a repository-owned source SBOM; Python standard library + git, gh, Syft.

Run: python scripts/repository_sbom.py --root . --output-dir build/sbom
The root must be a clean tagged Git checkout with a GitHub origin. No repository
code, CMake, package hooks, or downloaded source is executed. Syft scans an exported,
tracked source tree, never the working directory or .git/build/generated reports.
Remote gitlinks/build sources contribute package manifests/lockfiles to Syft, not
every source blob; their exact Git trees, CMake requirements and declared evidence
remain inventoried. Reference-only trees contribute license/provenance evidence,
never installed/shipped package discoveries.

Optional .sbom.json (paths are POSIX, relative to their containing repository):
{
  "gitlinks": {
    "dsp": {"repository": "wave-owl/fldigi-dsp-core", "licenses": ["LICENSE"]},
    "ref/oracle": {"repository": "owner/oracle", "licenses": ["COPYING"],
                   "role": "reference-only"}
  },
  "vendored": [{
    "path": "vendor/codec", "repository": "owner/upstream",
    "commit": "FULL_40_HEX_COMMIT", "licenses": ["vendor/codec/LICENSE"],
    "evidence": ["vendor/codec/PROVENANCE"]
  }],
  "references": [{
    "repository": "owner/oracle", "commit": "FULL_40_HEX_COMMIT",
    "licenses": ["LICENSE"]
  }],
  "models": ["models/decoder.onnx"],
  "external_libraries": [
    {"name": "fftw3", "version": "unresolved", "evidence": ["Makefile"]}
  ]
}

gitlinks maps EVERY recursive gitlink by its full root-relative path; repository
and LICENSE evidence are mandatory. Pins come from Git trees, never branch tips.
vendored paths are tracked files/directories in the root; every constituent blob
is SHA-256 hashed, including provenance evidence. references are provenance-only,
not linked/runtime dependencies. models are explicit tracked files, SHA-256 hashed.
For unknown vendored upstream provenance, set repository and commit BOTH to null;
do not invent an upstream pin. Container Git identity and blob hashes remain exact.
Unknown keys, missing declarations/evidence and inaccessible GitHub pins fail closed.
gitlinks.role optionally marks reference-only trees (excluded from Syft discovery);
otherwise gitlinks are source dependencies. references.role may be "build-source"
instead of the default "reference-only" for immutable build-fetch dependencies.
external_libraries records conditional,
unresolved build/runtime requirements evidenced in tracked files; no install is implied.
Native gitlinks in reference repositories are inspected using the same full-path map
under references/<owner>/<repo>@<commit>/. Declare vendored/model evidence from
gitlinks with the same full-root path in vendored.path/licenses/evidence or models.

The output always declares composition completeness unknown: source inventories
cannot establish operating-system or statically linked release-artifact closure.
Failures write diagnostic outputs and exit nonzero; never publish failed outputs.
CycloneDX 1.6 schema: https://cyclonedx.org/schema/bom-1.6.schema.json.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import quote
import uuid


SCOPE = (
    "Source repository inventory only; completeness is UNKNOWN. Syft inventories "
    "tracked source/package manifests. Gitlinks and declared vendored/model evidence "
    "are inspected at immutable pins. CMake declarations are conditional requirements, "
    "not resolved installations. This is NOT proof of operating-system packages, "
    "static-link closure, build-time resolution, or the contents of release binaries."
)
START_MARKER = "<!-- wave-owl-sbom:start -->"
END_MARKER = "<!-- wave-owl-sbom:end -->"
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
EXCLUDED_DIRS = {".git", "build", "builds", "_build", "dist", "target", "CMakeFiles"}
REPORTS = {"SBOM.cdx.json", "SBOM.md"}
REMOTE_MANIFESTS = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "bun.lockb", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "libs.versions.toml", "packages.lock.json", "conanfile.txt", "conanfile.py",
    "vcpkg.json", "vcpkg-configuration.json", "Directory.Packages.props",
}


class EvidenceError(RuntimeError):
    """Source identity or required evidence could not be established."""


def command(args, cwd=None):
    """Run only explicitly selected metadata/scanner tools, never a shell."""
    try:
        result = subprocess.run(
            args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("{}: {}".format(args[0], exc)) from exc
    if result.returncode:
        raise EvidenceError("{} failed: {}".format(
            args[0], result.stderr.decode("utf-8", "replace").strip()
        ))
    return result.stdout


def git(root, *args):
    return command(["git", "-c", "core.fsmonitor=false", "-C", str(root)] + list(args))


def safe_path(value):
    if not isinstance(value, str):
        raise EvidenceError("Expected a safe relative source path: {!r}".format(value))
    if any((
        not value, "\\" in value, any(c in value for c in "\r\n\x00"),
        PurePosixPath(value).is_absolute(),
        any(part in ("", ".", "..") for part in value.split("/")),
    )):
        raise EvidenceError("Expected a safe relative source path: {!r}".format(value))
    return value


def repository(value):
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value):
        raise EvidenceError("Expected GitHub owner/repository: {!r}".format(value))
    return value


def pin(value):
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        raise EvidenceError("Expected a full immutable Git commit: {!r}".format(value))
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def property_value(component, name, value):
    component.setdefault("properties", []).append({"name": name, "value": str(value)})


def load_config(path):
    if path.is_symlink():
        raise EvidenceError("Declaration file must not be a symlink: " + str(path))
    config = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    if not isinstance(config, dict) or set(config) - {
            "gitlinks", "vendored", "references", "models", "external_libraries"}:
        raise EvidenceError("Unknown .sbom.json keys or non-object declaration")
    for key, expected in (("gitlinks", dict), ("vendored", list),
                          ("references", list), ("models", list), ("external_libraries", list)):
        if not isinstance(config.get(key, expected()), expected):
            raise EvidenceError("Invalid .sbom.json field: " + key)
    return config


class Inventory:
    def __init__(self, root, config, syft="syft", tag=None):
        self.root = root.resolve()
        self.config = config
        self.syft = syft
        self.tag = tag
        self.bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {"timestamp": datetime.now(timezone.utc).isoformat()},
            "components": [], "dependencies": [],
        }
        self.components = {}
        self.edges = {}
        self.files = {}
        self.used_gitlinks = set()
        self.inspected = set()
        self.errors = []
        self.excluded_prefixes = []

    def add(self, component):
        ref = component["bom-ref"]
        if ref not in self.components:
            self.components[ref] = component
        self.edges.setdefault(ref, set())
        return ref

    def edge(self, parent, child):
        self.edges.setdefault(parent, set()).add(child)

    def gh(self, endpoint):
        try:
            return json.loads(command(["gh", "api", endpoint]))
        except EvidenceError as exc:
            raise EvidenceError(
                "GitHub immutable evidence read failed for {}. Private gitlinks "
                "require authorized read access; the workflow GITHUB_TOKEN cannot "
                "read other private repositories. No personal token is supplied. {}"
                .format(endpoint, exc)
            ) from exc

    def remote_tree(self, repo, commit):
        obj = self.gh("repos/{}/git/commits/{}".format(repo, commit))
        if obj["sha"] != commit:
            raise EvidenceError("GitHub returned a different commit for " + repo)
        tree_sha = pin(obj["tree"]["sha"])
        tree = self.gh("repos/{}/git/trees/{}?recursive=1".format(repo, tree_sha))
        if tree.get("truncated"):
            raise EvidenceError("Truncated GitHub tree: " + repo + "@" + commit)
        return tree_sha, {entry["path"]: entry for entry in tree["tree"]}

    def read_remote(self, repo, entry):
        data = self.gh("repos/{}/git/blobs/{}".format(repo, pin(entry["sha"])))
        if data.get("encoding") != "base64" or data.get("sha") != entry["sha"]:
            raise EvidenceError("Missing or mismatched GitHub blob: " + repo)
        content = base64.b64decode(data["content"])
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if actual != entry["sha"]:
            raise EvidenceError("GitHub blob hash mismatch: " + repo)
        return content

    def source_component(self, repo, commit, tree, role):
        component = {
            "type": "library", "name": repo, "version": commit,
            "bom-ref": "git:https://github.com/{}@{}".format(repo, commit),
            "externalReferences": [{
                "type": "vcs", "url": "https://github.com/{}/tree/{}".format(repo, commit),
            }],
            "properties": [
                {"name": "sbom:role", "value": role},
                {"name": "sbom:git-commit", "value": commit},
                {"name": "sbom:git-tree", "value": tree},
                {"name": "sbom:source-repository", "value": "https://github.com/" + repo},
            ],
        }
        if role == "reference-only":
            component["scope"] = "excluded"
        return component

    def license_evidence(self, component, paths, files):
        if not isinstance(paths, list) or not paths:
            raise EvidenceError("A nonempty licenses list is required for " + component["name"])
        evidence = []
        identifiers = set()
        for path in paths:
            content = self.read_file(safe_path(path), files)
            if not content.strip():
                raise EvidenceError("Empty declared license evidence: " + path)
            evidence.append({"path": path, "sha256": sha256(content)})
            identifiers.update(re.findall(
                r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)\s*(?:\r?\n|$)",
                content.decode("utf-8", "replace"),
            ))
        # An arbitrary SPDX-looking token is evidence, not a validated SPDX ID.
        component["licenses"] = [{"license": {"name": "License evidence; see declared files"}}]
        property_value(component, "sbom:license-evidence", json.dumps(evidence, sort_keys=True))
        property_value(component, "sbom:license-resolution", "unresolved; manual review required")
        if identifiers:
            property_value(component, "sbom:declared-spdx-identifiers", ", ".join(sorted(identifiers)))

    def read_file(self, path, files=None):
        entry = (self.files if files is None else files).get(path)
        if not entry or entry["type"] != "blob" or entry.get("mode") == "120000":
            raise EvidenceError("Missing declared regular-file evidence: " + path)
        if "content" not in entry:
            if "repository" in entry:
                entry["content"] = self.read_remote(entry["repository"], entry)
            else:
                entry["content"] = git(self.root, "cat-file", "blob", entry["sha"])
        return entry["content"]

    def inspect_tree(self, parent, entries, prefix="", repo=None):
        for path, entry in sorted(entries.items()):
            full = prefix + path
            if entry["type"] == "blob":
                self.files[full] = dict(entry, **({"repository": repo} if repo else {}))
                excluded = any(full.startswith(item) for item in self.excluded_prefixes)
                is_cmake = path.endswith(".cmake") or PurePosixPath(path).name == "CMakeLists.txt"
                if is_cmake and not excluded:
                    self.cmake(parent, full, self.read_file(full))
            elif entry["type"] == "commit":
                declaration = self.config.get("gitlinks", {}).get(full)
                if not isinstance(declaration, dict):
                    raise EvidenceError("Missing/invalid mapped gitlink: " + full)
                if any((
                    set(declaration) - {"repository", "licenses", "role"},
                    not {"repository", "licenses"} <= declaration.keys(),
                )):
                    raise EvidenceError("Missing/invalid mapped gitlink: " + full)
                self.used_gitlinks.add(full)
                child_repo = repository(declaration["repository"])
                commit = pin(entry["sha"])
                tree, children = self.remote_tree(child_repo, commit)
                role = declaration.get("role", "gitlink")
                if role not in ("gitlink", "reference-only"):
                    raise EvidenceError("Invalid gitlink role at " + full)
                component = self.source_component(child_repo, commit, tree, role)
                if role == "reference-only":
                    self.excluded_prefixes.append(full + "/")
                child_files = {
                    name: dict(item, repository=child_repo) for name, item in children.items()
                }
                self.license_evidence(component, declaration["licenses"], child_files)
                child = self.add(component)
                if role != "reference-only":
                    self.edge(parent, child)
                # Cycles are possible in malicious trees, but every path still needs mapping.
                identity = (child_repo, commit)
                if identity in self.inspected:
                    raise EvidenceError("Repeated/cyclic gitlink identity at " + full)
                self.inspected.add(identity)
                try:
                    self.inspect_tree(child, children, full + "/", child_repo)
                finally:
                    self.inspected.remove(identity)

    def cmake(self, parent, path, content):
        text = content.decode("utf-8", "replace")
        text = re.sub(r"#[^\n]*", "", text)
        pattern = r"\b(find_package|FetchContent_Declare|ExternalProject_Add)\s*\(([^)]*)\)"
        for index, match in enumerate(re.finditer(pattern, text, re.I)):
            declaration = " ".join(match.group(2).split())
            if not declaration:
                continue
            ref = "cmake:" + sha256((parent + path + str(index)).encode())
            child = self.add({
                "type": "library", "name": declaration.split()[0].strip('"'),
                "bom-ref": ref,
                "properties": [
                    {"name": "sbom:role", "value": "conditional-build-requirement"},
                    {"name": "sbom:cmake-source", "value": path},
                    {"name": "sbom:cmake-command", "value": match.group(1)},
                    {"name": "sbom:cmake-declaration", "value": declaration},
                    {"name": "sbom:resolution", "value": "conditional; unresolved version"},
                ],
            })
            self.edge(parent, child)

    def identity(self):
        if git(self.root, "status", "--porcelain", "--untracked-files=no").strip():
            raise EvidenceError("Source checkout is dirty (tracked changes)")
        commit = pin(git(self.root, "rev-parse", "HEAD").decode().strip())
        tree = pin(git(self.root, "rev-parse", "HEAD^{tree}").decode().strip())
        tags = git(self.root, "tag", "--points-at", "HEAD").decode().splitlines()
        if not tags or (self.tag is not None and self.tag not in tags):
            raise EvidenceError("Source must be checked out at the requested release tag")
        remote = git(self.root, "remote", "get-url", "origin").decode().strip()
        match = re.fullmatch(r"(?:https://github.com/|git@github.com:)([^/]+/[^/]+?)(?:\.git)?", remote)
        if not match:
            raise EvidenceError("Origin must identify a GitHub source repository")
        repo = repository(match.group(1))
        component = self.source_component(repo, commit, tree, "source-root")
        component["type"] = "application"
        property_value(component, "sbom:release-tags", json.dumps(tags))
        self.root_ref = self.add(component)
        self.bom["metadata"]["component"] = component
        entries = {}
        for record in git(self.root, "ls-tree", "-rz", "HEAD").split(b"\0"):
            if not record:
                continue
            meta, path = record.split(b"\t", 1)
            mode, kind, oid = meta.decode().split()
            name = safe_path(path.decode("utf-8"))
            entries[name] = {"mode": mode, "type": kind, "sha": oid}
        return entries

    def syft_scan(self, output_dir):
        staging = output_dir / ".source-input"
        if staging.exists():
            raise EvidenceError("Refusing to overwrite existing source staging path: " + str(staging))
        staging.mkdir()
        try:
            # Export tracked blobs ourselves: no hooks, filters, symlinks or archive extraction.
            for path, entry in sorted(self.files.items()):
                if entry["type"] != "blob" or entry.get("mode") == "120000":
                    continue
                parts = PurePosixPath(path).parts
                if any((
                    any(p in EXCLUDED_DIRS or p.startswith("build-") for p in parts),
                    any(path.startswith(prefix) for prefix in self.excluded_prefixes),
                    parts[-1] in REPORTS, parts[-1].endswith(".cdx.json"),
                )):
                    continue
                if "repository" in entry:
                    name = parts[-1]
                    is_manifest = any((
                        name in REMOTE_MANIFESTS,
                        name.startswith("requirements") and name.endswith(".txt"),
                        name.endswith((".csproj", ".nuspec", ".gemspec")),
                    ))
                    if not is_manifest:
                        continue
                destination = staging / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(self.read_file(path))
            scanned = json.loads(command([
                self.syft, "scan", "dir:" + str(staging),
                "--output", "cyclonedx-json@1.6",
            ]))
            # Syft also catalogs CI manifests as files; never publish workstation paths.
            scanned = json.loads(json.dumps(scanned).replace(
                json.dumps(str(staging))[1:-1], "tracked-source"
            ))
            if scanned.get("bomFormat") != "CycloneDX" or scanned.get("specVersion") != "1.6":
                raise EvidenceError("Syft must produce CycloneDX 1.6 (use Syft 1.55.0)")
            syft_root = scanned.get("metadata", {}).get("component", {}).get("bom-ref")
            for item in scanned.get("components", []):
                if not item.get("bom-ref"):
                    raise EvidenceError("Syft component is missing bom-ref")
                self.add(item)
                self.edge(self.root_ref, item["bom-ref"])
            for item in scanned.get("dependencies", []):
                parent = self.root_ref if item["ref"] == syft_root else item["ref"]
                for child in item.get("dependsOn", []):
                    self.edge(parent, self.root_ref if child == syft_root else child)
            self.bom["metadata"]["tools"] = scanned.get("metadata", {}).get("tools", {
                "components": [{"type": "application", "name": "syft"}],
            })
        finally:
            shutil.rmtree(staging)

    def generate(self, output_dir):
        entries = self.identity()
        self.inspect_tree(self.root_ref, entries)
        licenses = [
            path for path in entries if "/" not in path
            if re.match(r"^(LICENSE|COPYING)(?:[.-]|$)", path, re.I)
        ]
        if licenses:
            self.license_evidence(self.components[self.root_ref], licenses, entries)
        for declaration in self.config.get("references", []):
            if not isinstance(declaration, dict):
                raise EvidenceError("Invalid reference declaration")
            if any((
                set(declaration) - {"repository", "commit", "licenses", "role"},
                not {"repository", "commit", "licenses"} <= declaration.keys(),
            )):
                raise EvidenceError("Invalid reference declaration")
            repo = repository(declaration["repository"])
            commit = pin(declaration["commit"])
            tree, children = self.remote_tree(repo, commit)
            role = declaration.get("role", "reference-only")
            if role not in ("reference-only", "build-source"):
                raise EvidenceError("Invalid reference role")
            component = self.source_component(repo, commit, tree, role)
            files = {path: dict(item, repository=repo) for path, item in children.items()}
            self.license_evidence(component, declaration["licenses"], files)
            ref = self.add(component)
            prefix = "references/{}@{}/".format(repo, commit)
            if role == "reference-only":
                self.excluded_prefixes.append(prefix)
            else:
                self.edge(self.root_ref, ref)
            self.inspect_tree(ref, children, prefix, repo)
        unused = set(self.config.get("gitlinks", {})) - self.used_gitlinks
        if unused:
            raise EvidenceError("Declared gitlinks absent from immutable trees: " + ", ".join(sorted(unused)))
        for declaration in self.config.get("vendored", []):
            if not isinstance(declaration, dict) or set(declaration) != {
                    "path", "repository", "commit", "licenses", "evidence"}:
                raise EvidenceError("Invalid vendored declaration")
            path = safe_path(declaration["path"])
            unknown_origin = declaration["repository"] is None and declaration["commit"] is None
            repo = None if unknown_origin else repository(declaration["repository"])
            commit = None if unknown_origin else pin(declaration["commit"])
            if not isinstance(declaration["evidence"], list) or not declaration["evidence"]:
                raise EvidenceError("Vendored provenance evidence is mandatory: " + path)
            files = [name for name, item in self.files.items()
                     if (name == path or name.startswith(path + "/")) and item["type"] == "blob"]
            if not files:
                raise EvidenceError("Missing vendored source: " + path)
            component = {
                "type": "library", "name": path,
                "bom-ref": "vendored:" + path,
            }
            if not unknown_origin:
                component["version"] = commit
                component["externalReferences"] = [{
                    "type": "vcs", "url": "https://github.com/{}/tree/{}".format(repo, commit),
                }]
            self.license_evidence(component, declaration["licenses"], self.files)
            for name in declaration["evidence"]:
                self.read_file(safe_path(name))
            manifest = []
            for name in sorted(set(files + declaration["evidence"] + declaration["licenses"])):
                entry = self.files[name]
                if entry.get("mode") == "120000":
                    content = (self.read_remote(entry["repository"], entry)
                               if "repository" in entry else
                               git(self.root, "cat-file", "blob", entry["sha"]))
                    manifest.append({
                        "path": name, "sha256": sha256(content),
                        "kind": "symlink-target-blob-not-followed",
                    })
                else:
                    manifest.append({"path": name, "sha256": sha256(self.read_file(name))})
            property_value(component, "sbom:role", "declared-vendored-source")
            property_value(component, "sbom:source-manifest", json.dumps(manifest, sort_keys=True))
            property_value(component, "sbom:provenance-verification",
                           "unknown upstream origin" if unknown_origin else
                           "declared origin; local blob hashes do not establish upstream equivalence")
            self.edge(self.root_ref, self.add(component))
        for path in self.config.get("models", []):
            path = safe_path(path)
            content = self.read_file(path)
            if content.startswith(b"version https://git-lfs.github.com/spec/v1"):
                raise EvidenceError("Model evidence is only a Git LFS pointer, not model bytes: " + path)
            self.edge(self.root_ref, self.add({
                "type": "file", "name": path, "bom-ref": "model:" + path,
                "hashes": [{"alg": "SHA-256", "content": sha256(content)}],
                "properties": [{"name": "sbom:role", "value": "model-file"}],
            }))
        for index, declaration in enumerate(self.config.get("external_libraries", [])):
            if not isinstance(declaration, dict):
                raise EvidenceError("Invalid external_libraries declaration")
            if any((
                set(declaration) - {"name", "version", "evidence"},
                not {"name", "evidence"} <= declaration.keys(),
                not isinstance(declaration.get("name"), str),
                not isinstance(declaration.get("evidence"), list),
            )):
                raise EvidenceError("Invalid external_libraries declaration")
            if not declaration["name"].strip() or not declaration["evidence"]:
                raise EvidenceError("Invalid external_libraries declaration")
            evidence = [{"path": safe_path(path), "sha256": sha256(self.read_file(path))}
                        for path in declaration["evidence"]]
            component = {
                "type": "library", "name": declaration["name"],
                "bom-ref": "external-library:" + str(index),
                "properties": [
                    {"name": "sbom:role", "value": "conditional-build-runtime-requirement"},
                    {"name": "sbom:resolution", "value": "conditional; unresolved version"},
                    {"name": "sbom:declared-version", "value": str(declaration.get("version", "unresolved"))},
                    {"name": "sbom:evidence", "value": json.dumps(evidence, sort_keys=True)},
                ],
            }
            self.edge(self.root_ref, self.add(component))
        self.syft_scan(output_dir)
        self.validate_graph()

    def validate_graph(self):
        for parent, children in self.edges.items():
            if parent not in self.components or not children <= self.components.keys():
                raise EvidenceError("Dangling SBOM dependency reference: " + parent)

    def write(self, output_dir):
        root_ref = self.bom["metadata"].get("component", {}).get("bom-ref")
        self.bom["components"] = [
            item for ref, item in sorted(self.components.items()) if ref != root_ref
        ]
        self.bom["dependencies"] = [
            {"ref": ref, "dependsOn": sorted(children)}
            for ref, children in sorted(self.edges.items())
        ]
        self.bom["compositions"] = [{
            "aggregate": "unknown", **({"assemblies": [root_ref]} if root_ref else {}),
        }]
        self.bom["metadata"]["properties"] = [
            {"name": "sbom:scope", "value": SCOPE},
            {"name": "sbom:generation-status", "value": "failed" if self.errors else "success"},
            {"name": "sbom:generation-errors", "value": json.dumps(self.errors)},
        ]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "SBOM.cdx.json").write_text(
            json.dumps(self.bom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        lines = [
            "# Source SBOM", "", SCOPE, "",
            "Generation: **{}**".format("FAILED — DO NOT PUBLISH" if self.errors else "success"),
            "", "## Source identity", "",
        ]
        root = self.bom["metadata"].get("component", {})
        lines += ["{} `{}`".format(root.get("name", "unknown"), root.get("version", "unknown")), ""]
        lines += ["- {}: {}".format(p["name"], p["value"]) for p in root.get("properties", [])]
        lines += ["", "## Generation errors", ""]
        lines += ["- " + error for error in self.errors] or ["None."]
        lines += ["", "## Components and unresolved licenses", "",
                  "| Component | Version | Role | License |",
                  "| --- | --- | --- | --- |"]
        for item in self.components.values():
            props = {p["name"]: p["value"] for p in item.get("properties", [])}
            licenses = json.dumps(item.get("licenses", []), ensure_ascii=True)
            values = [item["name"], item.get("version", "unresolved"),
                      props.get("sbom:role", "Syft source/package discovery"),
                      props.get("sbom:license-resolution", licenses if licenses != "[]" else "unresolved")]
            lines.append("| " + " | ".join(
                str(value).replace("|", "\\|").replace("\n", " ") for value in values
            ) + " |")
        lines += ["", "License evidence paths/hashes, source manifests, model hashes and conditional",
                  "CMake declarations are recorded in SBOM.cdx.json. Declared upstream pins do not",
                  "prove vendored equivalence. No dependency installation or build was performed.", ""]
        (output_dir / "SBOM.md").write_text("\n".join(lines), encoding="utf-8")


def release_notes(body, tag):
    """Replace only this tool's documentation block, retaining all other release notes."""
    block = "\n".join([
        START_MARKER, "### Source SBOM",
        "[Readable report](../../releases/download/{}/SBOM.md) · "
        "[CycloneDX 1.6](../../releases/download/{}/SBOM.cdx.json)".format(
            quote(tag, safe=""), quote(tag, safe="")),
        "", SCOPE, END_MARKER,
    ])
    if START_MARKER in body:
        if body.count(START_MARKER) != 1 or body.count(END_MARKER) != 1:
            raise EvidenceError("Ambiguous SBOM release-notes markers")
        start, end = body.index(START_MARKER), body.index(END_MARKER)
        if end < start:
            raise EvidenceError("Malformed SBOM release-notes markers")
        return body[:start] + block + body[end + len(END_MARKER):]
    if END_MARKER in body:
        raise EvidenceError("Malformed SBOM release-notes markers")
    return body + ("\n\n" if body else "") + block + "\n"


def publish(repo, tag, output_dir):
    """Upload validated outputs and idempotently document them on an existing release."""
    repository(repo)
    bom = json.loads((output_dir / "SBOM.cdx.json").read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    source = bom["metadata"]["component"]
    source_props = {p["name"]: p["value"] for p in source["properties"]}
    if any((
        props.get("sbom:generation-status") != "success",
        source["name"] != repo,
        tag not in json.loads(source_props.get("sbom:release-tags", "[]")),
        bom.get("compositions", [{}])[0].get("aggregate") != "unknown",
    )):
        raise EvidenceError("Refusing to publish failed, mismatched or overclaimed source SBOM")
    endpoint = "repos/{}/releases/tags/{}".format(repo, quote(tag, safe=""))
    release = json.loads(command(["gh", "api", endpoint]))
    if release.get("draft"):
        raise EvidenceError("Refusing to publish assets to a draft release")
    # Do not replace a producer's stronger artifact-aware SBOM with this source-only one.
    if {"SBOM.cdx.json", "SBOM.md"} <= {a["name"] for a in release.get("assets", [])}:
        print("Existing complete SBOM asset pair preserved: " + tag)
        return
    remote = json.loads(command([
        "gh", "api", "repos/{}/commits/{}".format(repo, quote(tag, safe="")),
    ]))
    if remote["sha"] != source["version"]:
        raise EvidenceError("Release tag moved since generation; refusing publication")
    release_notes(release.get("body") or "", tag)  # Validate markers before uploading.
    command(["gh", "release", "upload", tag, "--repo", repo, "--clobber",
             str(output_dir / "SBOM.cdx.json"), str(output_dir / "SBOM.md")])
    # Read the body again after uploads so ordinary concurrent note edits are retained.
    release = json.loads(command(["gh", "api", endpoint]))
    notes = release_notes(release.get("body") or "", tag)
    command(["gh", "api", "--method", "PATCH",
             "repos/{}/releases/{}".format(repo, release["id"]), "-f", "body=" + notes])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("build/sbom"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--tag", help="Require this release tag to point to HEAD")
    parser.add_argument("--syft", default="syft", help="Syft executable (recommended: 1.55.0)")
    parser.add_argument("--publish", metavar="OWNER/REPO", help="Publish existing outputs; requires --tag")
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if args.publish:
        try:
            if not args.tag:
                raise EvidenceError("--publish requires --tag")
            publish(args.publish, args.tag, output)
            return 0
        except (EvidenceError, ValueError, KeyError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    inventory = Inventory(args.root, {}, args.syft, args.tag)
    try:
        config_path = args.config if args.config is not None else args.root / ".sbom.json"
        if args.config is not None and not config_path.is_file():
            raise EvidenceError("Explicit --config is missing: " + str(config_path))
        inventory.config = load_config(config_path)
        output.mkdir(parents=True, exist_ok=True)
        inventory.generate(output)
    except (EvidenceError, ValueError, KeyError, OSError) as exc:
        inventory.errors.append(str(exc))
        print(str(exc), file=sys.stderr)
    inventory.write(output)
    return 1 if inventory.errors else 0


if __name__ == "__main__":
    sys.exit(main())

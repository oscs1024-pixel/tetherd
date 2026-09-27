#!/usr/bin/env python3
import json
import pathlib
import sys
import urllib.parse


def purl(name: str, version: str) -> str:
    return f"pkg:cargo/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='')}"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: generate-cyclonedx.py <cargo-metadata.json> <output.json>", file=sys.stderr)
        return 2

    metadata_path = pathlib.Path(sys.argv[1])
    output_path = pathlib.Path(sys.argv[2])
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    packages = metadata.get("packages", [])
    by_id = {pkg["id"]: pkg for pkg in packages}
    root_id = (metadata.get("resolve") or {}).get("root")
    root = by_id.get(root_id)
    if root is None:
        print("cargo metadata does not contain a resolvable root package", file=sys.stderr)
        return 1

    refs = {
        pkg_id: purl(pkg["name"], pkg["version"])
        for pkg_id, pkg in by_id.items()
    }

    components = []
    for pkg_id, pkg in sorted(by_id.items(), key=lambda item: (item[1]["name"], item[1]["version"], item[0])):
        if pkg_id == root_id:
            continue
        component = {
            "type": "library",
            "bom-ref": refs[pkg_id],
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": refs[pkg_id],
        }
        if pkg.get("license"):
            component["licenses"] = [{"expression": pkg["license"]}]
        components.append(component)

    dependencies = []
    for node in (metadata.get("resolve") or {}).get("nodes", []):
        if node["id"] not in refs:
            continue
        depends_on = sorted(
            {
                refs[dep_id]
                for dep_id in node.get("dependencies", [])
                if dep_id in refs
            }
        )
        dependencies.append({"ref": refs[node["id"]], "dependsOn": depends_on})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": refs[root_id],
                "name": root["name"],
                "version": root["version"],
                "purl": refs[root_id],
            }
        },
        "components": components,
        "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(bom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a read-only REST operation inventory from the checked-in OpenAPI files.

Requires PyYAML 6.x. Run from any directory with Python 3:
    python docs/ps5-port/inventory-rest-operations.py [--check]
This inventories specification declarations only, not implementation coverage.
"""
import argparse
import csv
import io
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required (for example, use Debian WSL's python3-yaml).")

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "api" / "openapi"
OUTPUT = ROOT / "docs" / "ps5-port" / "rest-operation-index.csv"
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def read_yaml(path):
    with path.open(encoding="utf-8") as file:
        value = yaml.load(file, Loader=UniqueLoader)
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not an object")
    return value


def resolve_path_ref(ref, documents):
    if not isinstance(ref, str) or "#" not in ref:
        raise ValueError(f"unsupported path reference: {ref!r}")
    filename, pointer = ref.split("#", 1)
    path = (SPEC / filename).resolve()
    if not path.is_relative_to(SPEC.resolve()) or not path.is_file():
        raise ValueError(f"invalid reference path: {ref!r}")
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {ref!r}")
    if path not in documents:
        documents[path] = read_yaml(path)
    value = documents[path]
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise ValueError(f"unresolved reference: {ref!r}")
        value = value[token]
    if not isinstance(value, dict):
        raise ValueError(f"path reference is not an object: {ref!r}")
    return value


def extract():
    root = read_yaml(SPEC / "common.yaml")
    paths = root.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("common.yaml has no paths")
    docs = {}
    rows = []
    ids = set()
    for path, entry in paths.items():
        if not isinstance(entry, dict) or set(entry) != {"$ref"}:
            raise ValueError(f"path {path!r} must be reviewed: expected one external reference")
        ref = entry["$ref"]
        resolved = resolve_path_ref(ref, docs)
        methods = [(name, value) for name, value in resolved.items() if name.lower() in METHODS]
        if not methods:
            raise ValueError(f"no operations found for {path}")
        for method, operation in methods:
            if not isinstance(operation, dict) or not isinstance(operation.get("operationId"), str):
                raise ValueError(f"missing operationId on {method} {path}")
            op_id = operation["operationId"]
            if op_id in ids:
                raise ValueError(f"duplicate operationId: {op_id}")
            ids.add(op_id)
            security = operation.get("security", root.get("security"))
            rows.append({
                "operation_id": op_id, "method": method.upper(), "path": path,
                "source_ref": ref, "tags": json.dumps(operation.get("tags", []), ensure_ascii=False, separators=(",", ":")),
                "declared_security": json.dumps(security, ensure_ascii=False, separators=(",", ":")),
                "declared_responses": ",".join(str(k) for k in operation.get("responses", {})),
            })
    # Independently compare against the checked-in bundled spec. This detects stale bundles
    # and extraction gaps, but is not a substitute for running the upstream bundle task.
    bundle = read_yaml(ROOT / "api" / "openapi.yaml")
    bundled = {(method.upper(), path, operation.get("operationId"))
               for path, item in bundle.get("paths", {}).items()
               for method, operation in item.items()
               if method.lower() in METHODS and isinstance(operation, dict)}
    indexed = {(r["method"], r["path"], r["operation_id"]) for r in rows}
    if bundled != indexed:
        raise ValueError(f"bundle/source mismatch; source-only={sorted(indexed-bundled)[:5]}, bundle-only={sorted(bundled-indexed)[:5]}")
    return sorted(rows, key=lambda r: (r["path"], r["method"])), len(paths), len(docs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the generated inventory is stale")
    args = parser.parse_args()
    rows, path_count, doc_count = extract()
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    rendered = buffer.getvalue()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            sys.exit("Inventory missing or stale; regenerate it.")
    else:
        OUTPUT.write_text(rendered, encoding="utf-8", newline="")
    print(f"{len(rows)} operations, {path_count} paths, {doc_count} domain files; source and bundle agree")


if __name__ == "__main__":
    main()

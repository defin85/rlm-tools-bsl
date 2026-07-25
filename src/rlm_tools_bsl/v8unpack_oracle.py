"""Reproducible XML↔v8unpack metadata oracle."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import uuid

from rlm_tools_bsl.bsl_index import (
    _collect_metadata_tables,
    _collect_object_synonyms,
    _iter_metadata_xml_files,
)
from rlm_tools_bsl.bsl_xml_parsers import canonicalize_type_ref
from rlm_tools_bsl.v8unpack_metadata import (
    STRUCTURAL_CONTRACT,
    V8UNPACK_DIAGNOSTIC_ROLES,
    V8UNPACK_METADATA_CONTRACTS,
    V8UNPACK_METADATA_IDENTITY_MAP,
    builtin_type_contract,
    classify_v8unpack_json_path,
    collect_v8unpack_metadata,
    generated_type_coverage_contract,
    generated_type_contract,
)

SCHEMA_VERSION = 1
COMPARATOR_VERSION = 1
FORBIDDEN_DIAGNOSTICS = frozenset(
    {
        "unresolved_metadata_uuid",
        "missing_required_json",
        "malformed_required_json",
        "unsupported_header_shape",
    }
)
STRUCTURAL_CATEGORIES = frozenset(
    {
        "Catalogs",
        "Documents",
        "InformationRegisters",
        "AccumulationRegisters",
        "AccountingRegisters",
        "ChartsOfCharacteristicTypes",
    }
)
IDENTITY_CATEGORIES = frozenset(category for category, _head in V8UNPACK_METADATA_IDENTITY_MAP.values())
PROJECTIONS = {
    "object_attributes": 7,
    "object_synonyms": 3,
    "metadata_references": 5,
    "metadata_objects": 3,
    "metadata_type_ids": 3,
}


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def tree_sha256(root: str | Path, paths: set[str]) -> str:
    base = Path(root)
    rows = [[path, _sha256((base / path).read_bytes())] for path in sorted(paths)]
    return _sha256(_json_bytes(rows))


def projection_summary(rows: list[tuple]) -> dict:
    canonical = sorted((list(row) for row in rows), key=lambda row: _json_bytes(row))
    counts = Counter(tuple(row) for row in canonical)
    return {
        "total": len(canonical),
        "unique": len(counts),
        "duplicate": len(canonical) - len(counts),
        "sha256": _sha256(_json_bytes(canonical)),
    }


def _delta(left: list[tuple], right: list[tuple]) -> dict:
    left_counter, right_counter = Counter(left), Counter(right)

    def rows(counter: Counter) -> list[dict]:
        return [
            {"row": list(row), "count": count}
            for row, count in sorted(counter.items(), key=lambda item: _json_bytes(item[0]))
        ]

    return {"missing": rows(left_counter - right_counter), "extra": rows(right_counter - left_counter)}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


def _xml_identity(
    root: Path,
    read_paths: set[str],
    object_version: str,
) -> tuple[list[tuple], list[tuple]]:
    head_by_category = {category: head for category, head in V8UNPACK_METADATA_IDENTITY_MAP.values()}
    kind_by_category = {category: kind for kind, (category, _head) in V8UNPACK_METADATA_IDENTITY_MAP.items()}
    objects: list[tuple] = []
    type_ids: list[tuple] = []
    for category, object_name, rel in _iter_metadata_xml_files(str(root), categories=IDENTITY_CATEGORIES):
        if len(Path(rel).parts) != 2:
            continue
        path = root / rel
        tree = ET.parse(path)
        read_paths.add(rel)
        owner_tag = head_by_category[category]
        owner = next((node for node in tree.iter() if _local(node.tag) == owner_tag), None)
        if owner is None or not owner.attrib.get("uuid"):
            raise ValueError(f"missing {owner_tag} uuid in {rel}")
        objects.append((category, object_name, owner.attrib["uuid"].lower(), rel))
        internal = next((node for node in owner if _local(node.tag) == "InternalInfo"), None)
        for generated in (
            (node for node in internal if _local(node.tag) == "GeneratedType") if internal is not None else ()
        ):
            name = generated.attrib.get("name", "")
            type_form = name.split(".", 1)[0]
            positions, id_keys = generated_type_contract(object_version, kind_by_category[category])
            allowed_forms = {form for _position, form in positions} | {form for _key, form in id_keys}
            if type_form not in allowed_forms:
                continue
            type_id = next(
                ((node.text or "").strip() for node in generated if _local(node.tag) == "TypeId"),
                "",
            )
            canonical = canonicalize_type_ref(
                f"{head_by_category[category]}.{object_name}",
                fold_case=False,
            )
            if "." not in name or not type_id or not canonical:
                raise ValueError(f"invalid GeneratedType in {rel}")
            type_ids.append((type_id.lower(), canonical, type_form, rel))
    return objects, type_ids


def collect_xml(
    root: str | Path,
    object_version: str,
) -> tuple[dict[str, list[tuple]], set[str]]:
    base = Path(root).resolve()
    read_paths: set[str] = set()
    tables = _collect_metadata_tables(
        str(base),
        collect_es=False,
        collect_sj=False,
        collect_fo=False,
        collect_enums=False,
        collect_subs=False,
        collect_http=False,
        collect_ws=False,
        collect_xdto=False,
        collect_attrs_categories=set(STRUCTURAL_CATEGORIES),
        collect_exchange_plans=False,
        collect_defined_types=False,
        collect_pvh_types=False,
        collect_metadata_refs_categories=set(STRUCTURAL_CATEGORIES),
        read_paths=read_paths,
    )
    objects, type_ids = _xml_identity(base, read_paths, object_version)
    return {
        "object_attributes": [row[:7] for row in tables["object_attributes"]],
        "object_synonyms": [
            row[:3]
            for row in _collect_object_synonyms(str(base), categories=STRUCTURAL_CATEGORIES, read_paths=read_paths)
        ],
        "metadata_references": [row[:5] for row in tables["metadata_references"] if row[3] == "attribute_type"],
        "metadata_objects": [row[:3] for row in objects],
        "metadata_type_ids": [row[:3] for row in type_ids],
    }, read_paths


def collect_json(root: str | Path) -> tuple[dict[str, list[tuple]], object]:
    result = collect_v8unpack_metadata(root)
    if result.status == "unsupported":
        raise ValueError(f"unsupported JSON source: {result.diagnostics}")
    for table in ("metadata_objects", "metadata_type_ids"):
        for row in getattr(result, table):
            role = classify_v8unpack_json_path(root, row[-1])
            if role is None or role.role != "main":
                raise ValueError(f"invalid JSON source path: {row[-1]}")
    for row in result.object_attributes:
        role = classify_v8unpack_json_path(root, row[-1])
        if role is None or role.role != "main" or role.object_name != row[0]:
            raise ValueError(f"invalid attribute path: {row[-1]}")
    for row in result.object_synonyms:
        role = classify_v8unpack_json_path(root, row[-1])
        if role is None or role.role != "main" or role.object_name != row[0]:
            raise ValueError(f"invalid synonym path: {row[-1]}")
    if any(row[-1] is not None for row in result.metadata_references):
        raise ValueError("JSON metadata reference line must be null")
    for row in result.metadata_references:
        role = classify_v8unpack_json_path(root, row[-2])
        if role is None or role.role != "main" or role.object_name != row[0]:
            raise ValueError(f"invalid reference path: {row[-2]}")
    return {
        "object_attributes": [row[:7] for row in result.object_attributes],
        "object_synonyms": [row[:3] for row in result.object_synonyms],
        "metadata_references": [row[:5] for row in result.metadata_references],
        "metadata_objects": [row[:3] for row in result.metadata_objects],
        "metadata_type_ids": [row[:3] for row in result.metadata_type_ids],
    }, result


def compare(
    *,
    xml_root: str,
    json_root: str,
    cf_path: str,
    platform_version: str,
    v8unpack_path: str,
    commands: list[str],
) -> tuple[dict, dict]:
    json_tables, json_result = collect_json(json_root)
    xml, xml_paths = collect_xml(xml_root, json_result.object_version)
    projections = {}
    zero_delta = True
    for name in PROJECTIONS:
        delta = _delta(xml[name], json_tables[name])
        equal = not delta["missing"] and not delta["extra"]
        zero_delta &= equal
        projections[name] = {
            "xml": projection_summary(xml[name]),
            "json": projection_summary(json_tables[name]),
            "equal": equal,
            **delta,
        }
    expected_generated = sorted(
        [kind, str(source), type_form]
        for kind in V8UNPACK_METADATA_IDENTITY_MAP
        for source, type_form in generated_type_coverage_contract(json_result.object_version, kind)
    )
    coverage = {
        "structural": sorted([kind, row_kind] for kind, row_kind in json_result.structural_coverage),
        "type_shapes": sorted(json_result.type_shape_coverage),
        "generated_types": sorted([*row] for row in json_result.generated_type_coverage),
        "builtin_type_uuids": sorted(json_result.builtin_type_coverage),
        "missing_generated_types": sorted(
            row for row in expected_generated if tuple(row) not in json_result.generated_type_coverage
        ),
        "missing_builtin_type_uuids": sorted(
            set(builtin_type_contract(json_result.object_version)) - json_result.builtin_type_coverage
        ),
    }
    forbidden = sorted(
        diagnostic["code"] for diagnostic in json_result.diagnostics if diagnostic["code"] in FORBIDDEN_DIAGNOSTICS
    )
    assertions = {}
    characteristic_rows = [
        list(row) for row in json_tables["object_attributes"] if row[0] == "Характеристики" and row[2] == "Значение"
    ]
    if json_result.object_version == "803" and characteristic_rows:
        expected_row = [
            "Характеристики",
            "InformationRegisters",
            "Значение",
            "Значение",
            "[]",
            "resource",
            None,
        ]
        characteristic_references = [
            list(row)
            for row in json_tables["metadata_references"]
            if row[0] == "Характеристики" and "Значение" in row[4]
        ]
        if characteristic_rows != [expected_row] or characteristic_references:
            raise ValueError("803 TypeSet assertion failed")
        assertions["information_register_characteristic_typeset"] = {
            "row": expected_row,
            "references": [],
        }
    report_payload = {
        "schema_version": SCHEMA_VERSION,
        "comparator_version": COMPARATOR_VERSION,
        "projections": projections,
        "coverage": coverage,
        "status": json_result.status,
        "identity": {
            "total": json_result.identity_total,
            "indexed": json_result.identity_indexed,
            "failed": json_result.identity_total - json_result.identity_indexed,
        },
        "structural": {
            "total": json_result.structural_total,
            "indexed": json_result.structural_indexed,
            "failed": json_result.structural_total - json_result.structural_indexed,
        },
        "diagnostics": json_result.diagnostics,
        "unsupported_count": sum(diagnostic["count"] for diagnostic in json_result.diagnostics),
        "forbidden_diagnostics": forbidden,
        "assertions": assertions,
        "zero_delta": zero_delta,
    }
    report = {**report_payload, "content_sha256": _sha256(_json_bytes(report_payload))}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "comparator_version": COMPARATOR_VERSION,
        "cf_sha256": _sha256(Path(cf_path).read_bytes()),
        "commands": commands,
        "platform_version": platform_version,
        "v8unpack_version": json_result.producer_version,
        "v8unpack_sha256": _sha256(Path(v8unpack_path).read_bytes()),
        "root_object_version": json_result.object_version,
        "owner_object_versions": sorted(
            {
                version
                for path in json_result.read_paths
                if path != "Configuration.json" and not path.endswith(".id.json")
                for version in [json.loads((Path(json_root) / path).read_text(encoding="utf-8-sig")).get("obj_version")]
                if isinstance(version, str)
            }
        ),
        "xml_input_tree_sha256": tree_sha256(xml_root, xml_paths),
        "json_input_tree_sha256": tree_sha256(json_root, json_result.read_paths),
        "projections": {name: {"xml": value["xml"], "json": value["json"]} for name, value in projections.items()},
        "status": json_result.status,
        "identity": report_payload["identity"],
        "structural": report_payload["structural"],
        "diagnostics": json_result.diagnostics,
        "unsupported_count": report_payload["unsupported_count"],
        "coverage": coverage,
        "forbidden_diagnostics": forbidden,
        "assertions": assertions,
        "report_sha256": report["content_sha256"],
        "zero_delta": zero_delta,
    }
    return manifest, report


def _verify_manifest(path: str | Path) -> dict:
    manifest_path = Path(path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema")
    if manifest.get("comparator_version") != COMPARATOR_VERSION:
        raise ValueError("unsupported comparator version")
    if not manifest.get("zero_delta"):
        raise ValueError("manifest does not record a zero delta")
    if manifest.get("forbidden_diagnostics"):
        raise ValueError("manifest contains forbidden diagnostics")
    object_version = manifest.get("root_object_version")
    if manifest.get("v8unpack_version") not in V8UNPACK_METADATA_CONTRACTS.get(object_version, ()):
        raise ValueError("manifest records an unsupported version pair")
    if not manifest.get("commands") or not isinstance(manifest.get("platform_version"), str):
        raise ValueError("missing reproduction commands")
    if not all(isinstance(version, str) for version in manifest.get("owner_object_versions", [])):
        raise ValueError("invalid owner object versions")
    for name in ("identity", "structural"):
        counters = manifest.get(name, {})
        if counters.get("failed") != counters.get("total", 0) - counters.get("indexed", 0):
            raise ValueError(f"invalid counters: {name}")
    diagnostics = manifest.get("diagnostics", [])
    for diagnostic in diagnostics:
        code = diagnostic.get("code")
        role = diagnostic.get("role")
        roles = V8UNPACK_DIAGNOSTIC_ROLES.get(code)
        if roles is None or (
            role not in roles and not (code == "unsupported_header_facet" and isinstance(role, str) and _is_uuid(role))
        ):
            raise ValueError("invalid diagnostic code or role")
        if (
            not isinstance(diagnostic.get("count"), int)
            or isinstance(diagnostic.get("count"), bool)
            or diagnostic["count"] <= 0
        ):
            raise ValueError("invalid diagnostic count")
        examples = diagnostic.get("examples")
        if (
            not isinstance(examples, list)
            or not examples
            or len(examples) > 5
            or len(examples) > diagnostic["count"]
            or examples != sorted(set(examples))
            or not all(isinstance(example, str) for example in examples)
        ):
            raise ValueError("invalid diagnostic examples")
    if manifest.get("unsupported_count") != sum(diagnostic.get("count", 0) for diagnostic in diagnostics):
        raise ValueError("invalid unsupported count")
    if diagnostics != sorted(diagnostics, key=lambda diagnostic: (diagnostic.get("code"), diagnostic.get("role"))):
        raise ValueError("diagnostics are not deterministic")
    for name in PROJECTIONS:
        projection = manifest.get("projections", {}).get(name, {})
        if projection.get("xml") != projection.get("json"):
            raise ValueError(f"projection mismatch: {name}")
        summary = projection.get("xml", {})
        if summary.get("duplicate") != summary.get("total", 0) - summary.get("unique", 0):
            raise ValueError(f"invalid summary: {name}")
        if len(summary.get("sha256", "")) != 64:
            raise ValueError(f"invalid projection hash: {name}")
    for key in (
        "cf_sha256",
        "v8unpack_sha256",
        "xml_input_tree_sha256",
        "json_input_tree_sha256",
        "report_sha256",
    ):
        if len(manifest.get(key, "")) != 64:
            raise ValueError(f"invalid hash: {key}")
    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("missing coverage")
    required_shapes = {"primitive", "reference", "composite"}
    if not required_shapes.issubset(coverage.get("type_shapes", [])):
        raise ValueError("incomplete type-shape coverage")
    observed_generated = {tuple(row) for row in coverage.get("generated_types", [])}
    expected_generated = {
        (kind, source, type_form)
        for kind in V8UNPACK_METADATA_IDENTITY_MAP
        for source, type_form in generated_type_coverage_contract(object_version, kind)
    }
    if coverage.get("missing_generated_types") != sorted([*row] for row in expected_generated - observed_generated):
        raise ValueError("invalid missing generated-type coverage")
    observed_builtin = set(coverage.get("builtin_type_uuids", []))
    if coverage.get("missing_builtin_type_uuids") != sorted(
        set(builtin_type_contract(object_version)) - observed_builtin
    ):
        raise ValueError("invalid missing builtin UUID coverage")
    report_file = manifest.get("report_file")
    if not isinstance(report_file, str) or Path(report_file).name != report_file:
        raise ValueError("invalid report file")
    report = json.loads((manifest_path.parent / report_file).read_text(encoding="utf-8"))
    report_payload = {key: value for key, value in report.items() if key != "content_sha256"}
    report_sha256 = _sha256(_json_bytes(report_payload))
    if report.get("content_sha256") != report_sha256 or manifest["report_sha256"] != report_sha256:
        raise ValueError("report hash mismatch")
    for key in (
        "schema_version",
        "comparator_version",
        "coverage",
        "status",
        "identity",
        "structural",
        "diagnostics",
        "unsupported_count",
        "forbidden_diagnostics",
        "assertions",
        "zero_delta",
    ):
        if report.get(key) != manifest.get(key):
            raise ValueError(f"report content mismatch: {key}")
    for name in PROJECTIONS:
        report_projection = report["projections"][name]
        if (
            report_projection.get("xml") != manifest["projections"][name].get("xml")
            or report_projection.get("json") != manifest["projections"][name].get("json")
            or not report_projection.get("equal")
            or report_projection.get("missing")
            or report_projection.get("extra")
        ):
            raise ValueError(f"report projection mismatch: {name}")
    return manifest


def verify_manifests(paths: list[str | Path]) -> None:
    manifests = [_verify_manifest(path) for path in paths]
    for object_version in {manifest["root_object_version"] for manifest in manifests}:
        version_manifests = [manifest for manifest in manifests if manifest["root_object_version"] == object_version]
        generated = {tuple(row) for manifest in version_manifests for row in manifest["coverage"]["generated_types"]}
        expected_generated = {
            (kind, str(source), type_form)
            for kind in V8UNPACK_METADATA_IDENTITY_MAP
            for source, type_form in generated_type_coverage_contract(object_version, kind)
        }
        if expected_generated - generated:
            raise ValueError(f"incomplete generated-type coverage for {object_version}")
        builtin = {value for manifest in version_manifests for value in manifest["coverage"]["builtin_type_uuids"]}
        if set(builtin_type_contract(object_version)) - builtin:
            raise ValueError(f"incomplete builtin UUID coverage for {object_version}")
    manifests_803 = [manifest for manifest in manifests if manifest["root_object_version"] == "803"]
    if manifests_803:
        if not any(
            "information_register_characteristic_typeset" in manifest.get("assertions", {})
            for manifest in manifests_803
        ):
            raise ValueError("missing 803 TypeSet assertion")
        structural = {tuple(row) for manifest in manifests_803 for row in manifest["coverage"]["structural"]}
        expected_structural = {
            (kind, "ts_attribute" if row_kind == "tabular_section" else row_kind)
            for kind, groups in STRUCTURAL_CONTRACT.items()
            for _index, _tag, row_kind in groups
        }
        if expected_structural - structural:
            raise ValueError("incomplete 803 structural coverage")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    compare_parser = sub.add_parser("compare")
    for option in ("xml-root", "json-root", "cf", "platform-version", "v8unpack", "manifest", "report"):
        compare_parser.add_argument(f"--{option}", required=True)
    compare_parser.add_argument("--command", action="append", default=[])
    compare_parser.add_argument("--verify-existing", action="store_true")
    manifest_parser = sub.add_parser("manifest")
    manifest_sub = manifest_parser.add_subparsers(dest="manifest_action", required=True)
    verify_parser = manifest_sub.add_parser("verify")
    verify_parser.add_argument("path", nargs="+")
    args = parser.parse_args(argv)
    if args.action == "manifest":
        verify_manifests(args.path)
        return 0
    manifest, report = compare(
        xml_root=args.xml_root,
        json_root=args.json_root,
        cf_path=args.cf,
        platform_version=args.platform_version,
        v8unpack_path=args.v8unpack,
        commands=args.command,
    )
    manifest["report_file"] = Path(args.report).name
    if args.verify_existing:
        saved_manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        saved_report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        if saved_manifest != manifest or saved_report != report:
            raise ValueError("live oracle result differs from stored evidence")
        _verify_manifest(args.manifest)
        return 0
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(args.manifest).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if report["zero_delta"] and not report["forbidden_diagnostics"] else 1


if __name__ == "__main__":
    sys.exit(main())

"""Reproducible XML↔v8unpack metadata oracle."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
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
    V8UNPACK_FACET_CONTRACT_802,
    V8UNPACK_DIAGNOSTIC_ROLES,
    V8UNPACK_METADATA_CONTRACTS,
    V8UNPACK_METADATA_IDENTITY_MAP,
    builtin_type_contract,
    classify_v8unpack_json_path,
    collect_v8unpack_metadata,
    generated_type_coverage_contract,
    generated_type_contract,
)

SCHEMA_VERSION = 2
COMPARATOR_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = {1, SCHEMA_VERSION}
SUPPORTED_COMPARATOR_VERSIONS = {1, COMPARATOR_VERSION}
FORM_MANIFEST_SCHEMA = "v8unpack_forms_802_v2"
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
        "facets": {
            "total": json_result.facet_total,
            "supported": json_result.facet_supported,
            "unsupported": json_result.facet_total - json_result.facet_supported,
            "inventory": json_result.facets,
        },
        "diagnostics": json_result.diagnostics,
        "unsupported_count": json_result.unsupported_count,
        "diagnostic_groups_total": json_result.diagnostic_groups_total,
        "diagnostics_truncated": json_result.diagnostic_groups_total > len(json_result.diagnostics),
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
        "facets": report_payload["facets"],
        "diagnostics": json_result.diagnostics,
        "unsupported_count": report_payload["unsupported_count"],
        "diagnostic_groups_total": report_payload["diagnostic_groups_total"],
        "diagnostics_truncated": report_payload["diagnostics_truncated"],
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
    schema_version = manifest.get("schema_version")
    comparator_version = manifest.get("comparator_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("unsupported manifest schema")
    if comparator_version not in SUPPORTED_COMPARATOR_VERSIONS:
        raise ValueError("unsupported comparator version")
    if schema_version != comparator_version:
        raise ValueError("manifest schema/comparator mismatch")
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
    if schema_version >= 2:
        facets = manifest.get("facets", {})
        if facets.get("unsupported") != facets.get("total", 0) - facets.get("supported", 0):
            raise ValueError("invalid counters: facets")
        inventory = facets.get("inventory")
        if not isinstance(inventory, list) or sum(row.get("count", 0) for row in inventory) != facets.get("total"):
            raise ValueError("invalid facet inventory")
        facet_keys = [
            (
                row.get("family"),
                row.get("header_index"),
                row.get("tag"),
                row.get("classification"),
                row.get("semantic"),
                row.get("projection"),
                row.get("supported"),
            )
            for row in inventory
        ]
        if facet_keys != sorted(facet_keys, key=lambda key: tuple(str(value) for value in key)):
            raise ValueError("facet inventory is not deterministic")
        if len(facet_keys) != len(set(facet_keys)):
            raise ValueError("duplicate facet inventory row")
        for row in inventory:
            key = (row.get("family"), row.get("header_index"), row.get("tag"))
            classification = row.get("classification")
            supported = row.get("supported")
            count = row.get("count")
            owners = row.get("owners")
            examples = row.get("examples")
            if classification not in {"core", "projected", "informational", "blocked"}:
                raise ValueError("invalid facet classification")
            if not isinstance(supported, bool):
                raise ValueError("invalid facet support")
            if supported and (classification not in {"core", "projected"} or not row.get("projection")):
                raise ValueError("facet support lacks a target projection")
            contract = V8UNPACK_FACET_CONTRACT_802.get(key) if object_version == "802" else None
            actual = (
                classification,
                row.get("semantic"),
                row.get("projection"),
                supported,
            )
            if contract is not None:
                if contract != actual:
                    raise ValueError("facet classification differs from paired coverage")
            elif actual != ("blocked", "Unknown", None, False):
                raise ValueError("unknown facet is not blocked")
            if supported and contract != (
                row.get("classification"),
                row.get("semantic"),
                row.get("projection"),
                True,
            ):
                raise ValueError("facet support lacks paired coverage")
            if classification in {"informational", "blocked"} and supported:
                raise ValueError("non-projected facet marked supported")
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or count <= 0
                or not isinstance(owners, int)
                or isinstance(owners, bool)
                or not 0 < owners <= count
                or not isinstance(examples, list)
                or not examples
                or len(examples) > min(5, owners)
                or examples != sorted(set(examples))
                or not all(isinstance(example, str) for example in examples)
            ):
                raise ValueError("invalid facet evidence")
    diagnostics = manifest.get("diagnostics", [])
    for diagnostic in diagnostics:
        code = diagnostic.get("code")
        role = diagnostic.get("role")
        roles = V8UNPACK_DIAGNOSTIC_ROLES.get(code)
        facet_role = (
            code in {"unsupported_header_facet", "supported_header_facet"}
            and isinstance(role, str)
            and (_is_uuid(role) or any(role == key[2] for key in V8UNPACK_FACET_CONTRACT_802))
        )
        if roles is None or (role not in roles and not facet_role):
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
    visible_unsupported = sum(
        diagnostic.get("count", 0) for diagnostic in diagnostics if diagnostic.get("code") != "supported_header_facet"
    )
    if schema_version == 1:
        if manifest.get("unsupported_count") != visible_unsupported:
            raise ValueError("invalid unsupported count")
    else:
        groups_total = manifest.get("diagnostic_groups_total")
        truncated = manifest.get("diagnostics_truncated")
        if (
            not isinstance(groups_total, int)
            or groups_total < len(diagnostics)
            or len(diagnostics) != min(groups_total, 50)
            or truncated != (groups_total > len(diagnostics))
            or visible_unsupported > manifest.get("unsupported_count", -1)
            or (not truncated and visible_unsupported != manifest.get("unsupported_count"))
        ):
            raise ValueError("invalid unsupported diagnostics")
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
        "diagnostic_groups_total",
        "diagnostics_truncated",
        "forbidden_diagnostics",
        "assertions",
        "zero_delta",
    ):
        if report.get(key) != manifest.get(key):
            raise ValueError(f"report content mismatch: {key}")
    if schema_version >= 2 and report.get("facets") != manifest.get("facets"):
        raise ValueError("report content mismatch: facets")
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


def verify_metadata_inventory_manifest(path: str | Path) -> dict:
    inventory_path = Path(path)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    payload = dict(inventory)
    content_sha256 = payload.pop("content_sha256", "")
    if content_sha256 != _sha256(_json_bytes(payload)):
        raise ValueError("metadata inventory content hash mismatch")
    if inventory.get("schema") != "v8unpack_metadata_inventory_v1":
        raise ValueError("unsupported metadata inventory schema")
    evidence = inventory.get("evidence", {})
    paired_file = evidence.get("paired_manifest_file")
    if not isinstance(paired_file, str) or Path(paired_file).name != paired_file:
        raise ValueError("invalid paired metadata manifest")
    paired = _verify_manifest(inventory_path.parent / paired_file)
    if (
        evidence.get("paired_cf_sha256") != paired.get("cf_sha256")
        or evidence.get("reexport_cf_sha256") != paired.get("cf_sha256")
        or evidence.get("paired_xml_input_tree_sha256") != paired.get("xml_input_tree_sha256")
        or evidence.get("paired_json_input_tree_sha256") != paired.get("json_input_tree_sha256")
        or evidence.get("platform_version") != paired.get("platform_version")
        or not isinstance(evidence.get("reexport_command"), str)
        or "/DumpCfg" not in evidence["reexport_command"]
        or not evidence.get("resolution")
    ):
        raise ValueError("metadata inventory paired evidence mismatch")
    current = inventory.get("current", {})
    baseline = inventory.get("baseline", {})
    facets = inventory.get("facets")
    facet_total = sum(row.get("count", 0) for row in facets) if isinstance(facets, list) else -1
    facet_supported = (
        sum(row.get("count", 0) for row in facets if row.get("supported")) if isinstance(facets, list) else -1
    )
    if (
        not isinstance(facets, list)
        or baseline
        != {
            "identity": {"total": 2417, "indexed": 2417, "failed": 0},
            "structural": {"total": 689, "indexed": 130, "failed": 559},
            "unsupported_count": 1787,
        }
        or facet_total != baseline.get("unsupported_count")
        or facet_total != current.get("facets", {}).get("total")
        or facet_supported != current.get("facets", {}).get("supported")
        or facet_total - facet_supported != current.get("facets", {}).get("unsupported")
        or current.get("unsupported_count") != current.get("facets", {}).get("unsupported")
        or current.get("status") != ("partial" if current.get("unsupported_count") else "complete")
        or current.get("facets", {}).get("unsupported")
        != current.get("facets", {}).get("total", 0) - current.get("facets", {}).get("supported", 0)
    ):
        raise ValueError("invalid metadata facet inventory")
    for row in facets:
        count, owners, examples = row.get("count"), row.get("owners"), row.get("examples")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            or not isinstance(owners, int)
            or isinstance(owners, bool)
            or not 0 < owners <= count
            or not isinstance(examples, list)
            or not examples
            or len(examples) > min(5, owners)
            or examples != sorted(set(examples))
        ):
            raise ValueError("invalid metadata facet group")
    return inventory


def verify_metadata_inventory(path: str | Path, root: str | Path) -> dict:
    inventory = verify_metadata_inventory_manifest(path)
    evidence = inventory["evidence"]
    result = collect_v8unpack_metadata(root)
    current = inventory.get("current", {})
    expected = {
        "identity": {
            "total": result.identity_total,
            "indexed": result.identity_indexed,
            "failed": result.identity_total - result.identity_indexed,
        },
        "structural": {
            "total": result.structural_total,
            "indexed": result.structural_indexed,
            "failed": result.structural_total - result.structural_indexed,
        },
        "facets": {
            "total": result.facet_total,
            "supported": result.facet_supported,
            "unsupported": result.facet_total - result.facet_supported,
        },
        "unsupported_count": result.unsupported_count,
        "status": result.status,
    }
    if current != expected or inventory.get("facets") != result.facets:
        raise ValueError("live metadata inventory differs from manifest")
    if evidence.get("active_json_input_tree_sha256") != tree_sha256(root, result.read_paths):
        raise ValueError("metadata inventory JSON tree hash mismatch")
    return inventory


def verify_form_manifest(path: str | Path) -> dict:
    """Verify the compact, self-contained v8unpack form evidence manifest."""
    manifest_path = Path(path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != FORM_MANIFEST_SCHEMA:
        raise ValueError("unsupported form manifest schema")
    payload = dict(manifest)
    content_sha256 = payload.pop("content_sha256", "")
    if content_sha256 != _sha256(_json_bytes(payload)):
        raise ValueError("form manifest content hash mismatch")
    hashes = manifest.get("sha256", {})
    if not hashes or not all(isinstance(value, str) and len(value) == 64 for value in hashes.values()):
        raise ValueError("invalid form manifest hashes")
    repo_root = manifest_path.resolve().parents[3]
    for key, rel_path in (
        ("probe_script", "tools/v8unpack_form_probe/run.sh"),
        ("probe_verifier", "tools/v8unpack_form_probe/verify.py"),
        ("probe_matrix", "tools/v8unpack_form_probe/matrix.py"),
    ):
        if hashes.get(key) != _sha256((repo_root / rel_path).read_bytes()):
            raise ValueError(f"form manifest hash mismatch: {key}")
    fixture_root = repo_root / "tools/v8unpack_form_probe/fixture"
    fixture_paths = {item.relative_to(fixture_root).as_posix() for item in fixture_root.rglob("*") if item.is_file()}
    if hashes.get("probe_fixture_tree") != tree_sha256(fixture_root, fixture_paths):
        raise ValueError("form manifest hash mismatch: probe_fixture_tree")
    paired = manifest.get("paired_managed", {})
    counters = paired.get("counters", {})
    if (
        counters.get("total") != counters.get("indexed", 0) + counters.get("failed", 0) + counters.get("unsupported", 0)
        or counters.get("failed")
        or counters.get("unsupported")
        or counters.get("unproven_fragments")
    ):
        raise ValueError("invalid paired form counters")
    live_forms = manifest.get("live_coverage", {}).get("forms")
    if (
        not isinstance(live_forms, int)
        or paired.get("source_forms") != counters.get("total")
        or paired.get("live_form_delta") != counters.get("total") - live_forms
        or not paired.get("live_form_delta_note")
    ):
        raise ValueError("invalid paired/live form inventory relation")
    projections = paired.get("projections", {})
    if set(projections) != {"handlers", "commands", "attributes"}:
        raise ValueError("incomplete form projections")
    for projection in projections.values():
        if projection.get("xml") != projection.get("json") or projection.get("missing") or projection.get("extra"):
            raise ValueError("form projection is not a zero delta")
    coverage = manifest.get("live_coverage", {})
    expected_families = {
        "AccountingRegister",
        "AccumulationRegister",
        "Catalog",
        "ChartOfAccounts",
        "ChartOfCalculationTypes",
        "ChartOfCharacteristicType",
        "CommonForm",
        "DataProcessor",
        "Document",
        "DocumentJournal",
        "Enum",
        "ExchangePlan",
        "FilterCriterion",
        "InformationRegister",
        "Report",
    }
    if set(coverage.get("families", {})) != expected_families:
        raise ValueError("incomplete form family coverage")
    if sum(coverage["families"].values()) != coverage.get("forms"):
        raise ValueError("invalid form family counters")
    if set(coverage.get("local_versions", {})) != {"5", "7", "9", "12", "13"}:
        raise ValueError("incomplete local form version coverage")
    if set(coverage.get("element_versions", {})) != {"1", "0-26", "0-27", "0-5-1", "0-20-16", "0-23-16", "0-25-16"}:
        raise ValueError("incomplete form element version coverage")
    if (
        sum(coverage["local_versions"].values()) != coverage.get("forms")
        or sum(coverage["element_versions"].values()) != coverage.get("forms")
        or coverage.get("module_path_present", 0) + coverage.get("module_path_absent", 0) != coverage.get("forms")
    ):
        raise ValueError("invalid form coverage counters")
    inventory = manifest.get("inventory", {})
    inventory_projections = inventory.get("projections", {})
    roles = inventory_projections.get("roles", {})
    expected_ordinary_candidates = {
        "0-20-16": {
            "element": {"total": 4, "procedure_exists": 4, "procedure_missing": 0},
            "form": {"total": 4, "procedure_exists": 4, "procedure_missing": 0},
        },
        "0-23-16": {
            "element": {"total": 12, "procedure_exists": 12, "procedure_missing": 0},
            "ext_info": {"total": 1, "procedure_exists": 1, "procedure_missing": 0},
            "form": {"total": 9, "procedure_exists": 9, "procedure_missing": 0},
        },
        "0-25-16": {
            "element": {"total": 13, "procedure_exists": 13, "procedure_missing": 0},
            "ext_info": {"total": 1, "procedure_exists": 1, "procedure_missing": 0},
            "form": {"total": 23, "procedure_exists": 23, "procedure_missing": 0},
        },
        "0-26": {
            "element": {"total": 1212, "procedure_exists": 1212, "procedure_missing": 0},
            "ext_info": {"total": 36, "procedure_exists": 36, "procedure_missing": 0},
            "form": {"total": 1061, "procedure_exists": 1061, "procedure_missing": 0},
        },
        "0-27": {
            "element": {"total": 40706, "procedure_exists": 40694, "procedure_missing": 12},
            "ext_info": {"total": 410, "procedure_exists": 408, "procedure_missing": 2},
            "form": {"total": 9836, "procedure_exists": 9818, "procedure_missing": 18},
        },
    }
    if (
        inventory.get("forms") != coverage.get("forms")
        or inventory.get("families") != coverage.get("families")
        or inventory.get("local_versions") != coverage.get("local_versions")
        or inventory.get("element_versions") != coverage.get("element_versions")
        or inventory.get("ordinary_candidates") != expected_ordinary_candidates
        or inventory.get("ordinary_command_candidates") != 22733
        or inventory.get("ordinary_form_version_pairs")
        != {
            "5/0-20-16": 6,
            "5/0-23-16": 4,
            "7/0-5-1": 54,
            "7/0-25-16": 10,
            "7/0-26": 29,
            "9/0-20-16": 4,
            "9/0-23-16": 13,
            "9/0-25-16": 22,
            "9/0-26": 602,
            "9/0-27": 73,
            "12/0-26": 2,
            "12/0-27": 150,
            "13/0-27": 2771,
        }
        or inventory.get("structural_classes") != 544
        or inventory.get("structural_classes_sha256")
        != "9b190a6e7aed2ebe6e85d94db2cbc43ca70ee03a3247251a0201670c9ca6cf68"
        or not isinstance(inventory.get("rows_sha256"), str)
        or len(inventory["rows_sha256"]) != 64
        or inventory.get("handler_rows")
        != {
            "candidates": 53328,
            "indexed": 53328,
            "candidates_sha256": "f16d1114182dd1ac3a69ec7b19b81f14170193d2627991c9af7cd451815ae675",
            "indexed_sha256": "f16d1114182dd1ac3a69ec7b19b81f14170193d2627991c9af7cd451815ae675",
            "missing": 0,
            "extra": 0,
        }
        or set(roles) != {"handlers", "commands", "attributes", "elements"}
        or any(role.get("total") != coverage.get("forms") for role in roles.values())
        or inventory_projections.get("total") != 4 * coverage.get("forms")
        or inventory_projections.get("total")
        != sum(inventory_projections.get(state, 0) for state in ("complete", "empty", "unsupported", "failed"))
        or any(
            role.get("total") != sum(role.get(state, 0) for state in ("complete", "empty", "unsupported", "failed"))
            for role in roles.values()
        )
    ):
        raise ValueError("invalid ordinary form inventory")
    before_open_contract = {
        "form_type": "0",
        "element_version": "0-27",
        "event": "ПередОткрытием",
        "canonical_event": "BeforeOpen",
        "raw_event": "70000",
        "raw_event_pointer": "/form/0/0/4/1/0",
        "handler_pointer": "/form/0/0/4/1/2/1",
        "handler_mirror_pointer": "/form/0/0/4/1/2/2/1",
        "scope": "form",
        "element_name": "",
        "element_type": "",
        "data_path": "",
        "proof": "controlled_delta_and_runtime",
    }
    expected_contract = {
        "form_type": "0",
        "element_version": "0-27",
        "event": "ПриОткрытии",
        "canonical_event": "OnOpen",
        "raw_event": "70001",
        "raw_event_pointer": "/form/0/0/4/2/0",
        "handler_pointer": "/form/0/0/4/2/2/1",
        "handler_mirror_pointer": "/form/0/0/4/2/2/2/1",
        "scope": "form",
        "element_name": "",
        "element_type": "",
        "data_path": "",
        "proof": "controlled_delta_and_runtime",
    }
    unsupported = manifest.get("unsupported_projections", {})
    registry = manifest.get("ordinary_handler_registry", {})
    from rlm_tools_bsl.v8unpack_forms import (
        _ORDINARY_FORM_VERSION_PAIRS,
        _ORDINARY_HANDLER_CLASSES,
        _ordinary_event_name,
    )

    descriptor_keys_sha256 = _sha256(_json_bytes(sorted(_ORDINARY_HANDLER_CLASSES)))
    version_pairs_sha256 = _sha256(_json_bytes(sorted(_ORDINARY_FORM_VERSION_PAIRS)))
    proof_matrix_file = registry.get("proof_matrix_file")
    if not isinstance(proof_matrix_file, str):
        raise ValueError("missing ordinary form proof matrix")
    proof_matrix_path = manifest_path.parent / proof_matrix_file
    if _sha256(proof_matrix_path.read_bytes()) != registry.get("proof_matrix_sha256"):
        raise ValueError("ordinary form proof matrix hash mismatch")
    proof_matrix = json.loads(proof_matrix_path.read_text(encoding="utf-8"))
    proof_results = proof_matrix.get("results", [])
    proof_keys = [tuple(result.get("class_key", ())) for result in proof_results]
    if (
        proof_matrix.get("schema") != "v8unpack_ordinary_form_probe_matrix_v1"
        or proof_matrix.get("classes") != 544
        or proof_matrix.get("success") != 544
        or proof_matrix.get("failed") != 0
        or proof_matrix.get("structural_classes_sha256") != registry.get("structural_classes_sha256")
        or proof_matrix.get("rows_sha256") != registry.get("rows_sha256")
        or len(set(proof_keys)) != 544
        or set(proof_keys) != set(_ORDINARY_HANDLER_CLASSES)
    ):
        raise ValueError("invalid ordinary form proof matrix")
    event_classes: Counter = Counter()
    for result, key in zip(proof_results, proof_keys, strict=True):
        representative = result.get("representative", {})
        delta = result.get("delta", [])
        row_hashes = result.get("sha256", {})
        canonical_event = _ordinary_event_name(
            scope=key[3],
            element_type=key[4],
            raw_event=key[5],
            path=_pointer_parts(representative.get("positional_path", "")),
            element_version=key[1],
            family=representative.get("family", ""),
            owner=representative.get("owner", ""),
            form_name=representative.get("form", ""),
            element_name=representative.get("element_name", ""),
        )
        event_classes[canonical_event] += 1
        if (
            result.get("status") != "success"
            or not canonical_event
            or tuple(
                representative.get(name, "")
                for name in (
                    "local_version",
                    "element_version",
                    "positional_path",
                    "scope",
                    "element_type",
                    "raw_event",
                )
            )
            != key
            or {item.get("pointer") for item in delta}
            != {representative.get("handler_pointer"), representative.get("handler_mirror_pointer")}
            or {item.get("after") for item in delta} != {f'"{result.get("changed_handler", "")}"'}
            or set(row_hashes)
            != {
                "base_cf",
                "changed_cf",
                "base_json",
                "changed_json",
                "delta",
                "base_unchanged_tree",
                "changed_unchanged_tree",
            }
            or not all(isinstance(value, str) and len(value) == 64 for value in row_hashes.values())
            or row_hashes["base_unchanged_tree"] != row_hashes["changed_unchanged_tree"]
        ):
            raise ValueError("invalid ordinary form proof row")
    event_evidence = manifest.get("event_evidence", [])
    if (
        len(event_evidence) != 58
        or {row.get("canonical_event"): row.get("structural_classes") for row in event_evidence} != dict(event_classes)
        or {row.get("proof") for row in event_evidence} != {"runtime", "closed_descriptor_and_source_consensus"}
        or {row.get("canonical_event") for row in event_evidence if row.get("proof") == "runtime"}
        != {"BeforeOpen", "OnOpen"}
        or any(not row.get("reason") for row in event_evidence)
    ):
        raise ValueError("invalid ordinary form event evidence registry")
    if (
        manifest.get("handler_contracts") != [before_open_contract, expected_contract]
        or registry
        != {
            "snapshot": "v8unpack-1.2.9/802",
            "structural_classes": 544,
            "handlers": 53328,
            "canonical_events": 58,
            "ordinary_form_version_pairs": 13,
            "structural_classes_sha256": "9b190a6e7aed2ebe6e85d94db2cbc43ca70ee03a3247251a0201670c9ca6cf68",
            "rows_sha256": "93e7181b845e2ac1031598ba0c80be5a19a9ae3fbdedf0199a4f6d20fdad4880",
            "canonical_events_sha256": "da8cba66ddac9aa8afc841fa47b3fd33f9dbd6f6de15b556f54a06fdd600ef6c",
            "descriptor_keys_sha256": descriptor_keys_sha256,
            "ordinary_form_version_pairs_sha256": version_pairs_sha256,
            "proof_matrix_sha256": _sha256(proof_matrix_path.read_bytes()),
            "proof_matrix_file": "forms-802.proof-matrix.json",
            "proof": "controlled_delta_closed_descriptor_source_consensus_and_automatable_runtime",
        }
        or unsupported.get("commands", {}).get("element_versions")
        != ["0-5-1", "0-20-16", "0-23-16", "0-25-16", "0-26", "0-27"]
        or unsupported.get("handlers") != {"snapshot_unsupported": 0, "unknown_descriptors": True}
    ):
        raise ValueError("invalid ordinary form contract registry")
    probe = manifest.get("ordinary_probe", {})
    if (
        probe.get("status") != "success"
        or probe.get("runtime_events")
        != [
            {
                "action_id": "open-form",
                "event": "ПередОткрытием",
                "handler": "ПередОткрытием",
                "sequence": 1,
            },
            {
                "action_id": "open-form",
                "event": "ПриОткрытии",
                "handler": "ПробаПриОткрытии",
                "sequence": 2,
            },
        ]
        or not probe.get("handler_paths")
        or not probe.get("static_probes")
        or probe.get("handler_contract")
        != {key: value for key, value in expected_contract.items() if key not in {"event", "proof"}}
        or not isinstance(probe.get("runtime_events_sha256"), str)
        or len(probe["runtime_events_sha256"]) != 64
    ):
        raise ValueError("invalid ordinary form probe evidence")
    if not manifest.get("commands"):
        raise ValueError("missing form oracle reproduction command")
    return manifest


def _quoted(value: object) -> str:
    if not isinstance(value, str) or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return ""
    return value[1:-1].replace('""', '"')


def _json_pointer(path: tuple[object, ...]) -> str:
    return "/" + "/".join(str(value).replace("~", "~0").replace("/", "~1") for value in path)


def _pointer_parts(pointer: str) -> tuple[object, ...]:
    parts = []
    for part in pointer.removeprefix("/").split("/"):
        value = part.replace("~1", "/").replace("~0", "~")
        if value:
            parts.append(int(value) if value.isdigit() else value)
    return tuple(parts)


def _binding_context(parent: list, index: int) -> dict[str, object]:
    def compact(value: object) -> object:
        if not isinstance(value, (list, dict)):
            return value
        encoded = _json_bytes(value).decode("utf-8")
        return encoded if len(encoded) <= 256 else f"{encoded[:256]}…"

    return {
        "before": compact(parent[index - 1]) if 0 < index < len(parent) else None,
        "after": compact(parent[index + 1]) if 0 <= index + 1 < len(parent) else None,
        "prefix": [compact(value) for value in parent[:index]] if index >= 0 else [],
        "suffix": [compact(value) for value in parent[index + 1 :]] if index >= 0 else [],
    }


_ORDINARY_EVENT_MARKER_UUID = "e1692cc2-605b-4535-84dd-28440238746c"


def _ordinary_binding_records(
    value: object,
    path: tuple[object, ...] = (),
    *,
    parent: list | None = None,
    parent_index: int = -1,
):
    """Yield valid and malformed outer legacy binding records in one traversal."""
    stack = [(value, path, parent, parent_index)]
    while stack:
        current, current_path, current_parent, current_index = stack.pop()
        if isinstance(current, dict):
            for key, item in reversed(tuple(current.items())):
                if isinstance(item, (list, dict)):
                    stack.append((item, current_path + (key,), None, -1))
            continue
        if not isinstance(current, list):
            continue
        marker_record = len(current) >= 2 and current[1] == _ORDINARY_EVENT_MARKER_UUID
        binding = current[2] if marker_record and len(current) > 2 else current
        binding_record = marker_record or (len(current) >= 3 and current[0] == "3")
        valid = binding_record and (
            isinstance(binding, list)
            and len(binding) >= 3
            and binding[0] == "3"
            and isinstance(binding[1], str)
            and len(binding[1]) >= 2
            and binding[1][0] == '"'
            and binding[1][-1] == '"'
            and isinstance(binding[2], list)
            and len(binding[2]) >= 2
            and binding[2][0] == "1"
            and isinstance(binding[2][1], str)
            and len(binding[2][1]) >= 2
            and binding[2][1][0] == '"'
            and binding[2][1][-1] == '"'
        )
        if marker_record:
            raw_event = current[0]
            if not isinstance(raw_event, (str, int)) or not str(raw_event).isdigit():
                for index in range(len(current) - 1, -1, -1):
                    item = current[index]
                    if isinstance(item, (list, dict)):
                        stack.append((item, current_path + (index,), current, index))
                continue
            if valid and (outer_handler := _quoted(binding[1])):
                yield current_path + (2,), str(raw_event), outer_handler, _binding_context(current, 2)
            elif not valid:
                yield current_path + (2,), str(raw_event), None, {}
            continue
        if valid and binding is current and (outer_handler := _quoted(current[1])):
            raw_event = (
                str(current_parent[0])
                if current_parent
                and current_index >= 2
                and len(current_parent) >= 2
                and current_parent[1] == _ORDINARY_EVENT_MARKER_UUID
                and isinstance(current_parent[0], (str, int))
                else ""
            )
            yield (
                current_path,
                raw_event,
                outer_handler,
                _binding_context(
                    current_parent or [],
                    current_index,
                ),
            )
            continue
        for index in range(len(current) - 1, -1, -1):
            item = current[index]
            if isinstance(item, (list, dict)):
                stack.append((item, current_path + (index,), current, index))


def _ordinary_binding_candidates(
    value: object,
    path: tuple[object, ...] = (),
    *,
    parent: list | None = None,
    parent_index: int = -1,
):
    for record in _ordinary_binding_records(
        value,
        path,
        parent=parent,
        parent_index=parent_index,
    ):
        if record[2] is not None:
            yield record


def _ordinary_malformed_bindings(
    value: object,
    path: tuple[object, ...] = (),
):
    for record_path, raw_event, handler, _context in _ordinary_binding_records(value, path):
        if handler is None:
            yield record_path, raw_event


def _ordinary_element_types(tree: object) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    stack = list(tree) if isinstance(tree, list) else []
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        element_type = item.get("type")
        if isinstance(name, str) and isinstance(element_type, str):
            result.setdefault(name, set()).add(element_type)
        for key in ("child", "children", "items"):
            children = item.get(key)
            if isinstance(children, list):
                stack.extend(children)
    return result


_ORDINARY_OLD_ELEMENT_TYPES = {
    ("19f8b798-314e-4b4e-8121-905b2a7a03f5", (2, 2, 1, 2)): "ListField",
    ("236a17b3-7f44-46d9-a907-75f9cdc61ab5", (2, 17, 1, 2)): "TableField",
    ("381ed624-9217-4e63-85db-c4c3cb87daae", (2, 4, 1, 2)): "Field",
    ("d92a805c-98ae-4750-9158-d9ce7cec2f20", (2, 2, 1, 2)): "FieldHtml",
    ("ea83fe3a-ac3c-4cce-8045-3dddf35b28b1", (2, 4, 1, 2)): "Table",
    ("ea83fe3a-ac3c-4cce-8045-3dddf35b28b1", (2, 4, 2, 2)): "Table",
}
_ORDINARY_COMMAND_BAR_UUID = "e69bf21d-97b2-4f37-86db-675aea9ec2cb"


def _ordinary_main_binding_role(
    form: object,
    path: tuple[object, ...],
    raw_event: str,
) -> tuple[str, str, str]:
    """Classify a legacy binding by its exact section and owning element node."""
    relative = path[1:]
    if relative[:3] == (0, 0, 3):
        return "ext_info", "", ""
    try:
        if relative[:5] != (0, 0, 1, 2, 2):
            raise ValueError
        node = form[0][0][1][2][2][relative[5]]  # type: ignore[index]
        tail = relative[6:]
        if (
            node[0] == _ORDINARY_COMMAND_BAR_UUID
            and len(tail) == 5
            and tail[:3] == (2, 1, 7)
            and isinstance(tail[3], int)
            and tail[4] == 4
        ):
            return "command", "", ""
        element_type = _ORDINARY_OLD_ELEMENT_TYPES[(node[0], tail)]
        marker = node[4]
        if not isinstance(marker, list) or len(marker) < 2 or marker[0] != "14":
            raise ValueError
        element_name = _quoted(marker[1])
        if not element_name:
            raise ValueError
    except (IndexError, KeyError, TypeError, ValueError):
        return "ambiguous", "", ""
    return "element", element_name, element_type


def _ordinary_element_binding_scope(
    element_type: str,
    path: tuple[object, ...],
    raw_event: str,
) -> str:
    relative = path[2:]
    if (
        element_type == "Button"
        and len(relative) == 6
        and relative[:4] == ("raw", 2, 1, 12)
        and isinstance(relative[4], int)
        and relative[5] == 4
    ):
        return "command"
    return "command" if element_type == "CommandPanel" else "element"


def _module_procedures(path: Path) -> set[str]:
    if not path.is_file() or path.is_symlink():
        return set()
    return set(
        re.findall(
            r"(?im)^\s*(?:процедура|функция)\s+([\wА-Яа-яЁё]+)\s*\(",
            path.read_text(encoding="utf-8-sig"),
        )
    )


def build_form_inventory(
    root: str | Path,
    *,
    index_path: str | Path | None = None,
) -> dict:
    """Build the deterministic live ordinary-form evidence report."""
    from rlm_tools_bsl.v8unpack_forms import (
        _ordinary_event_name,
        _form_entries,
        collect_v8unpack_forms,
    )
    from rlm_tools_bsl.format_detector import V8UNPACK_CATEGORY_MAP
    from rlm_tools_bsl.v8unpack_metadata import read_v8unpack_json

    root_path = Path(root).resolve()
    families: Counter = Counter()
    local_versions: Counter = Counter()
    element_versions: Counter = Counter()
    candidate_counts: Counter = Counter()
    procedure_counts: Counter = Counter()
    class_counts: Counter = Counter()
    rows: list[dict] = []
    command_candidates = 0
    ordinary_version_pairs: Counter = Counter()
    ordinary_form_keys: set[tuple[str, str, str]] = set()
    for family, owner, form_name, form_dir, form_kind in _form_entries(root_path):
        rel_main = (form_dir / f"{form_kind}.json").relative_to(root_path).as_posix()
        rel_elements = (form_dir / f"{form_kind}.elem.json").relative_to(root_path).as_posix()
        try:
            main = read_v8unpack_json(root_path, rel_main)
            elements = read_v8unpack_json(root_path, rel_elements)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        families[family] += 1
        local_version = str(main.get("obj_version", ""))
        local_versions[local_version] += 1
        element_version = str(main.get("Версия элементов формы", ""))
        element_versions[element_version] += 1
        if str(main.get("Тип формы")) != "0":
            continue
        ordinary_version_pairs[(local_version, element_version)] += 1
        ordinary_form_keys.add((V8UNPACK_CATEGORY_MAP[family], owner, form_name))
        module_path = form_dir / f"{form_kind}.obj.bsl"
        procedures = _module_procedures(module_path)

        def append_candidate(
            *,
            source_path: str,
            path: tuple[object, ...],
            raw_event: str,
            handler: str,
            neighbor_context: dict[str, object],
            scope: str,
            element_name: str = "",
            element_type: str = "",
            data_path: str = "",
            positional_prefix: int = 0,
        ) -> None:
            nonlocal command_candidates
            if scope == "command":
                command_candidates += 1
                return
            procedure_exists = handler in procedures
            candidate_counts[(element_version, scope)] += 1
            procedure_counts[(element_version, scope)] += int(procedure_exists)
            json_pointer = _json_pointer(path)
            positional_path = _json_pointer(path[positional_prefix:])
            class_counts[(local_version, element_version, positional_path, scope, element_type, raw_event)] += 1
            rows.append(
                {
                    "data_path": data_path,
                    "element_name": element_name,
                    "element_type": element_type,
                    "element_version": element_version,
                    "family": family,
                    "form": form_name,
                    "handler": handler,
                    "handler_pointer": f"{json_pointer}/1",
                    "handler_mirror_pointer": f"{json_pointer}/2/1",
                    "json_pointer": json_pointer,
                    "local_version": local_version,
                    "module_path": (
                        module_path.relative_to(root_path).as_posix()
                        if module_path.is_file() and not module_path.is_symlink()
                        else ""
                    ),
                    "neighbor_context": neighbor_context,
                    "owner": owner,
                    "positional_path": positional_path,
                    "procedure_exists": procedure_exists,
                    "raw_event": raw_event,
                    "raw_event_pointer": _json_pointer(path[:-1] + (0,)),
                    "scope": scope,
                    "source_path": source_path,
                }
            )

        for path, raw_event, handler, context in _ordinary_binding_candidates(
            main.get("form"),
            ("form",),
        ):
            direct_form_slot = len(path) == 6 and path[:4] == ("form", 0, 0, 4) and path[-1] == 2
            scope, element_name, element_type = (
                ("form", "", "") if direct_form_slot else _ordinary_main_binding_role(main.get("form"), path, raw_event)
            )
            append_candidate(
                source_path=rel_main,
                path=path,
                raw_event=raw_event,
                handler=handler,
                neighbor_context=context,
                scope=scope,
                element_name=element_name,
                element_type=element_type,
            )

        element_types = _ordinary_element_types(elements.get("tree"))
        data = elements.get("data")
        if isinstance(data, dict):
            for element_key, details in data.items():
                if not isinstance(element_key, str) or not isinstance(details, dict):
                    continue
                element_name = element_key.rsplit("/", 1)[-1]
                types = sorted(element_types.get(element_name, set()))
                element_type = types[0] if len(types) == 1 else "|".join(types)
                for path, raw_event, handler, context in _ordinary_binding_candidates(
                    details.get("raw"),
                    ("data", element_key, "raw"),
                ):
                    append_candidate(
                        source_path=rel_elements,
                        path=path,
                        raw_event=raw_event,
                        handler=handler,
                        neighbor_context=context,
                        scope=_ordinary_element_binding_scope(element_type, path, raw_event),
                        element_name=element_name,
                        element_type=element_type,
                        data_path=str(details.get("ПутьКДанным", "")),
                        positional_prefix=2,
                    )
    for row in rows:
        row["candidate_id"] = _sha256(_json_bytes(row))
    rows.sort(key=_json_bytes)
    form_result = collect_v8unpack_forms(root_path)

    expected_handlers = []
    for row in rows:
        if row["scope"] not in {"form", "element", "ext_info"}:
            continue
        event = _ordinary_event_name(
            scope=row["scope"],
            element_type=row["element_type"],
            raw_event=row["raw_event"],
            path=_pointer_parts(row["positional_path"]),
            element_version=row["element_version"],
            family=row["family"],
            owner=row["owner"],
            form_name=row["form"],
            element_name=row["element_name"],
        )
        expected_handlers.append(
            (
                row["owner"],
                V8UNPACK_CATEGORY_MAP[row["family"]],
                row["form"],
                row["scope"],
                row["element_name"],
                row["element_type"],
                event,
                row["handler"],
                row["data_path"],
            )
        )
    indexed_handlers = [
        (row[0], row[1], row[2], row[4], row[5], row[6], row[7], row[8], row[9])
        for row in form_result.rows
        if row[3] == "handler" and (row[1], row[0], row[2]) in ordinary_form_keys
    ]
    expected_handler_counter = Counter(expected_handlers)
    indexed_handler_counter = Counter(indexed_handlers)
    ordinary_candidates = {}
    for version in sorted({key[0] for key in candidate_counts}):
        scopes = {}
        for scope in ("form", "ext_info", "element", "ambiguous"):
            total = candidate_counts[(version, scope)]
            if not total:
                continue
            present = procedure_counts[(version, scope)]
            scopes[scope] = {
                "total": total,
                "procedure_exists": present,
                "procedure_missing": total - present,
            }
        ordinary_candidates[version] = scopes
    structural_classes = [
        {
            "count": count,
            "element_type": element_type,
            "element_version": element_version,
            "local_version": local_version,
            "positional_path": positional_path,
            "scope": scope,
            "raw_event": raw_event,
        }
        for (
            local_version,
            element_version,
            positional_path,
            scope,
            element_type,
            raw_event,
        ), count in sorted(class_counts.items())
    ]
    report = {
        "schema": "v8unpack_form_inventory_v2",
        "root_object_version": "802",
        "forms": sum(families.values()),
        "families": dict(sorted(families.items())),
        "local_versions": dict(sorted(local_versions.items())),
        "element_versions": dict(sorted(element_versions.items())),
        "ordinary_candidates": ordinary_candidates,
        "ordinary_form_version_pairs": {
            f"{local_version}/{element_version}": count
            for (local_version, element_version), count in sorted(ordinary_version_pairs.items())
        },
        "ordinary_command_candidates": command_candidates,
        "structural_classes": structural_classes,
        "structural_classes_sha256": _sha256(_json_bytes(structural_classes)),
        "rows_sha256": _sha256(_json_bytes(rows)),
        "rows": rows,
        "handler_rows": {
            "candidates": len(expected_handlers),
            "indexed": len(indexed_handlers),
            "candidates_sha256": _sha256(_json_bytes(sorted(expected_handlers))),
            "indexed_sha256": _sha256(_json_bytes(sorted(indexed_handlers))),
            "missing": (expected_handler_counter - indexed_handler_counter).total(),
            "extra": (indexed_handler_counter - expected_handler_counter).total(),
        },
        "projections": form_result.projection_summary(),
    }
    if index_path is not None:
        with sqlite3.connect(index_path) as conn:
            indexed = [
                tuple(row)
                for row in conn.execute(
                    """
                    SELECT category, object_name, form_name, scope, element_name,
                           element_type, handler, data_path
                    FROM form_elements
                    WHERE kind='handler'
                    """
                )
            ]
            indexed_commands = conn.execute("SELECT COUNT(*) FROM form_elements WHERE kind='command'").fetchone()[0]

        def index_key(row: dict) -> tuple:
            return (
                V8UNPACK_CATEGORY_MAP[row["family"]],
                row["owner"],
                row["form"],
                row["scope"],
                row["element_name"],
                row["element_type"],
                row["handler"],
                row["data_path"],
            )

        candidates = [(row, index_key(row)) for row in rows if row["scope"] != "ambiguous"]
        indexed = [row for row in indexed if row[:3] in ordinary_form_keys]
        indexed_counter = Counter(indexed)
        extracted_ids: Counter = Counter()
        missed_ids: Counter = Counter()
        ambiguous_ids: Counter = Counter()
        misclassified_ids: Counter = Counter()
        remaining_candidates = []
        for row, key in candidates:
            if indexed_counter[key]:
                extracted_ids[row["candidate_id"]] += 1
                indexed_counter[key] -= 1
            else:
                remaining_candidates.append((row, key))
        for row in rows:
            if row["scope"] == "ambiguous":
                ambiguous_ids[row["candidate_id"]] += 1
        indexed_identities = Counter(
            (row[0], row[1], row[2], row[6]) for row, count in indexed_counter.items() for _ in range(count)
        )
        for row, key in remaining_candidates:
            identity = (key[0], key[1], key[2], key[6])
            if indexed_identities[identity]:
                misclassified_ids[row["candidate_id"]] += 1
                indexed_identities[identity] -= 1
            else:
                missed_ids[row["candidate_id"]] += 1

        def id_multiset(counter: Counter) -> list[dict]:
            return [{"candidate_id": candidate_id, "count": count} for candidate_id, count in sorted(counter.items())]

        report["index_comparison"] = {
            "handlers_total": len(indexed),
            "commands_total": indexed_commands,
            "candidate_handlers": len(candidates),
            "extracted": extracted_ids.total(),
            "missed": missed_ids.total(),
            "ambiguous": ambiguous_ids.total(),
            "misclassified": misclassified_ids.total(),
            "unexpected_index_rows": indexed_identities.total(),
            "candidate_ids": {
                "extracted": id_multiset(extracted_ids),
                "missed": id_multiset(missed_ids),
                "ambiguous": id_multiset(ambiguous_ids),
                "misclassified": id_multiset(misclassified_ids),
            },
        }
    payload = dict(report)
    report["content_sha256"] = _sha256(_json_bytes(payload))
    return report


def verify_form_inventory(report: dict, manifest: dict) -> None:
    from rlm_tools_bsl.v8unpack_forms import _ORDINARY_HANDLER_CLASSES

    expected = manifest.get("inventory", {})
    classes = {
        (
            row["local_version"],
            row["element_version"],
            row["positional_path"],
            row["scope"],
            row["element_type"],
            row["raw_event"],
        )
        for row in report.get("structural_classes", [])
    }
    comparison = report.get("index_comparison")
    invalid_index_comparison = comparison is not None and (
        comparison.get("handlers_total") != expected.get("handler_rows", {}).get("candidates")
        or comparison.get("candidate_handlers") != expected.get("handler_rows", {}).get("candidates")
        or comparison.get("extracted") != expected.get("handler_rows", {}).get("candidates")
        or any(comparison.get(key) != 0 for key in ("missed", "ambiguous", "misclassified", "unexpected_index_rows"))
    )
    if (
        report.get("schema") != "v8unpack_form_inventory_v2"
        or report.get("forms") != expected.get("forms")
        or report.get("families") != expected.get("families")
        or report.get("local_versions") != expected.get("local_versions")
        or report.get("element_versions") != expected.get("element_versions")
        or report.get("ordinary_candidates") != expected.get("ordinary_candidates")
        or report.get("ordinary_form_version_pairs") != expected.get("ordinary_form_version_pairs")
        or report.get("ordinary_command_candidates") != expected.get("ordinary_command_candidates")
        or report.get("structural_classes_sha256") != expected.get("structural_classes_sha256")
        or report.get("rows_sha256") != expected.get("rows_sha256")
        or report.get("handler_rows") != expected.get("handler_rows")
        or report.get("projections") != expected.get("projections")
        or classes != _ORDINARY_HANDLER_CLASSES
        or invalid_index_comparison
    ):
        raise ValueError("live form inventory differs from manifest")


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
    metadata_inventory_parser = sub.add_parser("metadata-inventory")
    metadata_inventory_parser.add_argument("--root", required=True)
    metadata_inventory_parser.add_argument("--manifest", required=True)
    form_manifest_parser = sub.add_parser("form-manifest")
    form_manifest_sub = form_manifest_parser.add_subparsers(dest="form_manifest_action", required=True)
    form_verify_parser = form_manifest_sub.add_parser("verify")
    form_verify_parser.add_argument("path")
    form_inventory_parser = sub.add_parser("form-inventory")
    form_inventory_parser.add_argument("--root", required=True)
    form_inventory_parser.add_argument("--output", required=True)
    form_inventory_parser.add_argument("--index")
    form_inventory_parser.add_argument("--manifest")
    args = parser.parse_args(argv)
    if args.action == "manifest":
        verify_manifests(args.path)
        return 0
    if args.action == "metadata-inventory":
        verify_metadata_inventory(args.manifest, args.root)
        return 0
    if args.action == "form-manifest":
        verify_form_manifest(args.path)
        return 0
    if args.action == "form-inventory":
        report = build_form_inventory(args.root, index_path=args.index)
        if args.manifest:
            verify_form_inventory(
                report,
                verify_form_manifest(args.manifest),
            )
        Path(args.output).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
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

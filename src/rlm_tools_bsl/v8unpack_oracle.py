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
            and (
                _is_uuid(role)
                or any(role == key[2] for key in V8UNPACK_FACET_CONTRACT_802)
            )
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
        diagnostic.get("count", 0)
        for diagnostic in diagnostics
        if diagnostic.get("code") != "supported_header_facet"
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
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if manifest.get("schema") != FORM_MANIFEST_SCHEMA:
        raise ValueError("unsupported form manifest schema")
    payload = dict(manifest)
    content_sha256 = payload.pop("content_sha256", "")
    if content_sha256 != _sha256(_json_bytes(payload)):
        raise ValueError("form manifest content hash mismatch")
    hashes = manifest.get("sha256", {})
    if not hashes or not all(isinstance(value, str) and len(value) == 64 for value in hashes.values()):
        raise ValueError("invalid form manifest hashes")
    repo_root = Path(path).resolve().parents[3]
    for key, rel_path in (
        ("probe_script", "tools/v8unpack_form_probe/run.sh"),
        ("probe_verifier", "tools/v8unpack_form_probe/verify.py"),
    ):
        if hashes.get(key) != _sha256((repo_root / rel_path).read_bytes()):
            raise ValueError(f"form manifest hash mismatch: {key}")
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
    if (
        inventory.get("forms") != coverage.get("forms")
        or inventory.get("families") != coverage.get("families")
        or inventory.get("local_versions") != coverage.get("local_versions")
        or inventory.get("element_versions") != coverage.get("element_versions")
        or inventory.get("ordinary_candidates")
        != {
            "0-26": {
                "total": 531,
                "procedure_exists": 531,
                "procedure_missing": 0,
            },
            "0-27": {
                "total": 2311,
                "procedure_exists": 2309,
                "procedure_missing": 2,
            },
        }
        or not isinstance(inventory.get("rows_sha256"), str)
        or len(inventory["rows_sha256"]) != 64
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
    expected_contract = {
        "form_type": "0",
        "element_version": "0-27",
        "event": "ПриОткрытии",
        "canonical_event": "OnOpen",
        "event_pointer": "/form/0/0/4/2/2/1",
        "handler_pointer": "/form/0/0/4/2/2/2/1",
        "scope": "form",
        "element_name": "",
        "element_type": "",
        "data_path": "",
        "proof": "controlled_delta_and_runtime",
    }
    unsupported = manifest.get("unsupported_projections", {})
    if (
        manifest.get("handler_contracts") != [expected_contract]
        or unsupported.get("commands", {}).get("element_versions")
        != ["0-5-1", "0-20-16", "0-23-16", "0-25-16", "0-26", "0-27"]
        or unsupported.get("handlers", {}).get("element_versions") != ["0-5-1", "0-20-16", "0-23-16", "0-25-16", "0-26"]
        or unsupported.get("handlers", {}).get("ordinary_element_handlers") is not True
        or unsupported.get("handlers", {}).get("unknown_events") is not True
    ):
        raise ValueError("invalid ordinary form contract registry")
    probe = manifest.get("ordinary_probe", {})
    if (
        probe.get("status") != "success"
        or probe.get("runtime_events")
        != [
            {
                "action_id": "open-form",
                "event": "ПриОткрытии",
                "handler": "ПробаПриОткрытии",
                "sequence": 1,
            }
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


def build_form_inventory(
    root: str | Path,
    *,
    index_path: str | Path | None = None,
) -> dict:
    """Build the deterministic live ordinary-form evidence report."""
    from rlm_tools_bsl.v8unpack_forms import (
        _form_entries,
        collect_v8unpack_forms,
    )
    from rlm_tools_bsl.v8unpack_metadata import read_v8unpack_json

    root_path = Path(root).resolve()
    families: Counter = Counter()
    local_versions: Counter = Counter()
    element_versions: Counter = Counter()
    candidate_counts: Counter = Counter()
    procedure_counts: Counter = Counter()
    rows = []
    form_keys_by_version: dict[str, set[tuple[str, str, str]]] = {
        "0-26": set(),
        "0-27": set(),
    }
    for family, owner, form_name, form_dir, form_kind in _form_entries(root_path):
        rel_main = (form_dir / f"{form_kind}.json").relative_to(root_path).as_posix()
        try:
            main = read_v8unpack_json(root_path, rel_main)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        families[family] += 1
        local_versions[str(main.get("obj_version", ""))] += 1
        element_version = str(main.get("Версия элементов формы", ""))
        element_versions[element_version] += 1
        if element_version not in form_keys_by_version:
            continue
        form_keys_by_version[element_version].add((family, owner, form_name))
        slot = 1 if element_version == "0-26" else 2
        try:
            binding = main["form"][0][0][4][slot][2]
            event = _quoted(binding[1])
            handler = _quoted(binding[2][1])
        except (KeyError, IndexError, TypeError):
            continue
        if not event or not handler:
            continue
        module_path = form_dir / f"{form_kind}.obj.bsl"
        procedure_exists = False
        if module_path.is_file() and not module_path.is_symlink():
            body = module_path.read_text(encoding="utf-8-sig")
            procedure_exists = (
                re.search(
                    rf"(?im)^\s*(?:процедура|функция)\s+{re.escape(handler)}\s*\(",
                    body,
                )
                is not None
            )
        candidate_counts[element_version] += 1
        if procedure_exists:
            procedure_counts[element_version] += 1
        rows.append(
            {
                "element_version": element_version,
                "event": event,
                "event_pointer": f"/form/0/0/4/{slot}/2/1",
                "family": family,
                "form": form_name,
                "handler": handler,
                "handler_pointer": f"/form/0/0/4/{slot}/2/2/1",
                "main_path": rel_main,
                "owner": owner,
                "procedure_exists": procedure_exists,
            }
        )
    rows.sort(key=_json_bytes)
    form_result = collect_v8unpack_forms(root_path)
    report = {
        "schema": "v8unpack_form_inventory_v1",
        "root_object_version": "802",
        "forms": sum(families.values()),
        "families": dict(sorted(families.items())),
        "local_versions": dict(sorted(local_versions.items())),
        "element_versions": dict(sorted(element_versions.items())),
        "ordinary_candidates": {
            version: {
                "total": candidate_counts[version],
                "procedure_exists": procedure_counts[version],
                "procedure_missing": candidate_counts[version] - procedure_counts[version],
            }
            for version in ("0-26", "0-27")
        },
        "rows_sha256": _sha256(_json_bytes(rows)),
        "rows": rows,
        "projections": form_result.projection_summary(),
    }
    if index_path is not None:
        with sqlite3.connect(index_path) as conn:
            indexed_handlers = conn.execute("SELECT COUNT(*) FROM form_elements WHERE kind='handler'").fetchone()[0]
            indexed_commands = conn.execute("SELECT COUNT(*) FROM form_elements WHERE kind='command'").fetchone()[0]
            exact = {}
            for version, keys in form_keys_by_version.items():
                matched = 0
                for _family, owner, form_name in keys:
                    matched += conn.execute(
                        "SELECT COUNT(*) FROM form_elements WHERE object_name=? AND form_name=? AND kind='handler'",
                        (owner, form_name),
                    ).fetchone()[0]
                exact[version] = matched
        report["index_comparison"] = {
            "handlers_total": indexed_handlers,
            "commands_total": indexed_commands,
            "ordinary_handlers_by_version": exact,
        }
    payload = dict(report)
    report["content_sha256"] = _sha256(_json_bytes(payload))
    return report


def verify_form_inventory(report: dict, manifest: dict) -> None:
    expected = manifest.get("inventory", {})
    if (
        report.get("schema") != "v8unpack_form_inventory_v1"
        or report.get("forms") != expected.get("forms")
        or report.get("families") != expected.get("families")
        or report.get("local_versions") != expected.get("local_versions")
        or report.get("element_versions") != expected.get("element_versions")
        or report.get("ordinary_candidates") != expected.get("ordinary_candidates")
        or report.get("rows_sha256") != expected.get("rows_sha256")
        or report.get("projections") != expected.get("projections")
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

import json
from pathlib import Path
import shutil
import sqlite3
import subprocess

import pytest

import rlm_tools_bsl.bsl_index as bsl_index
from rlm_tools_bsl.bsl_index import IndexBuilder, IndexReader
from rlm_tools_bsl.v8unpack_metadata import (
    GENERATED_TYPE_ID_POSITIONS,
    MAX_JSON_BYTES,
    STRUCTURAL_CONTRACT,
    V8UNPACK_METADATA_CONTRACTS,
    V8UNPACK_METADATA_IDENTITY_MAP,
    _decode_pattern,
    _diagnostics,
    classify_v8unpack_json_path,
    builtin_type_contract,
    collect_v8unpack_metadata,
    generated_type_contract,
    generated_type_coverage_contract,
    read_v8unpack_json,
)
from rlm_tools_bsl.v8unpack_oracle import (
    COMPARATOR_VERSION,
    PROJECTIONS,
    SCHEMA_VERSION,
    _json_bytes,
    _sha256,
    _verify_manifest,
    projection_summary,
    verify_manifests,
)


ENUM_TYPE_ID = "920a053a-5c39-4860-8e9f-d8446a4d9cc2"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _descriptor(name: str, synonym: str, item_uuid: str) -> list:
    return ["1", ["0", "0", item_uuid], f'"{name}"', ["1", '"ru"', f'"{synonym}"'], '""', "0", "0"]


def _attribute(name: str, synonym: str, item_uuid: str, *types: list) -> list:
    # Exact 1.2.9/802 fragment copied from Catalog/Склады/Catalog.json:
    # item[0][1][1][1] is the descriptor, item[0][1][1][2] is Pattern.
    return [
        [
            "3",
            ["27", ["2", _descriptor(name, synonym, item_uuid), ['"Pattern"', *types]]],
            "0",
            ["0"],
            ["0"],
            "0",
            '""',
            "0",
            ['"U"'],
            ['"U"'],
            "0",
            "00000000-0000-0000-0000-000000000000",
            "2",
            "0",
            ["5004", "0"],
            ["3", "0", "0"],
            ["0", "0"],
            "0",
            ["0"],
            ['"U"'],
            "0",
            "0",
            "0",
        ],
        "0",
    ]


def _tabular_section(name: str, synonym: str, item_uuid: str, children: list) -> list:
    # Exact relative positions from
    # Catalog/СоглашенияОбИспользованииЭД/Catalog.json.
    payload = ["11", "a", "b", "c", "d", ["0", _descriptor(name, synonym, item_uuid)]]
    return [["1", payload, "0"], "1", ["888744e1-b616-11d4-9436-004095e12fc7", str(len(children)), *children]]


def _catalog_header(enum_type_id: str) -> list:
    object_types = ["0"] * 35
    object_types[1] = "11111111-1111-4111-8111-111111111111"
    object_types[3] = "22222222-2222-4222-8222-222222222222"
    object_types[5] = "33333333-3333-4333-8333-333333333333"
    object_types[7] = "44444444-4444-4444-8444-444444444444"
    object_types[34] = "55555555-5555-4555-8555-555555555555"
    direct = _attribute(
        "Статус",
        "Статус",
        "66666666-6666-4666-8666-666666666666",
        ['"#"', enum_type_id],
    )
    column = _attribute(
        "Количество",
        "Количество",
        "77777777-7777-4777-8777-777777777777",
        ['"N"', "15", "2", "0"],
    )
    tabular = _tabular_section("Строки", "Строки", "88888888-8888-4888-8888-888888888888", [column])
    header = ["0"] * 8
    header[1] = object_types
    header[3] = ["3daea016-69b7-4ed4-9453-127911372fe6", "0"]
    header[4] = ["4fe87c89-9ad4-43f6-9fdb-9dc83b3879c6", "0"]
    header[5] = ["932159f9-95b2-4e76-a8dd-8849fe5c5ded", "1", tabular]
    header[6] = ["cf4abea7-37b2-11d4-940f-008048da11f9", "1", direct]
    header[7] = ["fdf816d2-1ead-11d5-b975-0050bae0a95d", "0"]
    return [header]


def _enum_header() -> list:
    header = ["0", ["0"] * 8]
    header[1][1] = ENUM_TYPE_ID
    header[1][3] = "99999999-9999-4999-8999-999999999999"
    header[1][7] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    return [header]


def _fixture(root: Path, *, unresolved: bool = False) -> None:
    _write(
        root / "Configuration.json",
        {
            "v8unpack": "1.2.9",
            "obj_version": "802",
            "name": "Тест",
            "name2": {"ru": 'Тестовая ""редакция"" '},
        },
    )
    _write(
        root / "Enum" / "Статусы" / "Enum.json",
        {
            "name": "Статусы",
            "name2": {"ru": "Статусы"},
            "obj_version": "802",
            "header": _enum_header(),
        },
    )
    _write(
        root / "Enum" / "Статусы" / "Enum.id.json",
        {
            "uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        },
    )
    type_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" if unresolved else ENUM_TYPE_ID
    _write(
        root / "Catalog" / "Товары" / "Catalog.json",
        {
            "name": "Товары",
            "name2": {"ru": 'Товары ""для продажи"" '},
            "obj_version": "802",
            "header": _catalog_header(type_id),
        },
    )
    _write(
        root / "Catalog" / "Товары" / "Catalog.id.json",
        {
            "uuid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        },
    )


def _fixture_version(root: Path, object_version: str) -> None:
    _fixture(root)
    producer = {"802": "1.2.9", "803": "1.2.6"}[object_version]
    config_path = root / "Configuration.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.update(v8unpack=producer, obj_version=object_version)
    _write(config_path, config)
    for path in root.glob("*/*/*.json"):
        if path.name.endswith(".id.json"):
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        data["obj_version"] = object_version
        if object_version == "803" and path.name == "Enum.json":
            data["header"][0][1].append(data["header"][0][1][7])
        _write(path, data)


def _json_layer(db_path: Path) -> dict:
    with sqlite3.connect(db_path) as conn:
        return {
            table: sorted(  # noqa: S608
                conn.execute(f"SELECT {columns} FROM {table}").fetchall(),
                key=repr,
            )
            for table, columns in {
                "metadata_objects": "category,object_name,object_uuid,source_file",
                "metadata_type_ids": "type_uuid,canonical_ref,type_form,source_file",
                "object_attributes": (
                    "object_name,category,attr_name,attr_synonym,attr_type,attr_kind,ts_name,source_file"
                ),
                "object_synonyms": "object_name,category,synonym,file",
                "metadata_references": ("source_object,source_category,ref_object,ref_kind,used_in,path,line"),
            }.items()
        } | {
            "meta": conn.execute(
                "SELECT key,value FROM index_meta "
                "WHERE key IN ('v8unpack_metadata_snapshot_json',"
                "'v8unpack_metadata_diagnostics_json','v8unpack_metadata_status') "
                "ORDER BY key"
            ).fetchall()
        }


def test_identity_map_and_whitelist_classifier(tmp_path):
    assert len(V8UNPACK_METADATA_IDENTITY_MAP) == 26
    role = classify_v8unpack_json_path(tmp_path, "Catalog/Товары/Catalog.json")
    assert role and (role.role, role.kind, role.object_name) == ("main", "Catalog", "Товары")
    assert classify_v8unpack_json_path(tmp_path, "Catalog/Товары/Catalog.id.json").role == "id"
    assert classify_v8unpack_json_path(tmp_path, "Catalog/Товары/Form/F.json") is None
    assert classify_v8unpack_json_path(tmp_path, "../outside.json") is None


def test_safe_json_rejects_symlink_and_oversize(tmp_path):
    outside = tmp_path.parent / "outside-v8.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / "link.json").symlink_to(outside)
    with pytest.raises(ValueError):
        read_v8unpack_json(tmp_path, "link.json")
    large = tmp_path / "large.json"
    with large.open("wb") as stream:
        stream.truncate(MAX_JSON_BYTES + 1)
    with pytest.raises(ValueError):
        read_v8unpack_json(tmp_path, large)


def test_oracle_manifest_verifies_report_content(tmp_path):
    empty_summary = projection_summary([])
    projections = {
        name: {
            "xml": empty_summary,
            "json": empty_summary,
            "equal": True,
            "missing": [],
            "extra": [],
        }
        for name in PROJECTIONS
    }
    missing_generated_types = sorted(
        [kind, source, type_form]
        for kind in V8UNPACK_METADATA_IDENTITY_MAP
        for source, type_form in generated_type_coverage_contract("803", kind)
    )
    shared = {
        "schema_version": SCHEMA_VERSION,
        "comparator_version": COMPARATOR_VERSION,
        "coverage": {
            "structural": [],
            "type_shapes": ["composite", "primitive", "reference"],
            "generated_types": [],
            "builtin_type_uuids": [],
            "missing_generated_types": missing_generated_types,
            "missing_builtin_type_uuids": sorted(builtin_type_contract("803")),
        },
        "status": "complete",
        "identity": {"total": 0, "indexed": 0, "failed": 0},
        "structural": {"total": 0, "indexed": 0, "failed": 0},
        "diagnostics": [],
        "unsupported_count": 0,
        "forbidden_diagnostics": [],
        "assertions": {},
        "zero_delta": True,
    }
    report_payload = {**shared, "projections": projections}
    report = {
        **report_payload,
        "content_sha256": _sha256(_json_bytes(report_payload)),
    }
    report_path = tmp_path / "pair.report.json"
    _write(report_path, report)
    manifest = {
        **shared,
        "root_object_version": "803",
        "v8unpack_version": "1.2.6",
        "commands": ["generate pair"],
        "platform_version": "8.3.27.1989",
        "owner_object_versions": ["803"],
        "projections": {name: {"xml": empty_summary, "json": empty_summary} for name in PROJECTIONS},
        "report_file": report_path.name,
        "report_sha256": report["content_sha256"],
        **{
            key: "0" * 64
            for key in (
                "cf_sha256",
                "v8unpack_sha256",
                "xml_input_tree_sha256",
                "json_input_tree_sha256",
            )
        },
    }
    manifest_path = tmp_path / "pair.manifest.json"
    _write(manifest_path, manifest)

    assert _verify_manifest(manifest_path)["zero_delta"] is True
    for invalid in (
        [{"code": "unknown", "role": "owner", "count": 1, "examples": ["x"]}],
        [{"code": "unsupported_header_shape", "role": "owner", "count": 0, "examples": ["x"]}],
        [
            {
                "code": "unsupported_header_shape",
                "role": "owner",
                "count": 1,
                "examples": ["b", "a"],
            }
        ],
    ):
        changed = {**manifest, "diagnostics": invalid, "unsupported_count": sum(row["count"] for row in invalid)}
        _write(manifest_path, changed)
        with pytest.raises(ValueError, match="invalid diagnostic"):
            _verify_manifest(manifest_path)
    _write(manifest_path, manifest)
    report["status"] = "partial"
    _write(report_path, report)
    with pytest.raises(ValueError, match="report hash mismatch"):
        _verify_manifest(manifest_path)


def test_real_demo_803_manifest_is_exact():
    manifest = _verify_manifest(Path(__file__).parent / "fixtures" / "v8unpack_oracle" / "demo-803.manifest.json")

    assert manifest["identity"] == {"total": 179, "indexed": 179, "failed": 0}
    assert manifest["structural"] == {"total": 36, "indexed": 13, "failed": 23}
    assert {name: manifest["projections"][name]["json"]["total"] for name in PROJECTIONS} == {
        "object_attributes": 135,
        "object_synonyms": 36,
        "metadata_references": 56,
        "metadata_objects": 179,
        "metadata_type_ids": 375,
    }
    assert manifest["unsupported_count"] == 51
    assert len(manifest["diagnostics"]) == 7
    assert {row["code"] for row in manifest["diagnostics"]} == {"unsupported_header_facet"}
    assert _sha256(_json_bytes(manifest["diagnostics"])) == (
        "1faae044b608b721a415932f93abde23b6bc578d1fe1a7e30e95acc106c1dd52"
    )
    assert manifest["forbidden_diagnostics"] == []
    assert manifest["assertions"]["information_register_characteristic_typeset"] == {
        "row": [
            "Характеристики",
            "InformationRegisters",
            "Значение",
            "Значение",
            "[]",
            "resource",
            None,
        ],
        "references": [],
    }


def test_real_oracle_manifests_cover_802_and_803_contracts():
    root = Path(__file__).parent / "fixtures" / "v8unpack_oracle"
    bp = _verify_manifest(root / "bp-802.manifest.json")
    structural = _verify_manifest(root / "structural-coverage-803.manifest.json")

    assert bp["identity"] == {"total": 2428, "indexed": 2428, "failed": 0}
    assert bp["structural"] == {"total": 689, "indexed": 689, "failed": 0}
    assert {name: bp["projections"][name]["json"]["total"] for name in PROJECTIONS} == {
        "object_attributes": 11700,
        "object_synonyms": 689,
        "metadata_references": 7634,
        "metadata_objects": 2428,
        "metadata_type_ids": 6779,
    }
    assert structural["identity"] == {"total": 185, "indexed": 185, "failed": 0}
    assert structural["forbidden_diagnostics"] == []
    assert structural["coverage"]["missing_builtin_type_uuids"] == []
    assert structural["zero_delta"] is True

    verify_manifests(
        [
            root / "bp-802.manifest.json",
            root / "demo-803.manifest.json",
            root / "structural-coverage-803.manifest.json",
        ]
    )


def test_verified_builtin_type_uuids_match_xml_representation():
    item = _attribute(
        "Значение",
        "Значение",
        "66666666-6666-4666-8666-666666666666",
        ['"#"', "280f5f0e-9c8a-49cc-bf6d-4d296cc17a63"],
        ['"B"'],
        ['"S"', "100", "1"],
        ['"D"'],
        ['"N"', "15", "3", "0"],
    )
    assert _decode_pattern(item, {}) == ('["Boolean", "String", "DateTime", "Number"]', [])


def test_803_characteristic_matches_xml_typeset():
    characteristic_uuid = "50000000-0000-4000-8000-000000000001"
    item = _attribute(
        "Значение",
        "Значение",
        "66666666-6666-4666-8666-666666666666",
        ['"#"', characteristic_uuid],
    )
    type_ids = {
        characteristic_uuid: (
            "ChartOfCharacteristicTypes.ВидыХарактеристик",
            "Characteristic",
        )
    }

    assert _decode_pattern(item, type_ids, object_version="803") == ("[]", [])
    assert _decode_pattern(item, type_ids, object_version="802") == (
        '["Characteristic.ВидыХарактеристик"]',
        [],
    )


def test_803_builtin_contract_contains_only_paired_uuids():
    assert builtin_type_contract("803") == {
        "e199ca70-93cf-46ce-a54b-6edc88c3a296": "ValueStorage",
        "fc01b5df-97fe-449b-83d4-218a090e681e": "UUID",
        "280f5f0e-9c8a-49cc-bf6d-4d296cc17a63": None,
    }
    item = _attribute(
        "Значение",
        "Значение",
        "66666666-6666-4666-8666-666666666666",
        ['"#"', "280f5f0e-9c8a-49cc-bf6d-4d296cc17a63"],
    )
    assert _decode_pattern(item, {}, object_version="803") == ("[]", [])


def test_803_accounting_register_generated_types_use_even_positions(tmp_path):
    _fixture_version(tmp_path, "803")
    generated = ["22", "22"]
    expected = {}
    for offset, (_index, type_form) in enumerate(GENERATED_TYPE_ID_POSITIONS["AccountingRegister"], start=1):
        type_uuid = f"60000000-0000-4000-8000-{offset:012d}"
        generated.extend((type_uuid, f"70000000-0000-4000-8000-{offset:012d}"))
        expected[type_uuid] = type_form
    header = ["0"] * 8
    header[1] = generated
    for index, tag, _row_kind in STRUCTURAL_CONTRACT["AccountingRegister"]:
        header[index] = [tag, "0"]
    _write(
        tmp_path / "AccountingRegister" / "Хозрасчетный" / "AccountingRegister.json",
        {
            "name": "Хозрасчетный",
            "name2": {"ru": "Журнал проводок"},
            "obj_version": "803",
            "header": [header],
        },
    )
    _write(
        tmp_path / "AccountingRegister" / "Хозрасчетный" / "AccountingRegister.id.json",
        {"uuid": "50000000-0000-4000-8000-000000000014"},
    )

    result = collect_v8unpack_metadata(tmp_path)

    assert {
        type_uuid: type_form
        for type_uuid, canonical, type_form, _source in result.metadata_type_ids
        if canonical == "AccountingRegister.Хозрасчетный"
    } == expected
    assert not any(
        row["code"] == "unsupported_header_shape"
        and "AccountingRegister/Хозрасчетный/AccountingRegister.json" in row["examples"]
        for row in result.diagnostics
    )


def test_closed_version_registry_and_separate_observability(tmp_path):
    assert V8UNPACK_METADATA_CONTRACTS == {
        "802": frozenset({"1.2.9"}),
        "803": frozenset({"1.2.6"}),
    }
    _fixture_version(tmp_path, "803")

    result = collect_v8unpack_metadata(tmp_path)

    assert result.status == "complete"
    assert result.index_meta()["v8unpack_metadata_version"] == "1.2.6"
    assert result.index_meta()["v8unpack_metadata_producer_version"] == "1.2.6"
    assert result.index_meta()["v8unpack_metadata_object_version"] == "803"


def test_unknown_object_version_has_exact_diagnostic(tmp_path):
    _write(
        tmp_path / "Configuration.json",
        {"v8unpack": "1.2.6", "obj_version": "804"},
    )

    result = collect_v8unpack_metadata(tmp_path)

    assert result.status == "unsupported"
    assert result.diagnostics == [
        {
            "code": "unsupported_object_version",
            "role": "configuration",
            "count": 1,
            "examples": ["Configuration.json"],
        }
    ]


@pytest.mark.parametrize("object_version", ["802", "803"])
def test_mixed_owner_version_keeps_only_identity(tmp_path, object_version):
    _fixture_version(tmp_path, object_version)
    path = tmp_path / "Catalog" / "Товары" / "Catalog.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["obj_version"] = "803" if object_version == "802" else "802"
    _write(path, data)

    result = collect_v8unpack_metadata(tmp_path)

    assert any(row[1] == "Товары" for row in result.metadata_objects)
    assert all(row[1] != "Catalog.Товары" for row in result.metadata_type_ids)
    assert all(row[0] != "Товары" for row in result.object_attributes)
    assert all(row[0] != "Товары" for row in result.object_synonyms)
    assert all(row[0] != "Товары" for row in result.metadata_references)
    assert {
        "code": "unsupported_header_shape",
        "role": "owner",
        "count": 1,
        "examples": ["Catalog/Товары/Catalog.json"],
    } in result.diagnostics


@pytest.mark.parametrize("object_version", ["802", "803"])
def test_mixed_identity_only_owner_version_keeps_only_identity(tmp_path, object_version):
    _fixture_version(tmp_path, object_version)
    path = tmp_path / "Enum" / "Статусы" / "Enum.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["obj_version"] = "803" if object_version == "802" else "802"
    _write(path, data)

    result = collect_v8unpack_metadata(tmp_path)

    assert any(row[1] == "Статусы" for row in result.metadata_objects)
    assert all(row[1] != "EnumRef.Статусы" for row in result.metadata_type_ids)
    assert {
        "code": "unsupported_header_shape",
        "role": "owner",
        "count": 1,
        "examples": ["Enum/Статусы/Enum.json"],
    } in result.diagnostics


@pytest.mark.parametrize("object_version", ["802", "803"])
def test_common_form_local_version_is_not_root_version(tmp_path, object_version):
    _fixture_version(tmp_path, object_version)
    _write(
        tmp_path / "CommonForm" / "Обычная" / "CommonForm.json",
        {"name": "Обычная", "name2": {"ru": "Обычная"}, "obj_version": "13", "header": []},
    )
    _write(
        tmp_path / "CommonForm" / "Обычная" / "CommonForm.id.json",
        {"uuid": "50000000-0000-4000-8000-000000000013"},
    )

    result = collect_v8unpack_metadata(tmp_path)

    assert any(
        row[:3] == ("CommonForms", "Обычная", "50000000-0000-4000-8000-000000000013") for row in result.metadata_objects
    )
    assert not any(
        row["code"] == "unsupported_header_shape" and "CommonForm/Обычная/CommonForm.json" in row["examples"]
        for row in result.diagnostics
    )


def test_diagnostics_are_bounded_and_deterministic():
    events = [
        ("unsupported_header_facet", f"00000000-0000-4000-8000-{number:012d}", f"{number}.json") for number in range(60)
    ]
    diagnostics = _diagnostics(list(reversed(events)))
    assert len(diagnostics) == 50
    assert diagnostics == sorted(diagnostics, key=lambda row: (row["code"], row["role"]))
    assert all(len(row["examples"]) <= 5 for row in diagnostics)


def test_collects_identity_generated_types_and_structural_rows(tmp_path):
    _fixture(tmp_path)
    result = collect_v8unpack_metadata(tmp_path)

    assert result.status == "complete"
    assert result.config_name == "Тест"
    assert result.config_synonym == 'Тестовая "редакция"'
    assert result.object_synonyms == [
        ("Товары", "Catalogs", 'Справочник: Товары "для продажи"', "Catalog/Товары/Catalog.json")
    ]
    assert result.identity_total == result.identity_indexed == 2
    assert result.structural_total == result.structural_indexed == 1
    assert (
        "Enums",
        "Статусы",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "Enum/Статусы/Enum.json",
    ) in result.metadata_objects
    assert (ENUM_TYPE_ID, "Enum.Статусы", "EnumRef", "Enum/Статусы/Enum.json") in result.metadata_type_ids
    assert (
        "Товары",
        "Catalogs",
        "Статус",
        "Статус",
        '["EnumRef.Статусы"]',
        "attribute",
        None,
        "Catalog/Товары/Catalog.json",
    ) in result.object_attributes
    assert (
        "Товары",
        "Catalogs",
        "Количество",
        "Количество",
        '["Number"]',
        "ts_attribute",
        "Строки",
        "Catalog/Товары/Catalog.json",
    ) in result.object_attributes
    assert result.metadata_references == [
        (
            "Товары",
            "Catalogs",
            "Enum.Статусы",
            "attribute_type",
            "Catalog.Товары.Attribute.Статус.Type",
            "Catalog/Товары/Catalog.json",
            None,
        )
    ]
    assert [row["path"] for row in result.snapshot] == sorted(row["path"] for row in result.snapshot)
    assert result.index_meta()["v8unpack_metadata_identity_failed"] == "0"


@pytest.mark.parametrize("kind", sorted(STRUCTURAL_CONTRACT))
def test_structural_contract_families(tmp_path, kind):
    _write(
        tmp_path / "Configuration.json",
        {"v8unpack": "1.2.9", "obj_version": "802", "name": "Тест"},
    )
    header = ["0"] * (max(index for index, _tag, _row_kind in STRUCTURAL_CONTRACT[kind]) + 1)
    header[1] = ["0"] * 40
    for number, (index, _type_form) in enumerate(generated_type_contract("802", kind)[0], 100):
        header[1][index] = f"00000000-0000-4000-8000-{number:012d}"
    expected = set()
    for number, (index, tag, row_kind) in enumerate(STRUCTURAL_CONTRACT[kind], 1):
        if row_kind == "tabular_section":
            child = _attribute(
                f"Колонка{number}",
                f"Колонка {number}",
                f"00000000-0000-4000-8000-{number:012d}",
                ['"S"', "10", "1"],
            )
            item = _tabular_section(
                f"Таблица{number}",
                f"Таблица {number}",
                f"10000000-0000-4000-8000-{number:012d}",
                [child],
            )
            expected.add("ts_attribute")
        else:
            item = _attribute(
                f"Поле{number}",
                f"Поле {number}",
                f"20000000-0000-4000-8000-{number:012d}",
                ['"S"', "10", "1"],
            )
            expected.add(row_kind)
        header[index] = [tag, "1", item]
    _write(
        tmp_path / kind / "Объект" / f"{kind}.json",
        {
            "name": "Объект",
            "name2": {"ru": "Объект"},
            "obj_version": "802",
            "header": [header],
        },
    )
    _write(
        tmp_path / kind / "Объект" / f"{kind}.id.json",
        {"uuid": "30000000-0000-4000-8000-000000000001"},
    )

    result = collect_v8unpack_metadata(tmp_path)
    assert result.structural_total == result.structural_indexed == 1
    assert {row[5] for row in result.object_attributes} == expected


@pytest.mark.parametrize("kind", sorted(GENERATED_TYPE_ID_POSITIONS))
def test_generated_type_forms_use_owner_canonical_reference(tmp_path, kind):
    _write(
        tmp_path / "Configuration.json",
        {"v8unpack": "1.2.9", "obj_version": "802", "name": "Тест"},
    )
    positions = GENERATED_TYPE_ID_POSITIONS[kind]
    generated = ["0"] * (max(index for index, _form in positions) + 1)
    for number, (index, _form) in enumerate(positions, 1):
        generated[index] = f"50000000-0000-4000-8000-{number:012d}"
    _write(
        tmp_path / kind / "Объект" / f"{kind}.json",
        {"name": "Объект", "obj_version": "802", "header": [["0", generated]]},
    )
    _write(
        tmp_path / kind / "Объект" / f"{kind}.id.json",
        {"uuid": "50000000-0000-4000-8000-000000000003"},
    )

    result = collect_v8unpack_metadata(tmp_path)
    canonical = f"{V8UNPACK_METADATA_IDENTITY_MAP[kind][1]}.Объект"
    assert {(row[1], row[2]) for row in result.metadata_type_ids} == {(canonical, form) for _index, form in positions}


def test_unresolved_type_is_partial_without_false_reference(tmp_path):
    _fixture(tmp_path, unresolved=True)
    result = collect_v8unpack_metadata(tmp_path)

    assert result.status == "partial"
    status = next(row for row in result.object_attributes if row[2] == "Статус")
    assert status[4] is None
    assert result.metadata_references == []
    assert result.diagnostics == [
        {
            "code": "unresolved_metadata_uuid",
            "role": "type",
            "count": 1,
            "examples": ["Catalog/Товары/Catalog.json"],
        }
    ]


def test_unknown_owner_header_keeps_only_identity(tmp_path):
    _fixture(tmp_path)
    path = tmp_path / "Catalog" / "Товары" / "Catalog.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["header"] = []
    _write(path, data)

    result = collect_v8unpack_metadata(tmp_path)

    assert any(row[1] == "Товары" for row in result.metadata_objects)
    assert not any(row[-1] == "Catalog/Товары/Catalog.json" for row in result.metadata_type_ids)
    assert not any(row[0] == "Товары" for row in result.object_attributes)
    assert not any(row[0] == "Товары" for row in result.object_synonyms)
    assert not any(row[0] == "Товары" for row in result.metadata_references)
    assert {
        "code": "unsupported_header_shape",
        "role": "owner",
        "count": 1,
        "examples": ["Catalog/Товары/Catalog.json"],
    } in result.diagnostics


def test_ambiguous_generated_type_uuid_is_not_resolved(tmp_path):
    _fixture(tmp_path)
    _write(
        tmp_path / "Enum" / "ДругиеСтатусы" / "Enum.json",
        {
            "name": "ДругиеСтатусы",
            "name2": {"ru": "Другие статусы"},
            "obj_version": "802",
            "header": _enum_header(),
        },
    )
    _write(
        tmp_path / "Enum" / "ДругиеСтатусы" / "Enum.id.json",
        {"uuid": "40000000-0000-4000-8000-000000000001"},
    )
    result = collect_v8unpack_metadata(tmp_path)
    status = next(row for row in result.object_attributes if row[2] == "Статус")
    assert status[4] is None
    assert result.metadata_references == []


def test_unsupported_root_does_not_collect_rows(tmp_path):
    _write(tmp_path / "Configuration.json", {"v8unpack": "1.3.0", "obj_version": "802"})
    result = collect_v8unpack_metadata(tmp_path)
    assert result.status == "unsupported"
    assert result.metadata_objects == []
    assert result.diagnostics[0]["code"] == "unsupported_v8unpack_version"


def test_malformed_id_has_exact_role(tmp_path):
    _fixture(tmp_path)
    (tmp_path / "Catalog" / "Товары" / "Catalog.id.json").write_text("{", encoding="utf-8")
    result = collect_v8unpack_metadata(tmp_path)
    assert {
        "code": "malformed_required_json",
        "role": "id",
        "count": 1,
        "examples": ["Catalog/Товары/Catalog.id.json"],
    } in result.diagnostics


def test_missing_id_has_exact_role(tmp_path):
    _fixture(tmp_path)
    (tmp_path / "Catalog" / "Товары" / "Catalog.id.json").unlink()
    result = collect_v8unpack_metadata(tmp_path)
    assert {
        "code": "missing_required_json",
        "role": "id",
        "count": 1,
        "examples": ["Catalog/Товары/Catalog.id.json"],
    } in result.diagnostics


def test_unknown_structural_tag_keeps_identity_and_other_rows(tmp_path):
    _fixture(tmp_path)
    path = tmp_path / "Catalog" / "Товары" / "Catalog.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["header"][0][6][0] = "70000000-0000-4000-8000-000000000001"
    _write(path, data)
    result = collect_v8unpack_metadata(tmp_path)
    assert result.status == "partial"
    assert any(row[1] == "Товары" for row in result.metadata_objects)
    assert {row[2] for row in result.object_attributes} == {"Количество"}
    assert any(row["code"] == "unsupported_header_shape" and row["role"] == "attribute" for row in result.diagnostics)


def test_excluded_header_facet_is_aggregated(tmp_path):
    _fixture(tmp_path)
    path = tmp_path / "Catalog" / "Товары" / "Catalog.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["header"][0][3] = [
        "3daea016-69b7-4ed4-9453-127911372fe6",
        "1",
        ["excluded"],
    ]
    _write(path, data)
    result = collect_v8unpack_metadata(tmp_path)
    assert {
        "code": "unsupported_header_facet",
        "role": "3daea016-69b7-4ed4-9453-127911372fe6",
        "count": 1,
        "examples": ["Catalog/Товары/Catalog.json"],
    } in result.diagnostics


def test_index_build_and_update_replace_json_layer(tmp_path, monkeypatch):
    root = tmp_path / "source"
    _fixture(root)
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))

    db_path = IndexBuilder().build(str(root), build_calls=False, build_metadata=True, build_fts=False)
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["source_format"] == "v8unpack"
    assert stats["metadata_objects"] == 2
    assert stats["metadata_type_ids"] == 8
    assert stats["object_attributes"] == 2
    assert stats["v8unpack_metadata_status"] == "complete"
    assert stats["v8unpack_metadata_producer_version"] == "1.2.9"
    assert stats["v8unpack_metadata_object_version"] == "802"
    assert json.loads(stats["v8unpack_metadata_snapshot_json"])
    assert stats["file_paths"] == 5

    (root / "Catalog" / "Товары" / "Catalog.json").write_text("{", encoding="utf-8")
    IndexBuilder().update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["metadata_objects"] == 1
    assert stats["object_attributes"] == 0
    assert stats["v8unpack_metadata_status"] == "partial"

    _fixture(root)
    IndexBuilder().update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["metadata_objects"] == 2
    assert stats["object_attributes"] == 2
    assert stats["v8unpack_metadata_status"] == "complete"

    (root / "Configuration.json").write_text("{", encoding="utf-8")
    IndexBuilder().update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["metadata_objects"] == 0
    assert stats["v8unpack_metadata_status"] == "unsupported"
    assert stats["v8unpack_metadata_recovery_pending"] is True
    assert stats["v8unpack_metadata_version"] is None
    assert stats["v8unpack_metadata_producer_version"] is None
    assert stats["v8unpack_metadata_object_version"] is None
    assert stats["v8unpack_metadata_diagnostics_json"] is None
    assert stats["v8unpack_metadata_snapshot_json"] is None

    _fixture(root)
    IndexBuilder().update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["metadata_objects"] == 2
    assert stats["v8unpack_metadata_status"] == "complete"
    assert stats["v8unpack_metadata_recovery_pending"] is False

    (root / "Configuration.json").unlink()
    IndexBuilder().update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["file_paths"] == 4
    assert stats["v8unpack_metadata_status"] == "unsupported"


@pytest.mark.parametrize("marker", ["", None, 42])
def test_known_v8_invalid_marker_clears_and_recovers(tmp_path, monkeypatch, marker):
    root = tmp_path / "source"
    _fixture_version(root, "803")
    update_index_root = tmp_path / "index"
    monkeypatch.setenv("RLM_INDEX_DIR", str(update_index_root))
    builder = IndexBuilder()
    db_path = builder.build(str(root), build_calls=False, build_fts=False)
    config_path = root / "Configuration.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["v8unpack"] = marker
    _write(config_path, config)

    builder.update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert stats["v8unpack_metadata_status"] == "unsupported"
    assert stats["v8unpack_metadata_recovery_pending"] is True
    assert stats["metadata_objects"] == 0
    assert stats["metadata_type_ids"] == 0
    assert stats["object_attributes"] == 0
    assert stats["v8unpack_metadata_identity_total"] == 0
    assert stats["v8unpack_metadata_producer_version"] is None
    assert stats["v8unpack_metadata_object_version"] is None
    assert stats["v8unpack_metadata_diagnostics_json"] is None
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM index_meta WHERE key IN "
                "('v8unpack_metadata_version',"
                "'v8unpack_metadata_producer_version',"
                "'v8unpack_metadata_object_version',"
                "'v8unpack_metadata_diagnostics_json',"
                "'v8unpack_metadata_snapshot_json')"
            ).fetchone()[0]
            == 0
        )

    _fixture_version(root, "803")
    builder.update(str(root))
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "fresh"))
    fresh_db = IndexBuilder().build(str(root), build_calls=False, build_fts=False)
    assert _json_layer(db_path) == _json_layer(fresh_db)


@pytest.mark.parametrize(
    ("build_metadata", "build_synonyms", "status", "objects", "attributes", "synonyms"),
    [
        (False, True, "disabled", 0, 0, 0),
        (True, False, "complete", 2, 2, 0),
    ],
)
def test_index_build_flags(
    tmp_path,
    monkeypatch,
    build_metadata,
    build_synonyms,
    status,
    objects,
    attributes,
    synonyms,
):
    root = tmp_path / "source"
    _fixture(root)
    _write(root / "Catalog" / "Товары" / "Catalog.elem.json", {"ignored": True})
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))

    db_path = IndexBuilder().build(
        str(root),
        build_calls=False,
        build_metadata=build_metadata,
        build_fts=False,
        build_synonyms=build_synonyms,
    )
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    assert reader.find_files_indexed("elem.json") == []
    reader.close()
    assert stats["v8unpack_metadata_status"] == status
    assert stats["metadata_objects"] == objects
    assert stats["object_attributes"] == attributes
    assert stats["object_synonyms"] == synonyms
    assert stats["file_paths"] == 5
    if not build_metadata:
        assert stats["v8unpack_metadata_producer_version"] is None
        assert stats["v8unpack_metadata_object_version"] is None
        assert stats["v8unpack_metadata_diagnostics_json"] is None
        assert stats["v8unpack_metadata_snapshot_json"] is None
        assert stats["v8unpack_metadata_identity_total"] == 0
        with sqlite3.connect(db_path) as conn:
            raw_keys = {
                row[0]
                for row in conn.execute(
                    "SELECT key FROM index_meta WHERE key IN "
                    "('v8unpack_metadata_version',"
                    "'v8unpack_metadata_producer_version',"
                    "'v8unpack_metadata_object_version',"
                    "'v8unpack_metadata_diagnostics_json',"
                    "'v8unpack_metadata_snapshot_json')"
                )
            }
        assert raw_keys == set()


@pytest.mark.parametrize("source_format", ["cf", "edt"])
def test_cf_and_edt_build_publish_not_applicable_without_v8_payload(tmp_path, monkeypatch, source_format):
    root = tmp_path / "source"
    if source_format == "cf":
        _write(root / "Configuration.xml", {})
    else:
        _write(root / "Configuration" / "Configuration.mdo", {})
    module = (
        root / "CommonModules" / "Тест" / "Ext" / "Module.bsl"
        if source_format == "cf"
        else root / "CommonModules" / "Тест" / "Module.bsl"
    )
    module.parent.mkdir(parents=True)
    module.write_text("Процедура Тест() Экспорт\nКонецПроцедуры", encoding="utf-8")
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))

    db_path = IndexBuilder().build(str(root), build_calls=False, build_metadata=True, build_fts=False)
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()

    assert stats["source_format"] == source_format
    assert stats["v8unpack_metadata_status"] == "not_applicable"
    assert stats["v8unpack_metadata_producer_version"] is None
    assert stats["v8unpack_metadata_object_version"] is None
    assert stats["v8unpack_metadata_diagnostics_json"] is None
    assert stats["v8unpack_metadata_snapshot_json"] is None
    assert stats["v8unpack_metadata_identity_total"] == 0
    with sqlite3.connect(db_path) as conn:
        raw_keys = {row[0] for row in conn.execute("SELECT key FROM index_meta WHERE key LIKE 'v8unpack_metadata_%'")}
    assert raw_keys == {
        "v8unpack_metadata_status",
        "v8unpack_metadata_identity_total",
        "v8unpack_metadata_identity_indexed",
        "v8unpack_metadata_identity_failed",
        "v8unpack_metadata_structural_total",
        "v8unpack_metadata_structural_indexed",
        "v8unpack_metadata_structural_failed",
        "v8unpack_metadata_unsupported_count",
    }


@pytest.mark.parametrize("target_format", ["cf", "edt"])
def test_v8_to_cf_or_edt_clears_json_metadata(tmp_path, monkeypatch, target_format):
    root = tmp_path / "source"
    _fixture(root)
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))
    builder = IndexBuilder()
    db_path = builder.build(str(root), build_calls=False, build_fts=False)

    (root / "Configuration.json").unlink()
    shutil.rmtree(root / "Catalog")
    shutil.rmtree(root / "Enum")
    if target_format == "cf":
        _write(root / "Configuration.xml", {})
        (root / "Ext").mkdir()
    else:
        _write(root / "Configuration" / "Configuration.mdo", {})

    builder.update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()

    assert stats["source_format"] == target_format
    assert stats["v8unpack_metadata_status"] == "not_applicable"
    assert stats["v8unpack_metadata_producer_version"] is None
    assert stats["v8unpack_metadata_object_version"] is None
    assert stats["v8unpack_metadata_diagnostics_json"] is None
    assert stats["v8unpack_metadata_snapshot_json"] is None
    assert stats["metadata_objects"] == 0
    assert stats["metadata_type_ids"] == 0
    assert stats["object_attributes"] == 0
    assert stats["object_synonyms"] == 0
    assert stats["metadata_references"] == 0


def test_real_version_16_rebuild_is_upgraded_to_17(tmp_path, monkeypatch):
    root = tmp_path / "source"
    _fixture(root)
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))
    builder = IndexBuilder()
    db_path = builder.build(
        str(root),
        build_calls=False,
        build_metadata=True,
        build_fts=False,
        build_synonyms=False,
    )
    monkeypatch.setattr(bsl_index, "BUILDER_VERSION", 16)
    builder.build(
        str(root),
        build_calls=False,
        build_metadata=True,
        build_fts=False,
        build_synonyms=False,
    )
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT value FROM index_meta WHERE key='builder_version'").fetchone()[0] == "16"
        conn.execute("INSERT INTO index_meta(key,value) VALUES ('future_opaque_key','kept-if-reused')")

    monkeypatch.setattr(bsl_index, "BUILDER_VERSION", 17)
    delta = builder.update(str(root))
    reader = IndexReader(db_path)
    stats = reader.get_statistics()
    reader.close()
    assert delta["rebuild_reason"] == "schema upgrade v16->17"
    assert stats["builder_version"] == "17"
    assert stats["metadata_objects"] == 2
    with sqlite3.connect(db_path) as conn:
        flags = dict(
            conn.execute(
                "SELECT key,value FROM index_meta WHERE key IN ('has_calls','has_metadata','has_fts','has_synonyms')"
            )
        )
    assert flags == {
        "has_calls": "0",
        "has_metadata": "1",
        "has_fts": "0",
        "has_synonyms": "0",
    }
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT value FROM index_meta WHERE key='future_opaque_key'").fetchone() is None


@pytest.mark.parametrize("object_version", ["802", "803"])
def test_git_add_rename_delete_keeps_json_layer_and_navigation_equal(tmp_path, monkeypatch, object_version):
    root = tmp_path / "source"
    _fixture_version(root, object_version)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True)
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))
    builder = IndexBuilder()
    db_path = builder.build(str(root), build_calls=False, build_fts=False)
    update_index_root = tmp_path / "index"

    def assert_matches_fresh(step: str) -> None:
        monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / f"fresh-git-{step}"))
        fresh_db = IndexBuilder().build(str(root), build_calls=False, build_fts=False)
        assert _json_layer(db_path) == _json_layer(fresh_db)
        monkeypatch.setenv("RLM_INDEX_DIR", str(update_index_root))

    extra = root / "Enum" / "НовыеСтатусы"
    enum_header = _enum_header()
    if object_version == "803":
        enum_header[0][1].append(enum_header[0][1][7])
    _write(
        extra / "Enum.json",
        {
            "name": "НовыеСтатусы",
            "name2": {"ru": "Новые статусы"},
            "obj_version": object_version,
            "header": enum_header,
        },
    )
    _write(extra / "Enum.id.json", {"uuid": "50000000-0000-4000-8000-000000000001"})
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "add"], check=True)
    assert builder.update(str(root))["git_fast_path"] is True
    reader = IndexReader(db_path)
    assert reader.get_statistics()["metadata_objects"] == 3
    assert len(reader.find_files_indexed("НовыеСтатусы")) == 2
    reader.close()
    assert_matches_fresh("add")

    renamed = extra.with_name("ПереименованныеСтатусы")
    extra.rename(renamed)
    data_path = renamed / "Enum.json"
    data = json.loads(data_path.read_text(encoding="utf-8"))
    data["name"] = "ПереименованныеСтатусы"
    _write(data_path, data)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "rename"], check=True)
    builder.update(str(root))
    reader = IndexReader(db_path)
    assert reader.find_files_indexed("НовыеСтатусы") == []
    assert len(reader.find_files_indexed("ПереименованныеСтатусы")) == 2
    reader.close()
    assert_matches_fresh("rename")

    for path in renamed.iterdir():
        path.unlink()
    renamed.rmdir()
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "delete"], check=True)
    builder.update(str(root))
    reader = IndexReader(db_path)
    assert reader.get_statistics()["metadata_objects"] == 2
    assert reader.find_files_indexed("ПереименованныеСтатусы") == []
    reader.close()
    assert_matches_fresh("delete")


@pytest.mark.parametrize("object_version", ["802", "803"])
def test_non_git_uuid_rename_delete_matches_current_files(tmp_path, monkeypatch, object_version):
    root = tmp_path / "source"
    _fixture_version(root, object_version)
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / "index"))
    builder = IndexBuilder()
    db_path = builder.build(str(root), build_calls=False, build_fts=False)
    update_index_root = tmp_path / "index"

    def assert_matches_fresh(step: str) -> None:
        fresh_root = tmp_path / f"fresh-{step}"
        monkeypatch.setenv("RLM_INDEX_DIR", str(fresh_root))
        fresh_db = IndexBuilder().build(str(root), build_calls=False, build_fts=False)
        assert _json_layer(db_path) == _json_layer(fresh_db)
        monkeypatch.setenv("RLM_INDEX_DIR", str(update_index_root))

    id_path = root / "Catalog" / "Товары" / "Catalog.id.json"
    new_uuid = "60000000-0000-4000-8000-000000000001"
    _write(id_path, {"uuid": new_uuid})
    builder.update(str(root))
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute(
                "SELECT object_uuid FROM metadata_objects WHERE category='Catalogs' AND object_name='Товары'"
            ).fetchone()[0]
            == new_uuid
        )
    assert_matches_fresh("uuid")

    old = root / "Catalog" / "Товары"
    renamed = old.with_name("НовыеТовары")
    old.rename(renamed)
    main_path = renamed / "Catalog.json"
    data = json.loads(main_path.read_text(encoding="utf-8"))
    data["name"] = "НовыеТовары"
    _write(main_path, data)
    builder.update(str(root))
    with sqlite3.connect(db_path) as conn:
        names = {row[0] for row in conn.execute("SELECT object_name FROM metadata_objects WHERE category='Catalogs'")}
    assert names == {"НовыеТовары"}
    assert_matches_fresh("rename")

    for path in renamed.iterdir():
        path.unlink()
    renamed.rmdir()
    builder.update(str(root))
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM metadata_objects WHERE category='Catalogs'").fetchone()[0] == 0
    assert_matches_fresh("delete")

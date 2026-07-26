import json
from pathlib import Path
import sqlite3

import pytest

from rlm_tools_bsl.bsl_helpers import make_bsl_helpers
from rlm_tools_bsl.bsl_index import IndexBuilder, IndexReader, _refresh_form_elements
from rlm_tools_bsl.format_detector import detect_format
from rlm_tools_bsl.v8unpack_forms import (
    V8UNPACK_FORM_FAMILIES,
    _ORDINARY_FORM_VERSION_PAIRS,
    _ORDINARY_HANDLER_CLASSES,
    _ordinary_event_name,
    collect_v8unpack_forms,
)
from rlm_tools_bsl.v8unpack_metadata import collect_v8unpack_metadata
from rlm_tools_bsl.v8unpack_oracle import (
    _json_bytes,
    _sha256,
    build_form_inventory,
)


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _root(tmp_path: Path) -> None:
    _write(
        tmp_path / "Configuration.json",
        {"v8unpack": "1.2.9", "obj_version": "802"},
    )


def _form(
    tmp_path: Path,
    family: str,
    owner: str,
    form_kind: str,
    form_name: str,
    *,
    element_version: str = "1",
    local_version: str = "13",
) -> None:
    if family == "CommonForm":
        folder = tmp_path / family / form_name
    else:
        folder = tmp_path / family / owner / form_kind / form_name
    _write(
        folder / f"{form_kind}.json",
        {
            "name": form_name,
            "obj_version": local_version,
            "Тип формы": "1",
            "Версия элементов формы": element_version,
            "form": [
                [
                    [
                        None,
                        [None] * 19
                        + [
                            [
                                None,
                                "9f2e5ddb-3492-4f5d-8f0d-416b8d1d5c5b",
                                '"ПриСозданииНаСервере"',
                            ]
                        ],
                    ]
                ]
            ],
        },
    )
    _write(
        folder / f"{form_kind}.elem.json",
        {
            "params": None,
            "props": [
                {
                    "name": "РеквизитПробника",
                    "raw": [
                        "9",
                        ["1"],
                        "0",
                        '"РеквизитПробника"',
                        ["1", "0"],
                        ['"Pattern"', ['"#"', "2fdc88ec-7c9b-43cd-8ba5-873f043bdd88"]],
                    ],
                }
            ],
            "commands": [
                {
                    "name": "КомандаПробника",
                    "raw": ["9", ["1"], '"КомандаПробника"', [], [], [], [], [], '"КомандаПробника"'],
                }
            ],
            "tree": [],
            "data": {},
        },
    )
    _write(folder / f"{form_kind}.id.json", {"uuid": "50000000-0000-4000-8000-000000000001"})


def _ordinary_form(
    tmp_path: Path,
    *,
    element_version: str = "0-27",
    local_version: str = "13",
    raw_event: str = "70001",
    handler: str = "ОбычныйПриОткрытии",
    slot: int | None = None,
) -> Path:
    _form(
        tmp_path,
        "Document",
        "Документ",
        "DocumentForm",
        "Форма",
        element_version=element_version,
        local_version=local_version,
    )
    folder = tmp_path / "Document" / "Документ" / "DocumentForm" / "Форма"
    main_path = folder / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["Тип формы"] = "0"
    slot = slot if slot is not None else 2
    form_payload = [None, None, None, None, [None] * (slot + 1)]
    form_payload[4][slot] = [
        raw_event,
        "e1692cc2-605b-4535-84dd-28440238746c",
        ["3", f'"{handler}"', ["1", f'"{handler}"']],
    ]
    main["form"] = [[form_payload]]
    _write(main_path, main)
    elements_path = folder / "DocumentForm.elem.json"
    elements = json.loads(elements_path.read_text())
    elements["props"] = []
    elements["commands"] = [
        {
            "name": "НедоказаннаяКоманда",
            "raw": ["9", ["1"], '"НедоказаннаяКоманда"', [], [], [], [], [], '"Действие"'],
        }
    ]
    _write(elements_path, elements)
    return folder


@pytest.mark.parametrize(
    ("family", "form_kind"),
    [*sorted(V8UNPACK_FORM_FAMILIES.items()), ("CommonForm", "CommonForm")],
)
def test_closed_family_matrix_discovers_form(tmp_path, family, form_kind):
    _root(tmp_path)
    _form(tmp_path, family, "Объект", form_kind, "Форма")

    result = collect_v8unpack_forms(tmp_path)

    assert result.status == "complete"
    assert (result.total, result.indexed, result.failed, result.unsupported) == (1, 1, 0, 0)
    assert any(row[3] == "form" for row in result.rows)


def test_managed_form_emits_proven_rows(tmp_path):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")

    result = collect_v8unpack_forms(tmp_path)

    assert {(row[3], row[5], row[7], row[8]) for row in result.rows} == {
        ("form", "", "", ""),
        ("attribute", "РеквизитПробника", "", ""),
        ("command", "КомандаПробника", "", "КомандаПробника"),
        ("handler", "", "OnCreateAtServer", "ПриСозданииНаСервере"),
    }
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"] == {
        "attributes": "complete",
        "commands": "complete",
        "elements": "empty",
        "handlers": "complete",
    }


def test_form_collector_reuses_existing_metadata_result(tmp_path, monkeypatch):
    _root(tmp_path)
    _ordinary_form(tmp_path)
    metadata_result = collect_v8unpack_metadata(tmp_path)
    monkeypatch.setattr(
        "rlm_tools_bsl.v8unpack_forms.collect_v8unpack_metadata",
        lambda _root: (_ for _ in ()).throw(AssertionError("duplicate metadata scan")),
    )

    result = collect_v8unpack_forms(tmp_path, metadata_result=metadata_result)

    assert (result.total, result.indexed, result.failed) == (1, 1, 0)


def test_ordinary_0_27_emits_proven_on_open_handler(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path)

    result = collect_v8unpack_forms(tmp_path)

    handlers = [row for row in result.rows if row[3] == "handler"]
    assert [(row[4], row[5], row[6], row[7], row[8], row[9]) for row in handlers] == [
        ("form", "", "", "OnOpen", "ОбычныйПриОткрытии", "")
    ]
    assert not any(row[3] == "command" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"] == {
        "attributes": "empty",
        "commands": "unsupported",
        "elements": "empty",
        "handlers": "complete",
    }
    summary = json.loads(result.index_meta()["v8unpack_form_projections_json"])
    assert summary["total"] == 4
    assert summary["unsupported"] == 1
    assert result.status == "partial"


@pytest.mark.parametrize(
    ("element_version", "local_version", "slot"),
    [
        ("0-26", "12", 2),
        ("0-20-16", "9", 1),
        ("0-23-16", "9", 1),
        ("0-25-16", "9", 1),
    ],
)
def test_other_ordinary_versions_decode_proven_handlers(
    tmp_path,
    element_version,
    local_version,
    slot,
):
    _root(tmp_path)
    _ordinary_form(
        tmp_path,
        element_version=element_version,
        local_version=local_version,
        slot=slot,
    )

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "command" for row in result.rows)
    assert any(row[3] == "handler" and row[7] == "OnOpen" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    projections = json.loads(marker[12])["projections"]
    assert projections["handlers"] == "complete"
    assert projections["commands"] == "unsupported"


def test_known_event_at_unknown_ordinary_position_is_not_guessed(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path, slot=3)

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "handler" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "unsupported"


def test_ordinary_inventory_points_to_outer_event_and_handler(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path)

    row = build_form_inventory(tmp_path)["rows"][0]

    assert row["raw_event_pointer"] == "/form/0/0/4/2/0"
    assert row["handler_pointer"] == "/form/0/0/4/2/2/1"
    assert row["handler_mirror_pointer"] == "/form/0/0/4/2/2/2/1"


def test_closed_ordinary_handler_registry_covers_every_proven_class():
    def pointer_parts(pointer: str) -> tuple[object, ...]:
        return tuple(
            int(value) if value.isdigit() else value
            for value in pointer.removeprefix("/").split("/")
        )

    events = {
        _ordinary_event_name(
            scope=scope,
            element_type=element_type,
            raw_event=raw_event,
            path=pointer_parts(path),
            element_version=element_version,
            family="Document",
            owner="",
            form_name="",
            element_name="",
        )
        for _local_version, element_version, path, scope, element_type, raw_event
        in _ORDINARY_HANDLER_CLASSES
    }

    assert len(_ORDINARY_HANDLER_CLASSES) == 544
    assert "" not in events
    assert len(events) == 58
    assert _sha256(_json_bytes(sorted(_ORDINARY_HANDLER_CLASSES))) == (
        "af0ee3fd7c15aae10085dcdb5bd1d242c5eca40b947649dfec4bd109c2ec51b3"
    )
    assert _sha256(_json_bytes(sorted(events))) == (
        "da8cba66ddac9aa8afc841fa47b3fd33f9dbd6f6de15b556f54a06fdd600ef6c"
    )


def test_table_raw50_exception_does_not_leak_to_other_forms():
    values = {
        "scope": "element",
        "element_type": "Table",
        "raw_event": "50",
        "path": ("raw", 2, 4, 1, 2),
        "element_version": "0-26",
        "family": "Document",
        "element_name": "Продукция",
    }

    assert _ordinary_event_name(
        **values,
        owner="ПередачаТоваров",
        form_name="ФормаПодбора",
    ) == "ExternalEvent"
    assert _ordinary_event_name(
        **values,
        owner="ДругойДокумент",
        form_name="ФормаПодбора",
    ) == "NewWriteProcessing"


def test_parse_form_keeps_duplicate_proven_element_handlers(tmp_path, monkeypatch):
    _root(tmp_path)
    folder = _ordinary_form(
        tmp_path,
        element_version="0-26",
        local_version="12",
    )
    marker = "e1692cc2-605b-4535-84dd-28440238746c"
    binding = ["3", '"ПолеПриИзменении"', ["1", '"ПолеПриИзменении"']]
    raw = [None, None, [None, None, None, None, [None, ["2147483647", marker, binding], None, [
        "2147483647",
        marker,
        binding,
    ]]]]
    elements_path = folder / "DocumentForm.elem.json"
    elements = json.loads(elements_path.read_text())
    elements["tree"] = [{"name": "Поле", "type": "Field"}]
    elements["data"] = {
        "Страница/Поле": {
            "raw": raw,
            "ПутьКДанным": "Объект.Поле",
        }
    }
    _write(elements_path, elements)
    (folder / "DocumentForm.obj.bsl").write_text(
        "Процедура ПолеПриИзменении()\nКонецПроцедуры\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / ".index"))

    db_path = IndexBuilder().build(
        str(tmp_path),
        build_calls=False,
        build_fts=False,
        build_synonyms=False,
    )
    reader = IndexReader(db_path)
    helpers = make_bsl_helpers(
        base_path=str(tmp_path),
        resolve_safe=lambda path: tmp_path / path,
        read_file_fn=lambda path: (tmp_path / path).read_text(encoding="utf-8-sig"),
        grep_fn=lambda *_args, **_kwargs: [],
        glob_files_fn=lambda pattern: [
            path.relative_to(tmp_path).as_posix()
            for path in tmp_path.glob(pattern)
        ],
        format_info=detect_format(tmp_path),
        idx_reader=reader,
    )

    parsed = helpers["parse_form"]("Документ", handler="ПолеПриИзменении")
    form_filtered = helpers["parse_form"](
        "Документ",
        handler="ОбычныйПриОткрытии",
    )
    reader.close()

    assert len(parsed[0]["handlers"]) == 2
    assert {
            (
                row["scope"],
                row["element"],
            row["element_type"],
            row["event"],
            row["handler"],
            row["data_path"],
        )
        for row in parsed[0]["handlers"]
    } == {
        (
            "element",
            "Поле",
            "Field",
            "OnChange",
            "ПолеПриИзменении",
            "Объект.Поле",
        )
    }
    assert parsed[0]["commands"] == []
    assert parsed[0]["projections"]["handlers"] == "complete"
    assert parsed[0]["projections"]["commands"] == "unsupported"
    assert form_filtered[0]["handlers"] == [
        {
            "element": "",
            "event": "OnOpen",
            "handler": "ОбычныйПриОткрытии",
            "element_type": "",
            "data_path": "",
            "scope": "form",
        }
    ]
    assert form_filtered[0]["attributes"] == parsed[0]["attributes"]
    assert form_filtered[0]["projections"] == parsed[0]["projections"]


def test_proven_ordinary_form_without_handlers_is_empty(tmp_path):
    _root(tmp_path)
    _form(
        tmp_path,
        "Document",
        "Документ",
        "DocumentForm",
        "Форма",
        element_version="0-5-1",
        local_version="7",
    )
    main_path = tmp_path / "Document" / "Документ" / "DocumentForm" / "Форма" / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["Тип формы"] = "0"
    main["form"] = []
    _write(main_path, main)

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "handler" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "empty"


def test_unknown_ordinary_version_pair_without_handlers_is_unsupported(tmp_path):
    _root(tmp_path)
    _form(
        tmp_path,
        "Document",
        "Документ",
        "DocumentForm",
        "Форма",
        element_version="0-5-1",
        local_version="13",
    )
    main_path = tmp_path / "Document" / "Документ" / "DocumentForm" / "Форма" / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["Тип формы"] = "0"
    main["form"] = []
    _write(main_path, main)

    result = collect_v8unpack_forms(tmp_path)

    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "unsupported"
    assert len(_ORDINARY_FORM_VERSION_PAIRS) == 13


def test_unknown_ordinary_event_is_not_guessed(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path, raw_event="79999")

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "handler" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "unsupported"


def test_known_ordinary_descriptor_in_unknown_local_version_is_not_guessed(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path, local_version="7")

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "handler" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "unsupported"


def test_binding_without_event_marker_is_not_guessed(tmp_path):
    _root(tmp_path)
    folder = _ordinary_form(tmp_path)
    main_path = folder / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["form"][0][0][4][2][1] = "future-marker"
    _write(main_path, main)

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "handler" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "unsupported"


def test_malformed_proven_ordinary_handler_is_failed(tmp_path):
    _root(tmp_path)
    folder = _ordinary_form(tmp_path)
    main_path = folder / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["form"][0][0][4][2][2][2] = []
    _write(main_path, main)

    result = collect_v8unpack_forms(tmp_path)

    marker = next(row for row in result.rows if row[3] == "form")
    assert json.loads(marker[12])["projections"]["handlers"] == "failed"
    assert result.status == "partial"


@pytest.mark.parametrize("data", [[], {"Поле": []}])
def test_malformed_required_element_data_fails_all_projections(tmp_path, data):
    _root(tmp_path)
    folder = _ordinary_form(tmp_path)
    elements_path = folder / "DocumentForm.elem.json"
    elements = json.loads(elements_path.read_text())
    elements["data"] = data
    _write(elements_path, elements)

    result = collect_v8unpack_forms(tmp_path)

    assert (result.total, result.indexed, result.failed, result.unsupported) == (1, 0, 1, 0)
    assert result.rows == []
    summary = json.loads(result.index_meta()["v8unpack_form_projections_json"])
    for role in ("attributes", "commands", "elements", "handlers"):
        assert summary["roles"][role] == {
            "total": 1,
            "complete": 0,
            "empty": 0,
            "unsupported": 0,
            "failed": 1,
        }


def test_ordinary_page_lists_are_valid_element_data(tmp_path):
    _root(tmp_path)
    folder = _ordinary_form(tmp_path)
    elements_path = folder / "DocumentForm.elem.json"
    elements = json.loads(elements_path.read_text())
    elements["data"]["-pages-"] = ["Страница1"]
    _write(elements_path, elements)

    result = collect_v8unpack_forms(tmp_path)

    assert (result.indexed, result.failed) == (1, 0)


def test_unknown_element_version_is_unsupported(tmp_path):
    _root(tmp_path)
    _form(
        tmp_path,
        "Document",
        "Документ",
        "DocumentForm",
        "Форма",
        element_version="0-99",
    )

    result = collect_v8unpack_forms(tmp_path)

    assert (result.total, result.indexed, result.failed, result.unsupported) == (1, 0, 0, 1)
    assert result.rows == []
    assert result.status == "partial"
    summary = json.loads(result.index_meta()["v8unpack_form_projections_json"])
    assert summary["unsupported"] == 4


def test_symlinked_required_json_fails_only_one_form(tmp_path):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Первая", "CommonForm", "Первая")
    _form(tmp_path, "CommonForm", "Вторая", "CommonForm", "Вторая")
    target = tmp_path / "CommonForm" / "Первая" / "CommonForm.elem.json"
    target.unlink()
    target.symlink_to(tmp_path / "CommonForm" / "Вторая" / "CommonForm.elem.json")

    result = collect_v8unpack_forms(tmp_path)

    assert (result.total, result.indexed, result.failed, result.unsupported) == (2, 1, 1, 0)
    assert {row[2] for row in result.rows} == {"Вторая"}
    summary = json.loads(result.index_meta()["v8unpack_form_projections_json"])
    assert summary["failed"] == 4


def test_unknown_element_type_is_reported_without_guessing(tmp_path):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")
    path = tmp_path / "CommonForm" / "Форма" / "CommonForm.elem.json"
    value = json.loads(path.read_text())
    value["tree"] = [{"name": "Неизвестный", "type": "FutureWidget"}]
    _write(path, value)

    result = collect_v8unpack_forms(tmp_path)

    assert result.status == "partial"
    assert result.unproven_fragments == 1
    assert not any(row[3] == "element" for row in result.rows)
    assert result.diagnostics[0]["role"] == "element_type"


def test_unknown_form_element_pair_is_unsupported(tmp_path):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")
    path = tmp_path / "CommonForm" / "Форма" / "CommonForm.json"
    value = json.loads(path.read_text())
    value["Тип формы"] = "0"
    _write(path, value)

    result = collect_v8unpack_forms(tmp_path)

    assert (result.indexed, result.failed, result.unsupported) == (0, 0, 1)
    assert result.rows == []


def test_oversized_required_json_fails_form(tmp_path, monkeypatch):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")
    monkeypatch.setattr("rlm_tools_bsl.v8unpack_metadata.MAX_JSON_BYTES", 100)

    result = collect_v8unpack_forms(tmp_path)

    assert (result.indexed, result.failed, result.unsupported) == (0, 1, 0)


def test_full_build_and_update_keep_identical_rows(tmp_path, monkeypatch):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")
    module = tmp_path / "CommonForm" / "Форма" / "CommonForm.obj.bsl"
    module.write_text("Процедура КомандаПробника()\nКонецПроцедуры", encoding="utf-8")
    monkeypatch.setenv("RLM_INDEX_DIR", str(tmp_path / ".index"))
    builder = IndexBuilder()
    db_path = builder.build(
        str(tmp_path),
        build_calls=False,
        build_fts=False,
        build_synonyms=False,
    )

    with sqlite3.connect(db_path) as conn:
        before = conn.execute("SELECT * FROM form_elements ORDER BY id").fetchall()
        before_meta = dict(
            conn.execute(
                "SELECT key, value FROM index_meta WHERE key LIKE 'v8unpack_form_%'"
            )
        )
    builder.update(str(tmp_path))
    with sqlite3.connect(db_path) as conn:
        after = conn.execute("SELECT * FROM form_elements ORDER BY id").fetchall()
        meta = dict(conn.execute("SELECT key, value FROM index_meta WHERE key LIKE 'v8unpack_form_%'"))

    assert after == before
    assert meta == before_meta
    assert meta["v8unpack_form_status"] == "complete"
    assert meta["v8unpack_form_total"] == "1"

    reader = IndexReader(db_path)
    helpers = make_bsl_helpers(
        base_path=str(tmp_path),
        resolve_safe=lambda path: tmp_path / path,
        read_file_fn=lambda path: (tmp_path / path).read_text(encoding="utf-8-sig"),
        grep_fn=lambda *_args, **_kwargs: [],
        glob_files_fn=lambda pattern: [path.relative_to(tmp_path).as_posix() for path in tmp_path.glob(pattern)],
        format_info=detect_format(tmp_path),
        idx_reader=reader,
    )
    parsed = helpers["parse_form"]("Форма", form_name="Форма")
    filtered = helpers["parse_form"]("Форма", handler="ПриСозданииНаСервере")
    reader.close()

    assert parsed[0]["module_path"] == "CommonForm/Форма/CommonForm.obj.bsl"
    assert parsed[0]["projections"] == {
        "attributes": "complete",
        "commands": "complete",
        "elements": "empty",
        "handlers": "complete",
    }
    assert filtered[0]["handlers"][0]["handler"] == "ПриСозданииНаСервере"
    assert filtered[0]["projections"] == parsed[0]["projections"]

    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE index_meta SET value='20' WHERE key IN ('builder_version', 'version')")
    delta = builder.update(str(tmp_path))
    with sqlite3.connect(db_path) as conn:
        flags = dict(
            conn.execute(
                "SELECT key, value FROM index_meta "
                "WHERE key IN ('builder_version', 'has_calls', 'has_fts', 'has_synonyms')"
            )
        )
    assert delta["rebuild_reason"] == "schema upgrade v20->21"
    assert flags == {
        "builder_version": "21",
        "has_calls": "0",
        "has_fts": "0",
        "has_synonyms": "0",
    }


def test_refresh_failure_preserves_previous_layer(tmp_path, monkeypatch):
    _root(tmp_path)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT)")
    _refresh_form_elements(conn, str(tmp_path), build_metadata=True)
    marker = ("Объект", "Категория", "Форма", "form", "", "", "", "", "", "", "", 0, "", "old")
    conn.execute(
        "INSERT INTO form_elements "
        "(object_name, category, form_name, kind, scope, element_name, "
        "element_type, event, handler, data_path, main_table, "
        "attribute_is_main, extra_json, file) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        marker,
    )
    monkeypatch.setattr(
        "rlm_tools_bsl.bsl_index.collect_v8unpack_forms",
        lambda _path, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError, match="boom"):
        _refresh_form_elements(conn, str(tmp_path), build_metadata=True)

    assert conn.execute("SELECT file FROM form_elements").fetchall() == [("old",)]


@pytest.mark.parametrize("failure_point", ["rows", "meta"])
def test_refresh_failure_inside_savepoint_preserves_previous_layer(tmp_path, failure_point):
    _root(tmp_path)
    _form(tmp_path, "CommonForm", "Форма", "CommonForm", "Форма")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT)")
    _refresh_form_elements(conn, str(tmp_path), build_metadata=True)
    old_rows = conn.execute("SELECT * FROM form_elements ORDER BY id").fetchall()
    old_meta = dict(conn.execute("SELECT key, value FROM index_meta WHERE key LIKE 'v8unpack_form_%'"))
    if failure_point == "rows":
        conn.execute(
            "CREATE TRIGGER fail_form_rows BEFORE INSERT ON form_elements BEGIN SELECT RAISE(ABORT, 'boom rows'); END"
        )
    else:
        conn.execute(
            "CREATE TRIGGER fail_form_meta BEFORE INSERT ON index_meta "
            "WHEN NEW.key='v8unpack_form_status' "
            "BEGIN SELECT RAISE(ABORT, 'boom meta'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="boom"):
        _refresh_form_elements(conn, str(tmp_path), build_metadata=True)

    assert conn.execute("SELECT * FROM form_elements ORDER BY id").fetchall() == old_rows
    assert dict(conn.execute("SELECT key, value FROM index_meta WHERE key LIKE 'v8unpack_form_%'")) == old_meta


def test_disabling_metadata_clears_previous_form_layer(tmp_path):
    _root(tmp_path)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT)")
    _refresh_form_elements(conn, str(tmp_path), build_metadata=True)
    conn.execute(
        "INSERT INTO form_elements "
        "(object_name, category, form_name, kind, file) "
        "VALUES ('Объект', 'Категория', 'Форма', 'form', 'old')"
    )

    _refresh_form_elements(conn, str(tmp_path), build_metadata=False)

    assert conn.execute("SELECT COUNT(*) FROM form_elements").fetchone()[0] == 0

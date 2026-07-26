import json
from pathlib import Path
import sqlite3

import pytest

from rlm_tools_bsl.bsl_helpers import make_bsl_helpers
from rlm_tools_bsl.bsl_index import IndexBuilder, IndexReader, _refresh_form_elements
from rlm_tools_bsl.format_detector import detect_format
from rlm_tools_bsl.v8unpack_forms import (
    V8UNPACK_FORM_FAMILIES,
    collect_v8unpack_forms,
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
) -> None:
    if family == "CommonForm":
        folder = tmp_path / family / form_name
    else:
        folder = tmp_path / family / owner / form_kind / form_name
    _write(
        folder / f"{form_kind}.json",
        {
            "name": form_name,
            "obj_version": "13",
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
    raw_event: str = "70001",
    handler: str = "ОбычныйПриОткрытии",
) -> Path:
    _form(
        tmp_path,
        "Document",
        "Документ",
        "DocumentForm",
        "Форма",
        element_version=element_version,
    )
    folder = tmp_path / "Document" / "Документ" / "DocumentForm" / "Форма"
    main_path = folder / "DocumentForm.json"
    main = json.loads(main_path.read_text())
    main["Тип формы"] = "0"
    slot = 1 if element_version == "0-26" else 2
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


@pytest.mark.parametrize("element_version", ["0-26", "0-5-1", "0-20-16", "0-23-16", "0-25-16"])
def test_other_ordinary_versions_decode_proven_handlers(tmp_path, element_version):
    _root(tmp_path)
    _ordinary_form(tmp_path, element_version=element_version)

    result = collect_v8unpack_forms(tmp_path)

    assert not any(row[3] == "command" for row in result.rows)
    assert any(row[3] == "handler" and row[7] == "OnOpen" for row in result.rows)
    marker = next(row for row in result.rows if row[3] == "form")
    projections = json.loads(marker[12])["projections"]
    assert projections["handlers"] == "complete"
    assert projections["commands"] == "unsupported"


def test_unknown_ordinary_event_is_not_guessed(tmp_path):
    _root(tmp_path)
    _ordinary_form(tmp_path, raw_event="79999")

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
    builder.update(str(tmp_path))
    with sqlite3.connect(db_path) as conn:
        after = conn.execute("SELECT * FROM form_elements ORDER BY id").fetchall()
        meta = dict(conn.execute("SELECT key, value FROM index_meta WHERE key LIKE 'v8unpack_form_%'"))

    assert after == before
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
        conn.execute("UPDATE index_meta SET value='19' WHERE key IN ('builder_version', 'version')")
    delta = builder.update(str(tmp_path))
    with sqlite3.connect(db_path) as conn:
        flags = dict(
            conn.execute(
                "SELECT key, value FROM index_meta "
                "WHERE key IN ('builder_version', 'has_calls', 'has_fts', 'has_synonyms')"
            )
        )
    assert delta["rebuild_reason"] == "schema upgrade v19->20"
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
        lambda _path: (_ for _ in ()).throw(RuntimeError("boom")),
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

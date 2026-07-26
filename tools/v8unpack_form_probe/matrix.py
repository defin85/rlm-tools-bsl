#!/usr/bin/env python3
"""Build one minimal v8unpack CF delta for every ordinary-form binding class."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def quoted(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def pointer_parts(pointer: str) -> list[str | int]:
    result = []
    for part in pointer.removeprefix("/").split("/"):
        value = part.replace("~1", "/").replace("~0", "~")
        result.append(int(value) if value.isdigit() else value)
    return result


def at_pointer(value: object, pointer: str) -> object:
    for part in pointer_parts(pointer):
        value = value[part]  # type: ignore[index]
    return value


def json_differences(left: object, right: object, path: tuple[object, ...] = ()):
    if type(left) is not type(right):
        yield path, left, right
    elif isinstance(left, dict):
        for key in sorted(left.keys() | right.keys()):
            if key not in left:
                yield path + (key,), None, right[key]
            elif key not in right:
                yield path + (key,), left[key], None
            else:
                yield from json_differences(left[key], right[key], path + (key,))
    elif isinstance(left, list):
        if len(left) != len(right):
            yield path + ("length",), len(left), len(right)
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            yield from json_differences(left_item, right_item, path + (index,))
    elif left != right:
        yield path, left, right


def json_pointer(path: tuple[object, ...]) -> str:
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in path)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run(command: list[str]) -> None:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)}\n{result.stdout}")


def class_key(row: dict) -> tuple[str, ...]:
    return (
        row["local_version"],
        row["element_version"],
        row["positional_path"],
        row["scope"],
        row["element_type"],
        row["raw_event"],
    )


def build_probe_class(
    class_id: str,
    sequence: int,
    key: tuple[str, ...],
    row: dict,
    *,
    source_root: Path,
    skeleton_root: Path,
    output_root: Path,
    v8unpack: Path,
    ibcmd: Path,
    ib_dir: Path,
    data_dir: Path,
) -> dict:
    class_root = output_root / class_id
    base_tree = class_root / "base-tree"
    changed_tree = class_root / "changed-tree"
    shutil.copytree(skeleton_root, base_tree)

    target_dir = base_tree / "CommonForm" / "ПробнаяФорма"
    target_main_path = target_dir / "CommonForm.json"
    target_elements_path = target_dir / "CommonForm.elem.json"
    donor_source = Path(row["source_path"])
    donor_main_name = donor_source.name.replace(".elem.json", ".json")
    donor_elements_name = (
        donor_source.name
        if donor_source.name.endswith(".elem.json")
        else donor_source.name.replace(".json", ".elem.json")
    )
    donor_main = read_json(source_root / donor_source.with_name(donor_main_name))
    donor_elements = read_json(source_root / donor_source.with_name(donor_elements_name))
    target_main = read_json(target_main_path)
    for field in ("obj_version", "Тип формы", "Версия элементов формы", "form"):
        target_main[field] = donor_main[field]
    write_json(target_main_path, target_main)
    write_json(target_elements_path, donor_elements)

    shutil.copytree(base_tree, changed_tree)
    relative_source = (
        Path("CommonForm/ПробнаяФорма/CommonForm.elem.json")
        if row["source_path"].endswith(".elem.json")
        else Path("CommonForm/ПробнаяФорма/CommonForm.json")
    )
    changed_source_path = changed_tree / relative_source
    changed_source = read_json(changed_source_path)
    transplant_pointer = row["json_pointer"]
    if relative_source.name == "CommonForm.elem.json":
        element_key = pointer_parts(row["json_pointer"])[1]
        prefix = f"/data/{str(element_key).replace('~', '~0').replace('/', '~1')}"
        transplant_pointer = row["json_pointer"].removeprefix(prefix)
        binding = at_pointer(changed_source["data"][element_key], transplant_pointer)
    else:
        binding = at_pointer(changed_source, transplant_pointer)
    if (
        not isinstance(binding, list)
        or len(binding) < 3
        or binding[0] != "3"
        or not isinstance(binding[2], list)
        or len(binding[2]) < 2
    ):
        raise ValueError(f"invalid binding at {row['json_pointer']}")
    changed_handler = f"ПробаКласса{sequence:03d}"
    binding[1] = quoted(changed_handler)
    binding[2][1] = quoted(changed_handler)
    write_json(changed_source_path, changed_source)

    base_raw_cf = class_root / "base-raw.cf"
    changed_raw_cf = class_root / "changed-raw.cf"
    base_cf = class_root / "base.cf"
    changed_cf = class_root / "changed.cf"
    base_roundtrip = class_root / "base-json"
    changed_roundtrip = class_root / "changed-json"
    run([str(v8unpack), "-B", str(base_tree), str(base_raw_cf)])
    run([str(v8unpack), "-B", str(changed_tree), str(changed_raw_cf)])
    for source_cf, normalized_cf in ((base_raw_cf, base_cf), (changed_raw_cf, changed_cf)):
        run(
            [
                str(ibcmd),
                "config",
                "load",
                f"--data={data_dir}",
                f"--database-path={ib_dir}",
                str(source_cf),
            ]
        )
        run(
            [
                str(ibcmd),
                "config",
                "save",
                f"--data={data_dir}",
                f"--database-path={ib_dir}",
                str(normalized_cf),
            ]
        )
    run([str(v8unpack), "-E", str(base_cf), str(base_roundtrip)])
    run([str(v8unpack), "-E", str(changed_cf), str(changed_roundtrip)])

    base_roundtrip_source = read_json(base_roundtrip / relative_source)
    changed_roundtrip_source = read_json(changed_roundtrip / relative_source)
    differences = [
        {
            "pointer": json_pointer(path),
            "before": before,
            "after": after,
        }
        for path, before, after in json_differences(
            base_roundtrip_source,
            changed_roundtrip_source,
        )
    ]
    if len(differences) != 2 or {item["after"] for item in differences} != {quoted(changed_handler)}:
        raise ValueError(f"non-minimal round-trip delta: {differences}")
    delta_path = class_root / "delta.json"
    write_json(delta_path, differences)
    return {
        "class_id": class_id,
        "class_key": list(key),
        "status": "success",
        "representative": row,
        "changed_handler": changed_handler,
        "delta": differences,
        "sha256": {
            "base_cf": sha256(base_cf),
            "changed_cf": sha256(changed_cf),
            "delta": sha256(delta_path),
        },
    }


def build_matrix(
    inventory_path: Path,
    source_root: Path,
    skeleton_root: Path,
    output_root: Path,
    v8unpack: Path,
    ibcmd: Path,
) -> dict:
    inventory_path = inventory_path.resolve()
    source_root = source_root.resolve()
    skeleton_root = skeleton_root.resolve()
    output_root = output_root.resolve()
    v8unpack = v8unpack.resolve()
    ibcmd = ibcmd.resolve()
    inventory = read_json(inventory_path)
    candidates_by_class: dict[tuple[str, ...], list[dict]] = {}

    def representative_priority(row: dict) -> tuple:
        source = source_root / row["source_path"]
        main = source.with_name(source.name.replace(".elem.json", ".json"))
        elements = source if source.name.endswith(".elem.json") else source.with_name(source.name.replace(".json", ".elem.json"))
        return (
            row["family"] != "CommonForm",
            main.stat().st_size + elements.stat().st_size,
            row["candidate_id"],
        )

    for row in inventory["rows"]:
        candidates_by_class.setdefault(class_key(row), []).append(row)

    output_root.mkdir(parents=True, exist_ok=True)
    ib_dir = output_root / "ib"
    data_dir = output_root / "data"
    data_dir.mkdir()
    run(
        [
            str(ibcmd),
            "infobase",
            "create",
            f"--data={data_dir}",
            f"--database-path={ib_dir}",
            "--locale=ru_RU",
            "--create-database",
        ]
    )
    results = []
    for sequence, (key, candidates) in enumerate(sorted(candidates_by_class.items()), 1):
        class_id = f"class-{sequence:03d}"
        ordered = sorted(candidates, key=representative_priority)
        shortlist = ordered[:5]
        seen_families = {row["family"] for row in shortlist}
        for row in ordered:
            if row["family"] not in seen_families:
                shortlist.append(row)
                seen_families.add(row["family"])
        errors = []
        result = None
        for row in shortlist:
            class_root = output_root / class_id
            if class_root.exists():
                shutil.rmtree(class_root)
            try:
                result = build_probe_class(
                    class_id,
                    sequence,
                    key,
                    row,
                    source_root=source_root,
                    skeleton_root=skeleton_root,
                    output_root=output_root,
                    v8unpack=v8unpack,
                    ibcmd=ibcmd,
                    ib_dir=ib_dir,
                    data_dir=data_dir,
                )
                result["attempts"] = len(errors) + 1
                break
            except Exception as exc:
                errors.append(
                    {
                        "candidate_id": row["candidate_id"],
                        "family": row["family"],
                        "error": str(exc),
                    }
                )
        if result is None:
            result = {
                "class_id": class_id,
                "class_key": list(key),
                "status": "failed",
                "representative": shortlist[0],
                "attempts": len(errors),
                "errors": errors,
            }
        results.append(result)
    report = {
        "schema": "v8unpack_ordinary_form_probe_matrix_v1",
        "classes": len(results),
        "success": sum(result["status"] == "success" for result in results),
        "failed": sum(result["status"] == "failed" for result in results),
        "results": results,
    }
    write_json(output_root / "matrix.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--skeleton-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--v8unpack", type=Path, required=True)
    parser.add_argument("--ibcmd", type=Path, required=True)
    args = parser.parse_args()
    report = build_matrix(
        args.inventory,
        args.source_root,
        args.skeleton_root,
        args.output,
        args.v8unpack,
        args.ibcmd,
    )
    print(
        json.dumps(
            {
                "classes": report["classes"],
                "success": report["success"],
                "failed": report["failed"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

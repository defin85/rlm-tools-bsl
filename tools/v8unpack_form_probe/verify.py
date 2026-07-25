#!/usr/bin/env python3
"""Verify the minimal paired XML/JSON managed-form contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


NS = {
    "f": "http://v8.1c.ru/8.3/xcf/logform",
    "v8": "http://v8.1c.ru/8.1/data/core",
}
TYPE_UUIDS = {"2fdc88ec-7c9b-43cd-8ba5-873f043bdd88": "v8:StandardPeriod"}


def xml_projection(path: Path) -> dict:
    root = ET.parse(path).getroot()
    return {
        "handlers": [
            {"scope": "form", "event": node.attrib["name"], "handler": node.text or ""}
            for node in root.findall("./f:Events/f:Event", NS)
        ],
        "commands": [
            {
                "name": node.attrib["name"],
                "action": node.findtext("f:Action", default="", namespaces=NS),
            }
            for node in root.findall("./f:Commands/f:Command", NS)
        ],
        "attributes": [
            {
                "name": node.attrib["name"],
                "types": ",".join(
                    child.text or "" for child in node.findall("./f:Type/v8:Type", NS)
                ),
                "main": node.findtext(
                    "f:MainAttribute", default="false", namespaces=NS
                ).lower() == "true",
            }
            for node in root.findall("./f:Attributes/f:Attribute", NS)
        ],
        "data_paths": [
            {
                "element": node.attrib["name"],
                "data_path": node.findtext("f:DataPath", default="", namespaces=NS),
            }
            for node in root.findall("./f:ChildItems/*", NS)
            if node.find("f:DataPath", NS) is not None
        ],
    }


def json_projection(main_path: Path, elements_path: Path) -> dict:
    main = json.loads(main_path.read_text(encoding="utf-8-sig"))
    elements = json.loads(elements_path.read_text(encoding="utf-8-sig"))
    props = elements["props"]
    commands = elements["commands"]
    handler = main["form"][0][0][1][19][2]
    return {
        "handlers": [
            {
                "scope": "form",
                "event": "OnCreateAtServer",
                "handler": handler[1:-1],
            }
        ],
        "commands": [
            {
                "name": command["name"],
                "action": command["raw"][8][1:-1],
            }
            for command in commands
        ],
        "attributes": [
            {
                "name": prop["name"],
                "types": TYPE_UUIDS[prop["raw"][5][1][1]],
                "main": len(prop["raw"]) > 10 and prop["raw"][10] == "1",
            }
            for prop in props
        ],
        "data_paths": [
            {
                "element": name,
                "data_path": data["ПутьКДанным"],
            }
            for name, data in elements["data"].items()
            if "ПутьКДанным" in data
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", type=Path)
    parser.add_argument("main_json", type=Path)
    parser.add_argument("elements_json", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    xml = xml_projection(args.xml)
    json_value = json_projection(args.main_json, args.elements_json)
    if xml != json_value:
        raise SystemExit(
            json.dumps({"xml": xml, "json": json_value}, ensure_ascii=False, indent=2)
        )
    args.output.write_text(
        json.dumps({"status": "success", "projection": xml}, ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

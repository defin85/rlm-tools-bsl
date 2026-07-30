"""Strict decoder for verified v8unpack metadata contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import stat
import uuid

from rlm_tools_bsl.bsl_xml_parsers import canonicalize_type_ref, normalize_type_string

MAX_JSON_BYTES = 16 * 1024 * 1024
V8UNPACK_METADATA_CONTRACTS = {
    "802": frozenset({"1.2.9"}),
    "803": frozenset({"1.2.6"}),
}
V8UNPACK_DIAGNOSTIC_ROLES = {
    "malformed_required_json": frozenset({"configuration", "main", "id"}),
    "missing_required_json": frozenset({"main", "id"}),
    "unsupported_v8unpack_version": frozenset({"configuration"}),
    "unsupported_object_version": frozenset({"configuration"}),
    "unsupported_header_shape": frozenset(
        {
            "owner",
            "attribute",
            "dimension",
            "resource",
            "tabular_section",
            "tabular_attribute",
        }
    ),
    "unsupported_header_facet": frozenset(),
    "supported_header_facet": frozenset(),
    "unresolved_metadata_uuid": frozenset({"type"}),
    "unsupported_json_role": frozenset({"filename"}),
}
OWNER_OBJECT_VERSION_OVERRIDES = {
    "CommonForm": frozenset({"13"}),
}

# Closed XML↔JSON evidence registry for obj_version 802 owner header facets.
# Values are (classification, XML semantic, target projection, supported).
V8UNPACK_FACET_CONTRACT_802: dict[tuple[str, int | None, str], tuple[str, str, str | None, bool]] = {
    ("Catalog", 3, "3daea016-69b7-4ed4-9453-127911372fe6"): (
        "informational",
        "Template",
        None,
        False,
    ),
    ("Catalog", 4, "4fe87c89-9ad4-43f6-9fdb-9dc83b3879c6"): (
        "informational",
        "Command",
        None,
        False,
    ),
    ("Catalog", 7, "fdf816d2-1ead-11d5-b975-0050bae0a95d"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("Document", 4, "3daea016-69b7-4ed4-9453-127911372fe6"): (
        "informational",
        "Template",
        None,
        False,
    ),
    ("Document", 6, "b544fc6a-2ba3-4885-8fb2-cb289fb6d65e"): (
        "informational",
        "Command",
        None,
        False,
    ),
    ("Document", 7, "fb880e93-47d7-4127-9357-a20e69c17545"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("InformationRegister", 5, "13134204-f60b-11d5-a3c7-0050bae0a776"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("InformationRegister", 6, "3daea016-69b7-4ed4-9453-127911372fe6"): (
        "informational",
        "Template",
        None,
        False,
    ),
    ("InformationRegister", 8, "b44ba719-945c-445c-8aab-1088fa4df16e"): (
        "informational",
        "Command",
        None,
        False,
    ),
    ("AccumulationRegister", 8, "b64d9a44-1642-11d6-a3c7-0050bae0a776"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("AccountingRegister", 8, "d3b5d6eb-4ea2-4610-a3e2-624d4e815934"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("ChartOfCharacteristicType", 7, "eb2b78a8-40a6-4b7e-b1b3-6ca9966cbc94"): (
        "projected",
        "Form",
        "form_elements",
        True,
    ),
    ("CommonForm", None, "obj_version:9"): ("projected", "Form", "form_elements", True),
    ("CommonForm", None, "obj_version:12"): ("projected", "Form", "form_elements", True),
    ("Constant", 13, "ConstantValueKey"): (
        "blocked",
        "GeneratedType",
        None,
        False,
    ),
}

# kind -> (SQLite category, canonical reference head)
V8UNPACK_METADATA_IDENTITY_MAP: dict[str, tuple[str, str]] = {
    "Catalog": ("Catalogs", "Catalog"),
    "Document": ("Documents", "Document"),
    "Enum": ("Enums", "Enum"),
    "InformationRegister": ("InformationRegisters", "InformationRegister"),
    "AccumulationRegister": ("AccumulationRegisters", "AccumulationRegister"),
    "AccountingRegister": ("AccountingRegisters", "AccountingRegister"),
    "CalculationRegister": ("CalculationRegisters", "CalculationRegister"),
    "ChartOfAccounts": ("ChartsOfAccounts", "ChartOfAccounts"),
    "ChartOfCharacteristicType": ("ChartsOfCharacteristicTypes", "ChartOfCharacteristicTypes"),
    "ChartOfCalculationTypes": ("ChartsOfCalculationTypes", "ChartOfCalculationTypes"),
    "ExchangePlan": ("ExchangePlans", "ExchangePlan"),
    "BusinessProcess": ("BusinessProcesses", "BusinessProcess"),
    "Task": ("Tasks", "Task"),
    "Constant": ("Constants", "Constant"),
    "DefinedType": ("DefinedTypes", "DefinedType"),
    "Subsystem": ("Subsystems", "Subsystem"),
    "Role": ("Roles", "Role"),
    "FunctionalOption": ("FunctionalOptions", "FunctionalOption"),
    "EventSubscription": ("EventSubscriptions", "EventSubscription"),
    "ScheduledJob": ("ScheduledJobs", "ScheduledJob"),
    "CommonModule": ("CommonModules", "CommonModule"),
    "CommonForm": ("CommonForms", "CommonForm"),
    "CommonCommand": ("CommonCommands", "CommonCommand"),
    "Report": ("Reports", "Report"),
    "DataProcessor": ("DataProcessors", "DataProcessor"),
    "DocumentJournal": ("DocumentJournals", "DocumentJournal"),
}

# Exact header[0] group positions and UUID tags verified against paired CF XML.
# tuple entries are (index, UUID tag, row kind); tabular groups contain
# 888744e1-b616-11d4-9436-004095e12fc7 child attributes at item[2].
STRUCTURAL_CONTRACT: dict[str, tuple[tuple[int, str, str], ...]] = {
    "Catalog": (
        (6, "cf4abea7-37b2-11d4-940f-008048da11f9", "attribute"),
        (5, "932159f9-95b2-4e76-a8dd-8849fe5c5ded", "tabular_section"),
    ),
    "Document": (
        (5, "45e46cbc-3e24-4165-8b7b-cc98a6f80211", "attribute"),
        (3, "21c53e09-8950-4b5e-a6a0-1054f1bbc274", "tabular_section"),
    ),
    "InformationRegister": (
        (4, "13134203-f60b-11d5-a3c7-0050bae0a776", "dimension"),
        (3, "13134202-f60b-11d5-a3c7-0050bae0a776", "resource"),
        (7, "a2207540-1400-11d6-a3c7-0050bae0a776", "attribute"),
    ),
    "AccumulationRegister": (
        (7, "b64d9a43-1642-11d6-a3c7-0050bae0a776", "dimension"),
        (5, "b64d9a41-1642-11d6-a3c7-0050bae0a776", "resource"),
        (6, "b64d9a42-1642-11d6-a3c7-0050bae0a776", "attribute"),
    ),
    "AccountingRegister": (
        (3, "35b63b9d-0adf-4625-a047-10ae874c19a3", "dimension"),
        (5, "63405499-7491-4ce3-ac72-43433cbe4112", "resource"),
        (7, "9d28ee33-9c7e-4a1b-8f13-50aa9b36607b", "attribute"),
    ),
    "ChartOfCharacteristicType": (
        (3, "31182525-9346-4595-81f8-6f91a72ebe06", "attribute"),
        (5, "54e36536-7863-42fd-bea3-c5edd3122fdc", "tabular_section"),
    ),
}

_STRUCTURAL_SYNONYM_PREFIX = {
    "Catalog": "Справочник",
    "Document": "Документ",
    "InformationRegister": "Регистр сведений",
    "AccumulationRegister": "Регистр накопления",
    "AccountingRegister": "Регистр бухгалтерии",
    "ChartOfCharacteristicType": "План видов характеристик",
}

TABULAR_ATTRIBUTE_TAG = "888744e1-b616-11d4-9436-004095e12fc7"
_FORM_KIND_BY_FAMILY = {
    "AccountingRegister": "AccountingRegisterForm",
    "AccumulationRegister": "AccumulationRegisterForm",
    "Catalog": "CatalogForm",
    "ChartOfCharacteristicType": "ChartOfCharacteristicTypeForm",
    "Document": "DocumentForm",
    "InformationRegister": "InformationRegisterForm",
}

# Exact TypeId positions under header[0][1]. Only positions observed in paired
# XML/JSON are declared; absent forms are not guessed.
GENERATED_TYPE_ID_POSITIONS: dict[str, tuple[tuple[int, str], ...]] = {
    "Catalog": (
        (1, "CatalogObject"),
        (3, "CatalogRef"),
        (5, "CatalogSelection"),
        (7, "CatalogList"),
        (34, "CatalogManager"),
    ),
    "Document": (
        (1, "DocumentObject"),
        (3, "DocumentRef"),
        (5, "DocumentSelection"),
        (7, "DocumentList"),
        (26, "DocumentManager"),
    ),
    "Enum": ((1, "EnumRef"), (3, "EnumManager"), (7, "EnumList")),
    "InformationRegister": (
        (1, "InformationRegisterRecord"),
        (3, "InformationRegisterManager"),
        (5, "InformationRegisterSelection"),
        (7, "InformationRegisterList"),
        (9, "InformationRegisterRecordSet"),
        (11, "InformationRegisterRecordKey"),
        (13, "InformationRegisterRecordManager"),
    ),
    "AccumulationRegister": (
        (1, "AccumulationRegisterRecord"),
        (3, "AccumulationRegisterManager"),
        (5, "AccumulationRegisterSelection"),
        (7, "AccumulationRegisterList"),
        (9, "AccumulationRegisterRecordSet"),
        (11, "AccumulationRegisterRecordKey"),
    ),
    "AccountingRegister": (
        (1, "AccountingRegisterRecord"),
        (3, "AccountingRegisterExtDimensions"),
        (5, "AccountingRegisterRecordSet"),
        (7, "AccountingRegisterRecordKey"),
        (9, "AccountingRegisterSelection"),
        (11, "AccountingRegisterList"),
        (13, "AccountingRegisterManager"),
    ),
    "ChartOfAccounts": (
        (1, "ChartOfAccountsObject"),
        (3, "ChartOfAccountsRef"),
        (5, "ChartOfAccountsSelection"),
        (7, "ChartOfAccountsList"),
        (9, "ChartOfAccountsManager"),
        (11, "ChartOfAccountsExtDimensionTypes"),
        (13, "ChartOfAccountsExtDimensionTypesRow"),
    ),
    "ChartOfCharacteristicType": (
        (1, "ChartOfCharacteristicTypesObject"),
        (3, "ChartOfCharacteristicTypesRef"),
        (5, "ChartOfCharacteristicTypesSelection"),
        (7, "ChartOfCharacteristicTypesList"),
        (9, "Characteristic"),
        (11, "ChartOfCharacteristicTypesManager"),
    ),
    "ChartOfCalculationTypes": (
        (2, "ChartOfCalculationTypesObject"),
        (4, "ChartOfCalculationTypesRef"),
        (6, "ChartOfCalculationTypesSelection"),
        (8, "ChartOfCalculationTypesList"),
        (10, "ChartOfCalculationTypesManager"),
        (12, "DisplacingCalculationTypes"),
        (14, "DisplacingCalculationTypesRow"),
        (16, "BaseCalculationTypes"),
        (18, "BaseCalculationTypesRow"),
        (20, "LeadingCalculationTypes"),
        (22, "LeadingCalculationTypesRow"),
    ),
    "ExchangePlan": (
        (1, "ExchangePlanObject"),
        (3, "ExchangePlanRef"),
        (5, "ExchangePlanSelection"),
        (7, "ExchangePlanList"),
        (9, "ExchangePlanManager"),
    ),
    "Constant": ((2, "ConstantManager"), (4, "ConstantValueManager"), (13, "ConstantValueKey")),
    "Report": ((1, "ReportObject"), (12, "ReportManager")),
    "DataProcessor": ((1, "DataProcessorObject"), (7, "DataProcessorManager")),
    "DocumentJournal": ((1, "DocumentJournalList"), (8, "DocumentJournalManager"), (10, "DocumentJournalSelection")),
}

GENERATED_TYPE_ID_POSITION_OVERRIDES_803 = {
    "AccountingRegister": (
        (2, "AccountingRegisterRecord"),
        (4, "AccountingRegisterExtDimensions"),
        (6, "AccountingRegisterRecordSet"),
        (8, "AccountingRegisterRecordKey"),
        (10, "AccountingRegisterSelection"),
        (12, "AccountingRegisterList"),
        (14, "AccountingRegisterManager"),
    ),
    "Enum": ((1, "EnumRef"), (3, "EnumManager"), (7, "EnumList")),
    "Constant": ((2, "ConstantManager"), (4, "ConstantValueManager")),
    "DataProcessor": (),
}
GENERATED_TYPE_ID_POSITION_VARIANTS_803 = {
    "Enum": ((8, "EnumList"),),
}
GENERATED_TYPE_ID_JSON_KEYS_803 = {
    "DataProcessor": (
        ("manager_uuid1", "DataProcessorObject"),
        ("manager_uuid3", "DataProcessorManager"),
    ),
}


def generated_type_contract(
    object_version: str,
    kind: str,
) -> tuple[tuple[tuple[int, str], ...], tuple[tuple[str, str], ...]]:
    positions = GENERATED_TYPE_ID_POSITIONS.get(kind, ())
    if object_version == "803":
        positions = GENERATED_TYPE_ID_POSITION_OVERRIDES_803.get(kind, positions)
        return positions, GENERATED_TYPE_ID_JSON_KEYS_803.get(kind, ())
    return positions, ()


def generated_type_coverage_contract(
    object_version: str,
    kind: str,
) -> tuple[tuple[str, str], ...]:
    positions, id_keys = generated_type_contract(object_version, kind)
    variants = GENERATED_TYPE_ID_POSITION_VARIANTS_803.get(kind, ()) if object_version == "803" else ()
    return tuple((str(source), type_form) for source, type_form in (*positions, *variants, *id_keys))


# Platform types verified against the paired CF XML oracle. ``None`` is the
# unconstrained component: XML represents it as an empty type list or omits it
# when concrete primitive components follow.
BUILTIN_TYPE_UUIDS: dict[str, str | None] = {
    "e199ca70-93cf-46ce-a54b-6edc88c3a296": "ValueStorage",
    "fc01b5df-97fe-449b-83d4-218a090e681e": "UUID",
    "ffbe8ea3-ce5f-4118-842e-03a6fafc1d42": None,
    "280f5f0e-9c8a-49cc-bf6d-4d296cc17a63": None,
    "38bfd075-3e63-4aaa-a93e-94521380d579": None,
    "0a52f9de-73ea-4507-81e8-66217bead73a": None,
    "e61ef7b8-f3e1-4f4b-8ac7-676e90524997": None,
    "18906d1b-33c0-4872-82f3-ce6f95b00d18": None,
    "214fa4d8-6ba4-4748-a5e1-6332b5887780": None,
    "593cd424-0877-470d-91f9-b90a982059b4": None,
    "6291e9b3-8df5-44e1-b6b2-d9fe008016c0": None,
    "99892482-ed55-4fb5-a7f7-20888820a758": None,
    "ac606d60-0209-4159-8e4c-794bc091ce38": None,
    "f04256af-e4b4-4d0a-8a65-baa878d4c6de": None,
}
BUILTIN_TYPE_UUIDS_803 = {
    key: BUILTIN_TYPE_UUIDS[key]
    for key in (
        "e199ca70-93cf-46ce-a54b-6edc88c3a296",
        "fc01b5df-97fe-449b-83d4-218a090e681e",
        "280f5f0e-9c8a-49cc-bf6d-4d296cc17a63",
    )
}


def builtin_type_contract(object_version: str) -> dict[str, str | None]:
    return BUILTIN_TYPE_UUIDS_803 if object_version == "803" else BUILTIN_TYPE_UUIDS


@dataclass(frozen=True)
class V8UnpackJsonRole:
    role: str
    path: str
    kind: str | None = None
    object_name: str | None = None


@dataclass
class V8UnpackMetadataResult:
    status: str = "complete"
    producer_version: str = ""
    object_version: str = ""
    config_name: str = ""
    config_synonym: str = ""
    metadata_objects: list[tuple] = field(default_factory=list)
    metadata_type_ids: list[tuple] = field(default_factory=list)
    metadata_attribute_names: dict[tuple[str, str, str], str] = field(default_factory=dict)
    object_attributes: list[tuple] = field(default_factory=list)
    object_synonyms: list[tuple] = field(default_factory=list)
    metadata_references: list[tuple] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    facets: list[dict] = field(default_factory=list)
    snapshot: list[dict] = field(default_factory=list)
    read_paths: set[str] = field(default_factory=set)
    generated_type_coverage: set[tuple[str, str, str]] = field(default_factory=set)
    builtin_type_coverage: set[str] = field(default_factory=set)
    type_shape_coverage: set[str] = field(default_factory=set)
    structural_coverage: set[tuple[str, str]] = field(default_factory=set)
    identity_total: int = 0
    identity_indexed: int = 0
    structural_total: int = 0
    structural_indexed: int = 0
    facet_total: int = 0
    facet_supported: int = 0
    unsupported_count: int = 0
    diagnostic_groups_total: int = 0

    def index_meta(self) -> dict[str, str]:
        return {
            "v8unpack_metadata_status": self.status,
            "v8unpack_metadata_version": self.producer_version,
            "v8unpack_metadata_producer_version": self.producer_version,
            "v8unpack_metadata_object_version": self.object_version,
            "v8unpack_metadata_identity_total": str(self.identity_total),
            "v8unpack_metadata_identity_indexed": str(self.identity_indexed),
            "v8unpack_metadata_identity_failed": str(self.identity_total - self.identity_indexed),
            "v8unpack_metadata_structural_total": str(self.structural_total),
            "v8unpack_metadata_structural_indexed": str(self.structural_indexed),
            "v8unpack_metadata_structural_failed": str(self.structural_total - self.structural_indexed),
            "v8unpack_metadata_facet_total": str(self.facet_total),
            "v8unpack_metadata_facet_supported": str(self.facet_supported),
            "v8unpack_metadata_facet_unsupported": str(self.facet_total - self.facet_supported),
            "v8unpack_metadata_facets_json": json.dumps(self.facets, ensure_ascii=False, separators=(",", ":")),
            "v8unpack_metadata_unsupported_count": str(self.unsupported_count),
            "v8unpack_metadata_diagnostic_groups_total": str(self.diagnostic_groups_total),
            "v8unpack_metadata_diagnostics_json": json.dumps(
                self.diagnostics, ensure_ascii=False, separators=(",", ":")
            ),
            "v8unpack_metadata_snapshot_json": json.dumps(self.snapshot, ensure_ascii=False, separators=(",", ":")),
        }


def classify_v8unpack_json_path(root: str | Path, path: str | Path) -> V8UnpackJsonRole | None:
    root_path = Path(root).resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    try:
        rel = candidate.resolve(strict=False).relative_to(root_path).as_posix()
    except ValueError:
        return None
    if rel == "Configuration.json":
        return V8UnpackJsonRole("configuration", rel)
    parts = rel.split("/")
    if len(parts) != 3 or parts[0] not in V8UNPACK_METADATA_IDENTITY_MAP:
        return None
    kind, object_name, filename = parts
    if filename == f"{kind}.json":
        return V8UnpackJsonRole("main", rel, kind, object_name)
    if filename == f"{kind}.id.json":
        return V8UnpackJsonRole("id", rel, kind, object_name)
    return None


def read_v8unpack_json(root: str | Path, path: str | Path) -> dict:
    root_path = Path(root).resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root_path)
    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"not a regular in-root file: {candidate}")
    if info.st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON exceeds {MAX_JSON_BYTES} bytes: {candidate}")
    with resolved.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {candidate}")
    return value


def _projected_forms(root: Path) -> tuple[set[str], set[tuple[str, str]]]:
    uuids: set[str] = set()
    common_forms: set[tuple[str, str]] = set()
    entries = (
        [
            ("CommonForm", path.name, path, "CommonForm")
            for path in sorted((root / "CommonForm").iterdir(), key=lambda item: item.name)
            if path.is_dir()
        ]
        if (root / "CommonForm").is_dir()
        else []
    )
    for family, form_kind in _FORM_KIND_BY_FAMILY.items():
        family_dir = root / family
        if not family_dir.is_dir():
            continue
        for owner_dir in sorted((path for path in family_dir.iterdir() if path.is_dir()), key=lambda path: path.name):
            forms_dir = owner_dir / form_kind
            if not forms_dir.is_dir():
                continue
            entries.extend(
                (family, owner_dir.name, form_dir, form_kind)
                for form_dir in sorted(
                    (path for path in forms_dir.iterdir() if path.is_dir()), key=lambda path: path.name
                )
            )
    for family, owner, form_dir, form_kind in entries:
        try:
            main = read_v8unpack_json(root, form_dir / f"{form_kind}.json")
            elements = read_v8unpack_json(root, form_dir / f"{form_kind}.elem.json")
            identity = read_v8unpack_json(root, form_dir / f"{form_kind}.id.json")
            if main.get("name") != form_dir.name or set(elements) != {"params", "props", "commands", "tree", "data"}:
                continue
            uuids.add(_uuid(identity["uuid"]))
            if family == "CommonForm":
                common_forms.add((family, owner))
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            continue
    return uuids, common_forms


def _unquote(value: object) -> str:
    if not isinstance(value, str) or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError("quoted string expected")
    return value[1:-1].replace('""', '"')


def _uuid(value: object) -> str:
    text = str(value)
    return str(uuid.UUID(text))


def _collect_descriptor_names(
    value: object,
    target: dict[tuple[str, str, str], str],
    owner: tuple[str, str],
) -> None:
    if isinstance(value, list):
        for left, right in zip(value, value[1:]):
            if isinstance(left, list) and isinstance(right, str):
                identifiers = [
                    item for item in left if isinstance(item, str) and len(item) == 36 and item.count("-") == 4
                ]
                if len(identifiers) == 1:
                    try:
                        target[(*owner, _uuid(identifiers[0]))] = _unquote(right)
                    except ValueError:
                        pass
        for item in value:
            _collect_descriptor_names(item, target, owner)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_descriptor_names(item, target, owner)


def _at(value: object, path: tuple[int, ...]) -> object:
    for index in path:
        if not isinstance(value, list) or index >= len(value):
            raise ValueError(f"missing header position {path}")
        value = value[index]
    return value


def _synonym(locales: object) -> str:
    if not isinstance(locales, list) or not locales:
        raise ValueError("locale list expected")
    count = int(locales[0])
    if len(locales) != count * 2 + 1:
        raise ValueError("invalid locale list")
    values = {_unquote(locales[i]): _unquote(locales[i + 1]) for i in range(1, len(locales), 2)}
    return values.get("ru", "").strip()


def _descriptor(item: object, *, tabular_section: bool = False) -> tuple[str, str, str]:
    path = (0, 1, 5, 1) if tabular_section else (0, 1, 1, 1)
    descriptor = _at(item, path)
    if not isinstance(descriptor, list) or len(descriptor) < 5:
        raise ValueError("invalid descriptor")
    identity = descriptor[1]
    if not isinstance(identity, list) or len(identity) < 3:
        raise ValueError("invalid identity descriptor")
    return _uuid(identity[-1]), _unquote(descriptor[2]), _synonym(descriptor[3])


def _decode_pattern(
    item: object,
    type_ids: dict[str, tuple[str, str]],
    *,
    object_version: str = "802",
    builtin_coverage: set[str] | None = None,
    shape_coverage: set[str] | None = None,
) -> tuple[str | None, list[str]]:
    pattern = _at(item, (0, 1, 1, 2))
    if not isinstance(pattern, list) or not pattern or pattern[0] != '"Pattern"':
        raise ValueError("invalid type pattern")
    types: list[str] = []
    unresolved: list[str] = []
    component_count = 0
    primitive = {'"S"': "String", '"N"': "Number", '"B"': "Boolean", '"D"': "DateTime"}
    for component in pattern[1:]:
        if not isinstance(component, list) or not component:
            raise ValueError("invalid type component")
        marker = component[0]
        component_count += 1
        if marker in primitive:
            types.append(primitive[marker])
            if shape_coverage is not None:
                shape_coverage.add("primitive")
        elif marker == '"#"' and len(component) == 2:
            type_uuid = _uuid(component[1])
            builtin_types = builtin_type_contract(object_version)
            if type_uuid in builtin_types:
                if builtin_coverage is not None:
                    builtin_coverage.add(type_uuid)
                builtin = builtin_types[type_uuid]
                if builtin:
                    types.append(builtin)
                continue
            resolved = type_ids.get(type_uuid)
            if resolved:
                if shape_coverage is not None:
                    shape_coverage.add("reference")
                canonical, type_form = resolved
                if object_version != "803" or type_form != "Characteristic":
                    types.append(f"{type_form}.{canonical.split('.', 1)[1]}")
            else:
                unresolved.append(type_uuid)
        else:
            raise ValueError("unsupported type component")
    if component_count > 1 and shape_coverage is not None:
        shape_coverage.add("composite")
    return (normalize_type_string(", ".join(types)) if not unresolved else None), unresolved


def _diagnostics(events: list[tuple[str, str, str]]) -> list[dict]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for code, role, example in events:
        roles = V8UNPACK_DIAGNOSTIC_ROLES.get(code)
        if roles is None:
            raise ValueError(f"unknown diagnostic code: {code}")
        if role not in roles:
            if code not in {"unsupported_header_facet", "supported_header_facet"}:
                raise ValueError(f"unknown diagnostic role: {code}/{role}")
            if code == "supported_header_facet" and any(role == key[2] for key in V8UNPACK_FACET_CONTRACT_802):
                pass
            else:
                _uuid(role)
        grouped.setdefault((code, role), []).append(example)
    result = []
    for (code, role), examples in sorted(grouped.items()):
        result.append({"code": code, "role": role, "count": len(examples), "examples": sorted(set(examples))[:5]})
    return result[:50]


def _apply_diagnostics(
    result: V8UnpackMetadataResult,
    events: list[tuple[str, str, str]],
) -> None:
    result.diagnostics = _diagnostics(events)
    result.unsupported_count = sum(code != "supported_header_facet" for code, _role, _example in events)
    result.diagnostic_groups_total = len({(code, role) for code, role, _example in events})
    if result.unsupported_count and result.status == "complete":
        result.status = "partial"


def _facets(
    events: list[tuple[str, int | None, str, str, str, str | None, bool, str]],
) -> list[dict]:
    grouped: dict[tuple[str, int | None, str, str, str, str | None, bool], list[str]] = {}
    for family, index, tag, classification, semantic, projection, supported, example in events:
        if classification not in {"core", "projected", "informational", "blocked"}:
            raise ValueError(f"unknown facet classification: {classification}")
        grouped.setdefault(
            (family, index, tag, classification, semantic, projection, supported),
            [],
        ).append(example)
    return [
        {
            "family": family,
            "header_index": index,
            "tag": tag,
            "classification": classification,
            "semantic": semantic,
            "projection": projection,
            "supported": supported,
            "count": len(examples),
            "owners": len(set(examples)),
            "examples": sorted(set(examples))[:5],
        }
        for (
            family,
            index,
            tag,
            classification,
            semantic,
            projection,
            supported,
        ), examples in sorted(grouped.items(), key=lambda item: tuple(str(value) for value in item[0]))
    ]


def _snapshot_row(root: Path, path: Path, owner: str) -> dict:
    info = path.stat()
    return {
        "path": path.relative_to(root).as_posix(),
        "owner": owner,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


def collect_v8unpack_metadata(root: str | Path, *, build_synonyms: bool = True) -> V8UnpackMetadataResult:
    root_path = Path(root).resolve()
    result = V8UnpackMetadataResult()
    events: list[tuple[str, str, str]] = []
    facet_events: list[tuple[str, int | None, str, str, str, str | None, bool, str]] = []
    root_file = root_path / "Configuration.json"
    try:
        config = read_v8unpack_json(root_path, root_file)
    except (OSError, ValueError, json.JSONDecodeError):
        result.status = "unsupported"
        events.append(("malformed_required_json", "configuration", "Configuration.json"))
        _apply_diagnostics(result, events)
        return result
    result.read_paths.add("Configuration.json")
    marker, object_version = config.get("v8unpack"), config.get("obj_version")
    result.producer_version = str(marker or "")
    result.object_version = str(object_version or "")
    producers = V8UNPACK_METADATA_CONTRACTS.get(object_version)
    if producers is None:
        result.status = "unsupported"
        events.append(("unsupported_object_version", "configuration", "Configuration.json"))
        _apply_diagnostics(result, events)
        return result
    if marker not in producers:
        result.status = "unsupported"
        events.append(("unsupported_v8unpack_version", "configuration", "Configuration.json"))
        _apply_diagnostics(result, events)
        return result
    result.config_name = str(config.get("name") or "")
    name2 = config.get("name2")
    result.config_synonym = str(name2.get("ru") or "").replace('""', '"').strip() if isinstance(name2, dict) else ""
    result.snapshot.append(_snapshot_row(root_path, root_file, "configuration"))
    projected_form_uuids, projected_common_forms = _projected_forms(root_path)

    owners: list[tuple[str, str, Path, dict, str]] = []
    for kind, (category, ref_head) in V8UNPACK_METADATA_IDENTITY_MAP.items():
        kind_dir = root_path / kind
        if not kind_dir.is_dir():
            continue
        for owner_dir in sorted((p for p in kind_dir.iterdir() if p.is_dir()), key=lambda p: p.name):
            result.identity_total += 1
            structural = kind in STRUCTURAL_CONTRACT
            if structural:
                result.structural_total += 1
            main = owner_dir / f"{kind}.json"
            id_file = owner_dir / f"{kind}.id.json"
            rel_main = main.relative_to(root_path).as_posix()
            rel_id = id_file.relative_to(root_path).as_posix()
            if main.is_symlink():
                events.append(("missing_required_json", "main", rel_main))
                continue
            try:
                main_data = read_v8unpack_json(root_path, main)
                result.read_paths.add(rel_main)
                object_name = str(main_data["name"])
                if not object_name or object_name != owner_dir.name:
                    raise ValueError("owner name mismatch")
                _collect_descriptor_names(
                    main_data,
                    result.metadata_attribute_names,
                    (kind, object_name),
                )
            except FileNotFoundError:
                events.append(("missing_required_json", "main", rel_main))
                continue
            except (KeyError, OSError, ValueError, json.JSONDecodeError):
                events.append(("malformed_required_json", "main", rel_main))
                continue
            if id_file.is_symlink():
                events.append(("missing_required_json", "id", rel_id))
                continue
            try:
                id_data = read_v8unpack_json(root_path, id_file)
                result.read_paths.add(rel_id)
                object_uuid = _uuid(id_data["uuid"])
            except FileNotFoundError:
                events.append(("missing_required_json", "id", rel_id))
                continue
            except (KeyError, OSError, ValueError, json.JSONDecodeError):
                events.append(("malformed_required_json", "id", rel_id))
                continue
            result.identity_indexed += 1
            result.metadata_objects.append((category, object_name, object_uuid, rel_main))
            result.snapshot.extend(
                (
                    _snapshot_row(root_path, main, f"{kind}/{object_name}"),
                    _snapshot_row(root_path, id_file, f"{kind}/{object_name}"),
                )
            )
            positions, id_keys = generated_type_contract(object_version, kind)
            owner_version = main_data.get("obj_version")
            if owner_version != object_version and owner_version not in OWNER_OBJECT_VERSION_OVERRIDES.get(kind, ()):
                if object_version == "802" and kind == "CommonForm" and owner_version in {"9", "12"}:
                    tag = f"obj_version:{owner_version}"
                    classification, semantic, projection, supported = V8UNPACK_FACET_CONTRACT_802[(kind, None, tag)]
                    form_supported = supported and (kind, object_name) in projected_common_forms
                    facet_events.append(
                        (
                            kind,
                            None,
                            tag,
                            classification,
                            semantic,
                            projection,
                            form_supported,
                            rel_main,
                        )
                    )
                    events.append(
                        (
                            "supported_header_facet" if form_supported else "unsupported_header_facet",
                            tag,
                            rel_main,
                        )
                    )
                else:
                    events.append(("unsupported_header_shape", "owner", rel_main))
                continue

            header = main_data.get("header")
            if positions:
                try:
                    _at(header, (0, 1))
                except (ValueError, TypeError):
                    events.append(("unsupported_header_shape", "owner", rel_main))
                    continue
            if object_version == "803" and kind == "Enum":
                try:
                    generated_header = _at(header, (0, 1))
                except (ValueError, TypeError):
                    generated_header = ()
                if isinstance(generated_header, list) and len(generated_header) <= 13:
                    positions = tuple(
                        (8 if type_form == "EnumList" else index, type_form) for index, type_form in positions
                    )
            generated_rows: list[tuple[str, str, str]] = []
            for index, type_form in positions:
                try:
                    type_uuid = _uuid(_at(header, (0, 1, index)))
                except (ValueError, TypeError):
                    events.append(("unsupported_header_shape", "owner", rel_main))
                    if object_version == "802" and kind == "Constant" and index == 13:
                        classification, semantic, projection, supported = V8UNPACK_FACET_CONTRACT_802[
                            (kind, index, "ConstantValueKey")
                        ]
                        facet_events.append(
                            (
                                kind,
                                index,
                                "ConstantValueKey",
                                classification,
                                semantic,
                                projection,
                                supported,
                                rel_main,
                            )
                        )
                    generated_rows = []
                    break
                generated_rows.append((type_uuid, str(index), type_form))
            else:
                for key, type_form in id_keys:
                    try:
                        type_uuid = _uuid(id_data[key])
                    except (KeyError, ValueError, TypeError):
                        events.append(("unsupported_header_shape", "owner", rel_main))
                        generated_rows = []
                        break
                    generated_rows.append((type_uuid, key, type_form))
            if (positions or id_keys) and not generated_rows:
                continue
            for type_uuid, source_position, type_form in generated_rows:
                canonical = canonicalize_type_ref(f"{ref_head}.{object_name}", fold_case=False)
                if canonical:
                    result.metadata_type_ids.append((type_uuid, canonical, type_form, rel_main))
                    result.generated_type_coverage.add((kind, source_position, type_form))
            owners.append((kind, category, main, main_data, object_name))

            for unknown in sorted(owner_dir.glob("*.json")):
                if unknown.name not in {f"{kind}.json", f"{kind}.id.json", f"{kind}.elem.json"}:
                    events.append(("unsupported_json_role", "filename", unknown.relative_to(root_path).as_posix()))

    type_refs: dict[str, set[tuple[str, str]]] = {}
    for type_uuid, canonical, type_form, _source in result.metadata_type_ids:
        type_refs.setdefault(type_uuid, set()).add((canonical, type_form))
    resolved_types = {key: sorted(values)[0] for key, values in type_refs.items() if len({v[0] for v in values}) == 1}

    for kind, category, main, data, object_name in owners:
        if kind not in STRUCTURAL_CONTRACT or data.get("obj_version") != object_version:
            continue
        rel = main.relative_to(root_path).as_posix()
        header = data.get("header")
        owner_ok = True
        if build_synonyms:
            name2 = data.get("name2")
            if isinstance(name2, dict) and name2.get("ru"):
                prefix = _STRUCTURAL_SYNONYM_PREFIX[kind]
                synonym = str(name2["ru"]).replace('""', '"').strip()
                result.object_synonyms.append((object_name, category, f"{prefix}: {synonym}", rel))
        supported_group_indexes = {index for index, _tag, _kind in STRUCTURAL_CONTRACT[kind]}
        try:
            owner_header = _at(header, (0,))
        except (ValueError, TypeError):
            owner_header = []
        for index, facet in enumerate(
            owner_header if object_version == "802" and isinstance(owner_header, list) else []
        ):
            if index in supported_group_indexes or not isinstance(facet, list):
                continue
            try:
                malformed_uuid = _uuid(facet[0])
            except (IndexError, ValueError, TypeError):
                malformed_uuid = None
            if len(facet) < 2:
                if malformed_uuid:
                    events.append(("unsupported_header_shape", "owner", rel))
                    facet_events.append((kind, index, malformed_uuid, "blocked", "Unknown", None, False, rel))
                continue
            try:
                facet_count = int(facet[1])
            except (ValueError, TypeError):
                if malformed_uuid:
                    events.append(("unsupported_header_shape", "owner", rel))
                    facet_events.append((kind, index, malformed_uuid, "blocked", "Unknown", None, False, rel))
                continue
            if facet_count <= 0:
                continue
            try:
                facet_uuid = _uuid(facet[0])
                facet_tag_valid = True
            except (ValueError, TypeError):
                facet_uuid = f"invalid:{facet[0]}"
                facet_tag_valid = False
            if len(facet) != facet_count + 2:
                events.extend(("unsupported_header_shape", "owner", rel) for _ in range(facet_count))
                facet_events.extend(
                    (kind, index, facet_uuid, "blocked", "Unknown", None, False, rel) for _ in range(facet_count)
                )
                continue
            if facet_count > 0:
                contract = (
                    V8UNPACK_FACET_CONTRACT_802.get((kind, index, facet_uuid)) if object_version == "802" else None
                )
                classification, semantic, projection, supported = contract or (
                    "blocked",
                    "Unknown",
                    None,
                    False,
                )
                for item in facet[2:]:
                    item_supported = supported
                    if semantic == "Form":
                        try:
                            item_supported = supported and _uuid(item) in projected_form_uuids
                        except (TypeError, ValueError):
                            item_supported = False
                    facet_events.append(
                        (kind, index, facet_uuid, classification, semantic, projection, item_supported, rel)
                    )
                    events.append(
                        (
                            (
                                "supported_header_facet"
                                if item_supported
                                else "unsupported_header_facet"
                                if facet_tag_valid
                                else "unsupported_header_shape"
                            ),
                            facet_uuid if facet_tag_valid else "owner",
                            rel,
                        )
                    )
        for group_index, group_tag, row_kind in STRUCTURAL_CONTRACT[kind]:
            try:
                group = _at(header, (0, group_index))
                if (
                    not isinstance(group, list)
                    or len(group) < 2
                    or group[0] != group_tag
                    or int(group[1]) != len(group) - 2
                ):
                    raise ValueError("invalid group")
            except (ValueError, TypeError):
                owner_ok = False
                events.append(("unsupported_header_shape", row_kind, rel))
                continue
            for item in group[2:]:
                if row_kind == "tabular_section":
                    try:
                        _ts_uuid, ts_name, _ts_synonym = _descriptor(item, tabular_section=True)
                        child_group = _at(item, (2,))
                        if (
                            not isinstance(child_group, list)
                            or len(child_group) < 2
                            or child_group[0] != TABULAR_ATTRIBUTE_TAG
                            or int(child_group[1]) != len(child_group) - 2
                        ):
                            raise ValueError("invalid tabular attribute group")
                    except (ValueError, TypeError):
                        owner_ok = False
                        events.append(("unsupported_header_shape", "tabular_attribute", rel))
                        continue
                    rows = ((child, "ts_attribute", ts_name) for child in child_group[2:])
                else:
                    rows = ((item, row_kind, None),)
                for child, attr_kind, ts_name in rows:
                    try:
                        _child_uuid, attr_name, attr_synonym = _descriptor(child)
                        result.metadata_attribute_names[(kind, object_name, _child_uuid)] = attr_name
                        attr_type, unresolved = _decode_pattern(
                            child,
                            resolved_types,
                            object_version=object_version,
                            builtin_coverage=result.builtin_type_coverage,
                            shape_coverage=result.type_shape_coverage,
                        )
                    except (ValueError, TypeError):
                        owner_ok = False
                        events.append(("unsupported_header_shape", "tabular_attribute" if ts_name else attr_kind, rel))
                        continue
                    result.object_attributes.append(
                        (object_name, category, attr_name, attr_synonym, attr_type, attr_kind, ts_name, rel)
                    )
                    result.structural_coverage.add((kind, attr_kind))
                    if unresolved:
                        owner_ok = False
                        events.append(("unresolved_metadata_uuid", "type", rel))
                    else:
                        for raw_type in json.loads(attr_type or "[]"):
                            canonical = canonicalize_type_ref(raw_type, fold_case=False)
                            if canonical:
                                suffix = (
                                    f"TabularSection.{ts_name}.Attribute.{attr_name}.Type"
                                    if ts_name
                                    else f"{attr_kind.title()}.{attr_name}.Type"
                                )
                                result.metadata_references.append(
                                    (
                                        object_name,
                                        category,
                                        canonical,
                                        "attribute_type",
                                        f"{V8UNPACK_METADATA_IDENTITY_MAP[kind][1]}.{object_name}.{suffix}",
                                        rel,
                                        None,
                                    )
                                )
        if owner_ok:
            result.structural_indexed += 1

    result.metadata_objects.sort()
    result.metadata_type_ids.sort()
    result.object_attributes.sort(key=lambda row: (row[1], row[0], row[5], row[6] or "", row[2]))
    result.object_synonyms.sort()
    result.metadata_references.sort()
    result.snapshot.sort(key=lambda row: row["path"])
    result.facets = _facets(facet_events)
    result.facet_total = sum(facet["count"] for facet in result.facets)
    result.facet_supported = sum(facet["count"] for facet in result.facets if facet["supported"])
    _apply_diagnostics(result, events)
    return result

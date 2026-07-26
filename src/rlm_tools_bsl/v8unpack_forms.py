"""Strict collector for verified v8unpack form contracts."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
from pathlib import Path
import uuid
import zlib

from rlm_tools_bsl.format_detector import V8UNPACK_CATEGORY_MAP
from rlm_tools_bsl.v8unpack_metadata import (
    BUILTIN_TYPE_UUIDS,
    V8UnpackMetadataResult,
    collect_v8unpack_metadata,
    read_v8unpack_json,
)


V8UNPACK_FORM_FAMILIES = {
    "AccountingRegister": "AccountingRegisterForm",
    "AccumulationRegister": "AccumulationRegisterForm",
    "Catalog": "CatalogForm",
    "ChartOfAccounts": "ChartOfAccountsForm",
    "ChartOfCalculationTypes": "ChartOfCalculationTypesForm",
    "ChartOfCharacteristicType": "ChartOfCharacteristicTypeForm",
    "DataProcessor": "Form",
    "Document": "DocumentForm",
    "DocumentJournal": "DocumentJournalForm",
    "Enum": "EnumForm",
    "ExchangePlan": "ExchangePlanForm",
    "FilterCriterion": "FilterCriterionForm",
    "InformationRegister": "InformationRegisterForm",
    "Report": "ReportForm",
}
SUPPORTED_LOCAL_VERSIONS = frozenset({"5", "7", "9", "12", "13"})
SUPPORTED_ELEMENT_VERSIONS = frozenset({"1", "0-26", "0-27", "0-5-1", "0-20-16", "0-23-16", "0-25-16"})
SUPPORTED_FORM_ELEMENT_PAIRS = frozenset(
    {("1", "1"), *(("0", version) for version in SUPPORTED_ELEMENT_VERSIONS if version != "1")}
)
PROJECTION_ROLES = ("handlers", "commands", "attributes", "elements")
PROJECTION_STATES = ("complete", "empty", "unsupported", "failed")
ELEMENT_TYPES_BY_VERSION = {
    "1": frozenset({"Button", "Decoration", "Field", "Group", "Table"}),
    "0-26": frozenset(
        {
            "Button",
            "CheckBox",
            "CommandPanel",
            "Field",
            "FieldHtml",
            "Group",
            "Image",
            "Indicator",
            "Label",
            "ListField",
            "Panel",
            "RadioBtn",
            "SelectField",
            "Separator",
            "Table",
            "TableField",
            "TextDocumentField",
        }
    ),
    "0-27": frozenset(
        {
            "Button",
            "CalendarBox",
            "Chart",
            "CheckBox",
            "CommandPanel",
            "Field",
            "FieldHtml",
            "Group",
            "Image",
            "Indicator",
            "Label",
            "ListField",
            "Panel",
            "RadioBtn",
            "SelectField",
            "Separator",
            "Table",
            "TableField",
            "TextDocumentField",
            "TrackBar",
        }
    ),
    "0-5-1": frozenset(),
    "0-20-16": frozenset(),
    "0-23-16": frozenset(),
    "0-25-16": frozenset(),
}
PLATFORM_FORM_TYPE_UUIDS: dict[str, str | None] = {
    **BUILTIN_TYPE_UUIDS,
    "e199ca70-93cf-46ce-a54b-6edc88c3a296": "v8:ValueStorage",
    "fc01b5df-97fe-449b-83d4-218a090e681e": "v8:UUID",
    "acf6192e-81ca-46ef-93a6-5a6968b78663": "v8:ValueTable",
    "4772b3b4-f4a3-49c0-a1a5-8cb5961511a3": "v8:ValueListType",
    "65abad24-838b-4987-8b35-ed9e2bd4d9c8": "cfg:DynamicList",
    "e603c0f2-92fb-4d47-8f38-a44a381cf235": "v8:ValueTree",
    "e603103e-a318-4edc-a014-b1c6cf94d49f": "mxl:SpreadsheetDocument",
    "2fdc88ec-7c9b-43cd-8ba5-873f043bdd88": "v8:StandardPeriod",
    "e6f51714-91cb-4dce-94fe-90ae3e3e1ad1": "v8ui:Picture",
    "dcfc3784-a14f-4786-ac7b-c82db5ba275f": "cfg:ConstantsSet",
    "9cd510c7-abfc-11d4-9434-004095e12fc7": "v8ui:Color",
    "cab0d12b-3c88-4993-8edc-8c3827cadc7d": "dcsset:SettingsComposer",
    "ebf766b1-f32c-11d3-9851-008048da1252": "d5p1:TextDocument",
    "140b5ff4-37b1-4df5-b5ec-a0bfd2b94f8f": "v8ui:FormattedString",
    "0387f3a2-7df5-4804-948b-4580a51e4a15": "v8:StandardBeginningDate",
    "0dda99d9-ae9f-43d2-b7ac-44f3fb0d4059": "v8:ReportBuilder",
    "4652c4ec-1d1d-4af4-b835-e33fcb43af8c": "v8:Filter",
    "5878e725-50de-4998-b589-3c56ea63e735": "v8:ChartType",
    "f5c65050-3bbb-11d5-b988-0050bae0a95d": "v8:TypeDescription",
    "b1b064f3-ae38-49bf-8c6d-390c65fd94af": "v8:ComparisonType",
    # XML writes these broad TypeSet components instead of concrete Type nodes;
    # the existing CF parser intentionally returns an empty type string for them.
    "474c3bf6-08b5-4ddc-a2ad-989cedf11583": None,
    "11e5f865-1501-40c6-b4d4-022095a296a5": None,
    "25ba5efe-2013-4090-931b-380dec461060": None,
}
PRIMITIVE_TYPES = {
    '"S"': "xs:string",
    '"N"': "xs:decimal",
    '"B"': "xs:boolean",
    '"D"': "xs:dateTime",
}
OWNER_TYPE_FOR_FAMILY = {
    "Catalog": "CatalogObject",
    "DataProcessor": "DataProcessorObject",
    "Document": "DocumentObject",
}
FORM_EVENT_UUIDS = {
    "047d4d09-961c-4bdc-8519-eef10674c35b": "AfterWrite",
    "1d632984-de3c-4b4b-ad9f-d69682a10182": "ChoiceProcessing",
    "213d1900-dcad-4616-9f20-3f077156a40f": "AfterWriteAtServer",
    "3699f6a3-9a2a-4c82-a775-6ff4824a08ca": "NotificationProcessing",
    "390d5e4b-e732-4c88-8748-9e211a416984": "OnReadAtServer",
    "3ccc650e-f631-4cae-8e33-3eaac610b5f9": "OnOpen",
    "52dbb775-1631-4fd5-8c55-1615b5881dac": "BeforeClose",
    "6b3175a5-c143-4179-a670-ef231dc0a688": "OnReopen",
    "79cea13e-f6fb-4483-905d-713326405771": "OnLoadDataFromSettingsAtServer",
    "8a5894c9-d2ff-4c1d-b433-89cc352bbfbc": "BeforeWrite",
    "8f42e083-be92-4102-b1f0-fa58452c1a63": "BeforeWriteAtServer",
    "9cc34712-da5f-4faa-a653-343d2085fbe8": "BeforeWrite",
    "9f2e5ddb-3492-4f5d-8f0d-416b8d1d5c5b": "OnCreateAtServer",
    "bf0ac0e1-bcbb-4dfe-8fc4-0b1923b461a6": "BeforeWriteAtServer",
    "c1bc0d3e-d35e-4207-a06b-ece68ed25314": "OnWriteAtServer",
    "ca21cd18-35b2-4281-b5c8-016ecc8da8ac": "OnClose",
    "e73d6384-49d2-4885-a752-a674d6ff7742": "FillCheckProcessingAtServer",
    "e773807c-0c0c-4689-a093-231ddcd6409f": "BeforeLoadDataFromSettingsAtServer",
}
ELEMENT_EVENT_UUIDS = {
    "01d80ddd-dce5-4db3-beb5-f63c97cb05b9": "OnEditEnd",
    "0d644ff6-443b-4390-86fa-7f9105e42711": "DragCheck",
    "0d8cf5b0-55eb-4d1e-960a-22c160210945": "ValueChoice",
    "11707a99-4eb9-4373-bc8c-84891483a034": "Click",
    "1282f000-23b6-4887-87f4-9e8e79db3d32": "Selection",
    "178a97c4-0ffe-4fcc-93e6-505369939da5": "AutoComplete",
    "1960479b-4d89-4eba-8b39-0aa802020558": "StartChoice",
    "2042ec93-3108-4190-b767-ec6c10dd9ff4": "OnActivate",
    "22287505-97d8-4258-a318-209e2493f7eb": "Selection",
    "2391e7b8-7235-45d7-ab7e-6ff3dc086396": "BeforeAddRow",
    "2988b2a5-c887-4928-94ae-5d0c9c31e999": "DetailProcessing",
    "2ccfdec5-583d-4eca-8319-e55de492665a": "BeforeDeleteRow",
    "411a4578-276c-4f4a-b56a-b3b01181c997": "OnChangeAreaContent",
    "526c501f-ed3f-4db4-8731-fd0324707501": "OnCurrentPageChange",
    "60edb81d-887b-478e-94ee-7fef2b13393d": "OnActivateRow",
    "6d4d6747-a823-4f61-ab31-a426572f2c6c": "DragStart",
    "70636369-514c-4662-977e-1c3976c9756c": "Tuning",
    "8ad48496-8d0b-4f6c-ae48-99d95227884b": "Drag",
    "8bfdb5eb-62dc-4851-8a2c-e983526356bf": "ChoiceProcessing",
    "97365900-eadf-4dfd-a9aa-fbb9ecabd079": "OnGetDataAtServer",
    "9874537f-454c-40ae-83e9-3b9cefbc6d08": "Click",
    "ab930362-ff94-4dcb-ad16-188805d23e3c": "BeforeRowChange",
    "ac5a9c5a-5f1d-4fc5-b88c-a187038c16d1": "Opening",
    "b3b65989-73ac-4db3-b6cb-398cb41a062f": "StartListChoice",
    "b3c10170-c5ff-4cba-b537-679e1c872b45": "OnStartEdit",
    "b50dc41b-c15a-4ebe-a17f-d01e51c47de6": "Clearing",
    "c331eb1b-d32b-4533-844c-1276600b64e3": "TextEditEnd",
    "c41e7b98-098c-433e-8ac3-56ec2a2c49e2": "BeforeLoadUserSettingsAtServer",
    "cb286ab3-3a1c-40d2-a232-6e64f624ccec": "DragEnd",
    "d710ea07-5c96-4c43-ab6e-e138d3653780": "URLProcessing",
    "da8dfb86-c5d1-4e35-a8a4-01b167a60ad3": "OnClick",
    "de65638d-a806-4a76-bc10-f62bbc86e0e7": "AfterDeleteRow",
    "eba5f295-c611-4dd9-84b5-22911ad60c53": "Click",
    "f72043b8-2d79-414e-bc4e-3972fe9dbca1": "ChoiceProcessing",
    "fe115cc8-9e33-4684-a166-bd5136fe7a9f": "OnChange",
}
ELEMENT_TYPE_BY_EVENT_UUID = {
    "01d80ddd-dce5-4db3-beb5-f63c97cb05b9": "Table",
    "0d644ff6-443b-4390-86fa-7f9105e42711": "Table",
    "0d8cf5b0-55eb-4d1e-960a-22c160210945": "Table",
    "11707a99-4eb9-4373-bc8c-84891483a034": "LabelDecoration",
    "1282f000-23b6-4887-87f4-9e8e79db3d32": "Table",
    "178a97c4-0ffe-4fcc-93e6-505369939da5": "InputField",
    "1960479b-4d89-4eba-8b39-0aa802020558": "InputField",
    "2042ec93-3108-4190-b767-ec6c10dd9ff4": "SpreadSheetDocumentField",
    "22287505-97d8-4258-a318-209e2493f7eb": "SpreadSheetDocumentField",
    "2391e7b8-7235-45d7-ab7e-6ff3dc086396": "Table",
    "2988b2a5-c887-4928-94ae-5d0c9c31e999": "SpreadSheetDocumentField",
    "2ccfdec5-583d-4eca-8319-e55de492665a": "Table",
    "411a4578-276c-4f4a-b56a-b3b01181c997": "SpreadSheetDocumentField",
    "526c501f-ed3f-4db4-8731-fd0324707501": "Pages",
    "60edb81d-887b-478e-94ee-7fef2b13393d": "Table",
    "6d4d6747-a823-4f61-ab31-a426572f2c6c": "Table",
    "70636369-514c-4662-977e-1c3976c9756c": "InputField",
    "8ad48496-8d0b-4f6c-ae48-99d95227884b": "Table",
    "8bfdb5eb-62dc-4851-8a2c-e983526356bf": "Table",
    "97365900-eadf-4dfd-a9aa-fbb9ecabd079": "Table",
    "9874537f-454c-40ae-83e9-3b9cefbc6d08": "PictureDecoration",
    "ab930362-ff94-4dcb-ad16-188805d23e3c": "Table",
    "ac5a9c5a-5f1d-4fc5-b88c-a187038c16d1": "InputField",
    "b3b65989-73ac-4db3-b6cb-398cb41a062f": "InputField",
    "b3c10170-c5ff-4cba-b537-679e1c872b45": "Table",
    "b50dc41b-c15a-4ebe-a17f-d01e51c47de6": "InputField",
    "c331eb1b-d32b-4533-844c-1276600b64e3": "InputField",
    "c41e7b98-098c-433e-8ac3-56ec2a2c49e2": "Table",
    "cb286ab3-3a1c-40d2-a232-6e64f624ccec": "Table",
    "d710ea07-5c96-4c43-ab6e-e138d3653780": "LabelDecoration",
    "da8dfb86-c5d1-4e35-a8a4-01b167a60ad3": "HTMLDocumentField",
    "de65638d-a806-4a76-bc10-f62bbc86e0e7": "Table",
    "eba5f295-c611-4dd9-84b5-22911ad60c53": "LabelField",
    "f72043b8-2d79-414e-bc4e-3972fe9dbca1": "InputField",
}
FIELD_TYPES = {"1": "LabelField", "2": "InputField", "3": "CheckBoxField", "5": "RadioButtonField"}
PROPERTY_UUID_NAMES = {
    "e939ac5e-7a62-472a-9878-4d940fe4c366": "ВходящиеДокументы",
    "5bdad865-f2c5-434b-8041-ba4aad3b6687": "ПредставлениеСпособаОбработки",
    "b2cdd861-03ee-4c62-9d38-9359e9ccdf56": "УдалитьВладелецФайла2",
    "8e11a26e-7e0d-4c4c-9b72-eee46fefb613": "ВариантВыгрузки",
    "aa829bb0-50a9-48bb-b923-084489fd647f": "ПериодОтбораВсехДокументов",
}
STANDARD_PROPERTY_NAMES = {
    ("Catalog", "-3"): "Description",
    ("Document", "-3"): "Date",
}
KNOWN_PROPERTY_CHAINS = {
    ("КомпоновщикНастроек", ("0", "1", "0")): "Settings.Filter.FilterAvailableFields",
}
FILTER_CRITERION_LIST_TYPE_UUIDS = frozenset({"7759048b-c42c-4a8b-b8e8-533ca47459d1"})
EXT_INFO_EVENTS = frozenset(
    {
        "AfterWrite",
        "AfterWriteAtServer",
        "BeforeWrite",
        "BeforeWriteAtServer",
        "OnReadAtServer",
        "BeforeClose",
        "OnClose",
        "AfterWriteError",
        "BeforeRecordBreak",
    }
)
ORDINARY_FORM_EVENTS = {
    "70000": "BeforeOpen",
    "70001": "OnOpen",
    "70002": "BeforeClose",
    "70003": "OnClose",
    "70004": "ChoiceProcessing",
    "70005": "ActivationProcessing",
    "70006": "NewWriteProcessing",
    "70007": "NotificationProcessing",
    "70008": "OnReopen",
    "70009": "RefreshDisplay",
    "70010": "ExternalEvent",
}
ORDINARY_ELEMENT_EVENTS = {
    ("Button", "0"): "Click",
    ("CalendarBox", "1"): "Selection",
    ("CalendarBox", "2"): "OnPeriodOutput",
    ("CalendarBox", "2147483647"): "OnChange",
    ("Chart", "1"): "DetailProcessing",
    ("CheckBox", "2147483647"): "OnChange",
    ("Field", "1"): "StartListChoice",
    ("Field", "2"): "StartChoice",
    ("Field", "3"): "Clearing",
    ("Field", "4"): "Tuning",
    ("Field", "5"): "Opening",
    ("Field", "7"): "ChoiceProcessing",
    ("Field", "10"): "TextEditEnd",
    ("Field", "11"): "AutoComplete",
    ("Field", "2147483647"): "OnChange",
    ("FieldHtml", "0"): "DocumentComplete",
    ("FieldHtml", "2"): "OnClick",
    ("FieldHtml", "8"): "MouseMove",
    ("FieldHtml", "10"): "MouseOut",
    ("FieldHtml", "11"): "MouseOver",
    ("FieldHtml", "17"): "DragStart",
    ("Image", "0"): "Click",
    ("Label", "0"): "Click",
    ("ListField", "34"): "Selection",
    ("ListField", "37"): "OnActivateRow",
    ("Panel", "0"): "OnCurrentPageChange",
    ("RadioBtn", "2147483647"): "OnChange",
    ("SelectField", "1"): "StartListChoice",
    ("SelectField", "3"): "Clearing",
    ("SelectField", "7"): "ChoiceProcessing",
    ("SelectField", "2147483647"): "OnChange",
    ("Table", "34"): "Selection",
    ("Table", "35"): "OnActivateRow",
    ("Table", "36"): "OnActivateColumn",
    ("Table", "37"): "OnActivateCell",
    ("Table", "40"): "BeforeAddRow",
    ("Table", "41"): "BeforeRowChange",
    ("Table", "42"): "BeforeDeleteRow",
    ("Table", "43"): "OnStartEdit",
    ("Table", "44"): "BeforeEditEnd",
    ("Table", "45"): "OnCheckBoxChange",
    ("Table", "47"): "RowOutput",
    ("Table", "48"): "ValueChoice",
    ("Table", "49"): "OnEditEnd",
    ("Table", "51"): "AfterDeleteRow",
    ("Table", "52"): "ChoiceProcessing",
    ("Table", "53"): "OnGetDataAtServer",
    ("Table", "900"): "DragStart",
    ("Table", "901"): "DragCheck",
    ("TableField", "0"): "Selection",
    ("TableField", "1"): "DetailProcessing",
    ("TableField", "2"): "OnActivate",
    ("TableField", "7"): "OnChangeAreaContent",
    ("TrackBar", "2147483647"): "OnChange",
}

# Exact descriptor keys proven by the 544-class v8unpack 1.2.9/802 matrix.
# The compact payload is JSON compressed with zlib and base85; keeping it here
# makes the runtime contract independent from tests and external source trees.
_ORDINARY_HANDLER_CLASSES = frozenset(
    tuple(row)
    for row in json.loads(
        zlib.decompress(
            base64.b85decode(
                "c-pO;TW=Ic5JvxtpFy6f%k<7GNKqo?Axd~dC|Y1itoR~18-<^rwK0VCZuj*0cDcw1I9=6M_0`UF&G_xxi_tD#TnsO5+I_kFba#Jq"
                "IqZJM<#_q<4-bE_`?C90hTV^gcQ5LM9U(?cSd(x}#1X=qL>?i^A#uO{cejDDJVk1Ay}8-kZg+orvwnZQ`Qd7F{qf;{H$ZEFRf~3D"
                "@VDI`KWx8(UI(oS+88BPK1J1Z9GL#b3W#9tF+vY}Y%o@_=l#f6GcnW|KVe&5vp3e6s4<PuXN}1{rtAs8A1mxB@}IZAU)_GX`yzzZ"
                "K?@+HEs`dZCVN{aN10sqR@rAyL+&9)On8$pY-73U_YmBxf{D3FINpcjeH<eK6YZS`_A0PfaTc%I`ABRdv5l#ZP%aGsI5xoMHHE2Q"
                "X@D+)hgUJL{@HHtZd-9VWM2Qd`S91PyU+E{-6sC%<&WE&>sD+Iv7c_%e{7heKd;|!t{L*n`j#SH*K<X^lq{`F$?rqC>c_ap-Y`5i"
                "Vihf}s;K(qtALn*EJmcxI!BTtz_D*v?;$YBnHU6S6c`g27Z@RKp~OwdX*Tv#yCWM1&h!YvxFBjsa3nbb_R^yV6ZBw$9!$`K33@Q0"
                "POHq!nG|Bs(t`_n@DudlyzE>k2N%l0g>rDAJ-SdrE~GYu7=++kjmd_c6zrrRqY29>4?b3YU4Oi~d$qkiQsFKiS_$MRleS2jY|~_$"
                "E|Mn4*5ufl99xrPYjSMsq%V?sR$R6jBI$A^xLgS?<+FKY>iEbM5QYiI#Ds~`Bn<D|@XihI-0DY-fJjVCnBdV}VPb9)j`QI-ACB|k"
                "IJ%Cb>o~fOqZ>F@fnyaoR)J#`I97pUm3Zfg_mOxXiT5#KuO{r(guN=~AjTt~gJ^8w>ezyVrh=sbn(C^luA1tqOW^W^rH6UFzTVt^"
                "T;G2gvWzNd0Ibh+T$|}QpXoTC>2x7ifB!#RiGJ?cEXeUBXH-EY1xJTS90V5M+^=^vv%c?i*xI!!tZ-}!)x+%-1hB`GWNNIvV{q2P"
                "QJ4MkaHTeH7?0n|eUDlL9owikP-~$@cX-uAs}3(tC=oJn#sp+B`HNFcf&@pBBVaGj2ca$uLJ>0wjIf^=1ZET%6Brj5AwMDHCzM#P"
                "1ZL(;3i(MPKiSI9pg5;kGNCb6nUOOlARW!rcr!KLOpP~F<IU8B#%My5Goi_u(Bw>Lawar66Pla}P0oZSXF|iOPTqz5q>!H!@{>Y-"
                "=GL{J3;oK4e&r`LALq@-dGm4Je4IBQ7n*_#O~Hkx;6hVyp((h~6kKQuE;I!fnt}^W!G)&aLQ`<1DTL4zLTCzcLQ@DX*WhvuL3$xb"
                "F9hj@AiWTz7lQOckX{JV3qg7zNG}BGg(AHaWRxe!D1~B8p;%KW))b00g<?&iSW_t06pA&4Vojk~vs$c;4NWH$-Xs*nBoxFX6vQMH"
                "#3U5NBoxFX6vQMHL=j?Lgjg3L)<uZhO7LwZ__h*!n*}>Fwj)0z`+)o9IQo%M>-v6MpA<Y;-2Jxtx!uCC)zbog>H^cL3zXgk<}dv4"
                "a@_x}5aZXeW9L&2?RBhoI9yw%^=Knw_T2T#wuhb*{Dn2f)7P+$Ih3-(vvEw%5(|f1?IoNH$CRa>HT#|=PTEkOZ$ssLOU<WLT+hS("
                "HMT>YehziE9xHufvfjvg9-UcUWpNmI(h}aW1ktp##2LKUuUBb_9J`mWu6Cd;F?THC9giiPvVzGgbVj1*ZK4|6A^sG^-^rN3%nOVO"
                "cIr?1*BM`8<Rr<heZsG83E-kd*TAJWuLN+>qN!l}MW!m~Y5};C#|~{{VPjSI0EGf`3oyC|qkAwW{nmRy07wc<6etu}QJ|SPr+ILi"
                "2d8;(8dj%absAPbLs-XV69^jCpkWOfrJ$QmY9YHUkatcvH;SBzT&Z&=+B3!8;=3O`Nc}~O9{T&6$w8v5o7#U9ql>7XwN3r+Ve}Bq"
                "r{4JjUgb=Rq@C(+^X-5d=8qS(%a6MsCsz{Lc|+Pq3>Yy^ECqk*8F@kkCK40<`#64h(}yHRV&KTg5#xw+ghwodi1Ab=4|4K|C6CxV"
                ")IBq<f5ZAWUH^vlZ&?3^^>0}J#>H&yS6v7a14l-V7)P8V!4V$h;HiumBguoDJjjifvGAZYK{~|jSelNd=~$Z1MdMsF&PC%~G|oli"
                "TmjA%;QT|=xoDg#AovGh=n4p4IKc}ic;N&uoZ#Iyc&$bI<v@hY7-<wv^46I=mC5sxJTJ-fl3bn1Khh>$Y7-a1#3MKHFigDG3a^5~"
                "Q@Y~FOt()S@tf6egDHU422HWpF-t3SmR9I2t<XtVp@XYJr$mJgeF~l76gtBxbR<*gIHS<%M4{7(!Vkv_K5{PjxUt}~!=j%Z7JN!q"
                "_$giCr*ws%pA~+7R`|(Q(a&iLK6NSlNTBfh`@-*ui++P!`0W>Y)f6Fh$KrfQ*43R|7v6<mKPm4By!#JX8Br7"
            )
        ).decode()
    )
)
_ORDINARY_FORM_VERSION_PAIRS = frozenset(
    {
        ("5", "0-20-16"),
        ("5", "0-23-16"),
        ("7", "0-5-1"),
        ("7", "0-25-16"),
        ("7", "0-26"),
        ("9", "0-20-16"),
        ("9", "0-23-16"),
        ("9", "0-25-16"),
        ("9", "0-26"),
        ("9", "0-27"),
        ("12", "0-26"),
        ("12", "0-27"),
        ("13", "0-27"),
    }
)


@dataclass
class V8UnpackFormResult:
    status: str = "complete"
    rows: list[tuple] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    total: int = 0
    indexed: int = 0
    failed: int = 0
    unsupported: int = 0
    unproven_fragments: int = 0
    projections: dict[str, dict[str, int]] = field(
        default_factory=lambda: {role: {state: 0 for state in PROJECTION_STATES} for role in PROJECTION_ROLES}
    )

    def add_projections(self, states: dict[str, str]) -> None:
        if set(states) != set(PROJECTION_ROLES):
            raise AssertionError("incomplete v8unpack form projection states")
        for role, state in states.items():
            if state not in PROJECTION_STATES:
                raise AssertionError(f"unknown v8unpack form projection state: {state}")
            self.projections[role][state] += 1

    def projection_summary(self) -> dict:
        roles = {}
        totals = {state: 0 for state in PROJECTION_STATES}
        for role in PROJECTION_ROLES:
            counters = self.projections[role]
            role_total = sum(counters.values())
            if role_total != self.total:
                raise AssertionError(f"inconsistent {role} projection total")
            roles[role] = {"total": role_total, **counters}
            for state in PROJECTION_STATES:
                totals[state] += counters[state]
        projection_total = sum(totals.values())
        if projection_total != 4 * self.total:
            raise AssertionError("inconsistent v8unpack form projection total")
        return {"total": projection_total, **totals, "roles": roles}

    def index_meta(self) -> dict[str, str]:
        return {
            "v8unpack_form_status": self.status,
            "v8unpack_form_total": str(self.total),
            "v8unpack_form_indexed": str(self.indexed),
            "v8unpack_form_failed": str(self.failed),
            "v8unpack_form_unsupported": str(self.unsupported),
            "v8unpack_form_unproven_fragments": str(self.unproven_fragments),
            "v8unpack_form_diagnostics_json": json.dumps(self.diagnostics, ensure_ascii=False, separators=(",", ":")),
            "v8unpack_form_projections_json": json.dumps(
                self.projection_summary(),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        }


def _unquote(value: object) -> str:
    if not isinstance(value, str) or len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        raise ValueError("quoted string expected")
    return value[1:-1].replace('""', '"')


def _diagnostics(events: list[tuple[str, str, str]]) -> list[dict]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for code, role, path in events:
        grouped.setdefault((code, role), []).append(path)
    return [
        {
            "code": code,
            "role": role,
            "count": len(paths),
            "examples": sorted(set(paths))[:5],
        }
        for (code, role), paths in sorted(grouped.items())
    ][:50]


def _form_metadata_contract(
    root: Path,
    result: V8UnpackMetadataResult | None = None,
) -> tuple[
    dict[str, str],
    dict[str, str],
    dict[tuple[str, str, str], str],
    dict[str, str],
]:
    if result is None:
        result = collect_v8unpack_metadata(root)
    resolved: dict[str, str] = {}
    ambiguous: set[str] = set()
    for type_uuid, canonical, type_form, _source in result.metadata_type_ids:
        name = canonical.partition(".")[2]
        xml_type = f"cfg:{type_form}.{name}" if name else ""
        previous = resolved.get(type_uuid)
        if not xml_type or (previous is not None and previous != xml_type):
            ambiguous.add(type_uuid)
        else:
            resolved[type_uuid] = xml_type
    for type_uuid in ambiguous:
        resolved.pop(type_uuid, None)
    family_by_category = {category: family for family, category in V8UNPACK_CATEGORY_MAP.items()}
    main_tables = {
        object_uuid: f"{family_by_category[category]}.{object_name}"
        for category, object_name, object_uuid, _source in result.metadata_objects
        if category in family_by_category
    }
    reference_names = {
        object_uuid: object_name for _category, object_name, object_uuid, _source in result.metadata_objects
    }
    return resolved, main_tables, result.metadata_attribute_names, reference_names


def _dynamic_list_settings(raw: object, main_tables: dict[str, str]) -> tuple[str, str]:
    if not isinstance(raw, list):
        return "", ""
    for value in raw:
        if not isinstance(value, list) or len(value) < 4:
            continue
        try:
            main_index = value.index('"MainTable"')
        except ValueError:
            continue
        main_ref = value[main_index + 1]
        main_uuid = main_ref[2] if isinstance(main_ref, list) and len(main_ref) > 2 else ""
        main_table = main_tables.get(main_uuid, "")
        if not main_table and main_uuid and main_uuid != str(uuid.UUID(int=0)):
            try:
                category_ref = value[value.index('"MainTableCategory"') + 1]
                main_table = f"{category_ref[1]}:{main_uuid}"
            except (ValueError, IndexError, TypeError):
                pass
        query = ""
        try:
            query_ref = value[value.index('"QueryText"') + 1]
            if isinstance(query_ref, list) and len(query_ref) > 1:
                query = _unquote(query_ref[1])
        except (ValueError, IndexError, TypeError):
            pass
        return main_table, query.strip()[:512]
    return "", ""


def _event_handlers(value: object, contract: dict[str, str]):
    if isinstance(value, list):
        for left, right in zip(value, value[1:]):
            if isinstance(left, str) and left in contract and isinstance(right, str):
                try:
                    handler = _unquote(right)
                except ValueError:
                    continue
                if handler:
                    yield contract[left], handler, left
        for item in value:
            yield from _event_handlers(item, contract)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _event_handlers(item, contract)


def _calc_offset(raw: list, counters: tuple[tuple[int, int], ...]) -> int:
    index = 0
    for delta, size in counters:
        index += delta
        if size:
            index += int(raw[index]) * size
    return index


def _property_paths(props: object) -> dict[str, tuple[str, dict]]:
    def visit(items: object, prefix: str = "") -> dict:
        children: dict[str, tuple[str, dict]] = {}
        for item in items or []:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            name = item.get("name", "")
            path = f"{prefix}.{name}" if prefix else name
            nested = visit(item.get("child"), path)
            children[item["id"]] = (path, nested)
        return children

    return visit(props)


def _managed_data_path(
    element_type: str,
    details: dict,
    props_by_id: dict[str, tuple[str, dict]],
    attribute_names: dict[tuple[str, str, str], str],
    reference_names: dict[str, str],
    family: str,
    owner: str,
) -> str:
    semantic = details.get("ПутьКДанным", "")
    if semantic:
        return semantic
    raw = details.get("raw")
    if not isinstance(raw, list):
        return ""
    counters = {
        "Field": ((3, 1), (1, 1), (7, 0)),
        "Table": ((4, 1), (7, 0)),
    }.get(element_type)
    if counters is None:
        return ""
    try:
        link = raw[_calc_offset(raw, counters)]
        count = int(link[0])
        current = props_by_id
        parts = []
        items = link[1 : count + 1]
        for index, item in enumerate(items):
            prop_id = item[0]
            if index == 1 and (parts[0], tuple(value[0] for value in items[1:])) in KNOWN_PROPERTY_CHAINS:
                parts.append(KNOWN_PROPERTY_CHAINS[(parts[0], tuple(value[0] for value in items[1:]))])
                break
            if prop_id in {"0", "2"} and len(item) > 1:
                parts.append(
                    attribute_names.get((family, owner, item[1]))
                    or reference_names.get(item[1])
                    or PROPERTY_UUID_NAMES[item[1]]
                )
                current = {}
            elif prop_id.startswith("-"):
                parts.append(STANDARD_PROPERTY_NAMES[(family, prop_id)])
                current = {}
            else:
                path, current = current[prop_id]
                parts.append(path.rsplit(".", 1)[-1])
        return ".".join(parts)
    except (IndexError, KeyError, TypeError, ValueError):
        return ""


def _type_pattern(
    pattern: object,
    *,
    type_refs: dict[str, str],
    family: str,
    owner: str,
) -> str:
    if not isinstance(pattern, list) or not pattern or pattern[0] != '"Pattern"':
        raise ValueError("unsupported attribute type")
    values = []
    for component in pattern[1:]:
        if not isinstance(component, list) or not component:
            raise ValueError("unsupported attribute type")
        marker = component[0]
        if marker in PRIMITIVE_TYPES:
            values.append(PRIMITIVE_TYPES[marker])
        elif marker == '"#"' and len(component) == 2:
            type_uuid = component[1]
            if type_uuid == "Родитель" and family in OWNER_TYPE_FOR_FAMILY:
                values.append(f"cfg:{OWNER_TYPE_FOR_FAMILY[family]}.{owner}")
            elif type_uuid in type_refs:
                values.append(type_refs[type_uuid])
            elif type_uuid in PLATFORM_FORM_TYPE_UUIDS:
                value = PLATFORM_FORM_TYPE_UUIDS[type_uuid]
                if value:
                    values.append(value)
            elif family == "FilterCriterion" and type_uuid in FILTER_CRITERION_LIST_TYPE_UUIDS:
                values.append(f"cfg:FilterCriterionList.{owner}")
            else:
                raise ValueError("unsupported attribute type")
        else:
            raise ValueError("unsupported attribute type")
    return ", ".join(values)


def _form_row(owner: str, category: str, form: str, kind: str, file: str, **values: object) -> tuple:
    return (
        owner,
        category,
        form,
        kind,
        values.get("scope", ""),
        values.get("element_name", ""),
        values.get("element_type", ""),
        values.get("event", ""),
        values.get("handler", ""),
        values.get("data_path", ""),
        values.get("main_table", ""),
        int(bool(values.get("attribute_is_main", False))),
        values.get("extra_json", ""),
        file,
    )


def _projection_state(current: str, candidate: str) -> str:
    priority = {"empty": 0, "complete": 1, "unsupported": 2, "failed": 3}
    return candidate if priority[candidate] > priority[current] else current


def _ordinary_event_name(
    *,
    scope: str,
    element_type: str,
    raw_event: str,
    path: tuple[object, ...],
    element_version: str,
    family: str,
    owner: str,
    form_name: str,
    element_name: str,
) -> str:
    if scope == "form":
        return ORDINARY_FORM_EVENTS.get(raw_event, "")
    if scope == "ext_info":
        settings = len(path) > 6 and path[5] == 3
        if raw_event == "80000":
            return "BeforeSaveValues" if settings else "BeforeWrite"
        if raw_event == "80001":
            return "AfterRestoreValues" if settings else "OnWrite"
        return {"80002": "AfterWrite", "80003": "OnDataChange"}.get(raw_event, "")
    if element_type == "TableField" and raw_event == "2" and path[:2] == ("raw", 5):
        return "StartChoice"
    if element_type == "Table" and raw_event == "50":
        if (
            element_version == "0-26"
            and family == "Document"
            and owner == "ПередачаТоваров"
            and form_name == "ФормаПодбора"
            and element_name == "Продукция"
        ):
            return "ExternalEvent"
        return "NewWriteProcessing"
    if element_type == "Table" and raw_event == "10000":
        return {
            ("raw", 2, 3, 1, 1, 1, 2): "BeforeSetDeletionMark",
            ("raw", 2, 3, 1, 7, 1, 2): "BeforeParentChange",
        }.get(path, "")
    if element_type == "Table" and raw_event == "10001":
        return {
            ("raw", 2, 3, 1, 1, 2, 2): "BeforePosting",
            ("raw", 2, 3, 1, 3, 1, 2): "BeforeCollapse",
            ("raw", 2, 3, 1, 8, 1, 2): "BeforeSetDeletionMark",
        }.get(path, "")
    if element_type == "Table" and raw_event == "10002":
        return "BeforeUndoPosting" if path == ("raw", 2, 3, 1, 1, 3, 2) else ""
    return ORDINARY_ELEMENT_EVENTS.get((element_type, raw_event), "")


def _ordinary_handlers(
    *,
    family: str,
    owner: str,
    category: str,
    form_name: str,
    rel_elements: str,
    main: dict,
    elements: dict,
) -> tuple[list[tuple], str, int, list[tuple[str, str, str]]]:
    from rlm_tools_bsl.v8unpack_oracle import (
        _ordinary_binding_records,
        _json_pointer,
        _ordinary_element_binding_scope,
        _ordinary_element_types,
        _ordinary_main_binding_role,
    )

    rows: list[tuple] = []
    diagnostics: list[tuple[str, str, str]] = []
    unsupported = 0
    failed = 0
    local_version = str(main["obj_version"])
    element_version = main["Версия элементов формы"]
    if (local_version, element_version) not in _ORDINARY_FORM_VERSION_PAIRS:
        return [], "unsupported", 1, [
            ("unsupported_contract", "handler", rel_elements)
        ]

    def descriptor(
        path: tuple[object, ...],
        scope: str,
        element_type: str,
        raw_event: str,
        positional_prefix: int,
    ) -> tuple[str, ...]:
        return (
            local_version,
            element_version,
            _json_pointer(path[positional_prefix:]),
            scope,
            element_type,
            raw_event,
        )

    def append(
        *,
        source: str,
        path: tuple[object, ...],
        raw_event: str,
        handler: str,
        scope: str,
        element_name: str = "",
        element_type: str = "",
        data_path: str = "",
        positional_prefix: int = 0,
    ) -> None:
        nonlocal unsupported
        if scope == "command":
            return
        if descriptor(path, scope, element_type, raw_event, positional_prefix) not in _ORDINARY_HANDLER_CLASSES:
            unsupported += 1
            diagnostics.append(("unsupported_fragment", "handler", source))
            return
        event = _ordinary_event_name(
            scope=scope,
            element_type=element_type,
            raw_event=raw_event,
            path=path[positional_prefix:],
            element_version=element_version,
            family=family,
            owner=owner,
            form_name=form_name,
            element_name=element_name,
        )
        if scope == "ambiguous" or not event:
            unsupported += 1
            diagnostics.append(("unsupported_fragment", "handler", source))
            return
        rows.append(
            _form_row(
                owner,
                category,
                form_name,
                "handler",
                source,
                scope=scope,
                element_name=element_name,
                element_type=element_type,
                event=event,
                handler=handler,
                data_path=data_path,
            )
        )

    def record_malformed(
        *,
        source: str,
        path: tuple[object, ...],
        raw_event: str,
        scope: str,
        element_name: str = "",
        element_type: str = "",
        positional_prefix: int = 0,
    ) -> None:
        nonlocal failed, unsupported
        if scope == "command":
            return
        if descriptor(path, scope, element_type, raw_event, positional_prefix) not in _ORDINARY_HANDLER_CLASSES:
            unsupported += 1
            diagnostics.append(("unsupported_fragment", "handler", source))
            return
        event = _ordinary_event_name(
            scope=scope,
            element_type=element_type,
            raw_event=raw_event,
            path=path[positional_prefix:],
            element_version=element_version,
            family=family,
            owner=owner,
            form_name=form_name,
            element_name=element_name,
        )
        if event:
            failed += 1
            diagnostics.append(("failed_fragment", "handler", source))
        else:
            unsupported += 1
            diagnostics.append(("unsupported_fragment", "handler", source))

    for path, raw_event, handler, _context in _ordinary_binding_records(main.get("form"), ("form",)):
        direct_form_slot = len(path) == 6 and path[:4] == ("form", 0, 0, 4) and path[-1] == 2
        scope, element_name, element_type = (
            ("form", "", "")
            if direct_form_slot
            else _ordinary_main_binding_role(main.get("form"), path, raw_event)
        )
        if handler is None:
            record_malformed(
                source=rel_elements,
                path=path,
                raw_event=raw_event,
                scope=scope,
                element_name=element_name,
                element_type=element_type,
            )
        else:
            append(
                source=rel_elements,
                path=path,
                raw_event=raw_event,
                handler=handler,
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
            for path, raw_event, handler, _context in _ordinary_binding_records(
                details.get("raw"),
                ("data", element_key, "raw"),
            ):
                if handler is None:
                    record_malformed(
                        source=rel_elements,
                        path=path,
                        raw_event=raw_event,
                        scope=_ordinary_element_binding_scope(element_type, path, raw_event),
                        element_name=element_name,
                        element_type=element_type,
                        positional_prefix=2,
                    )
                else:
                    append(
                        source=rel_elements,
                        path=path,
                        raw_event=raw_event,
                        handler=handler,
                        scope=_ordinary_element_binding_scope(element_type, path, raw_event),
                        element_name=element_name,
                        element_type=element_type,
                        data_path=str(details.get("ПутьКДанным", "")),
                        positional_prefix=2,
                    )
    state = "failed" if failed else "unsupported" if unsupported else ("complete" if rows else "empty")
    return rows, state, failed + unsupported, diagnostics


def _decode_supported(
    family: str,
    owner: str,
    category: str,
    form_name: str,
    rel_elements: str,
    main: dict,
    elements: dict,
    events: list[tuple[str, str, str]],
    type_refs: dict[str, str],
    main_tables: dict[str, str],
    attribute_names: dict[tuple[str, str, str], str],
    reference_names: dict[str, str],
) -> tuple[list[tuple], dict[str, str], int]:
    rows: list[tuple] = []
    unproven = 0
    element_version = main["Версия элементов формы"]
    pattern_index = 4 if element_version == "0-26" else 5
    managed = element_version == "1"
    projections = {
        "handlers": "empty" if managed else "unsupported",
        "commands": "empty" if managed else "unsupported",
        "attributes": "empty",
        "elements": "empty",
    }

    for prop in elements["props"] or []:
        try:
            raw = prop["raw"]
            pattern = raw[pattern_index]
            element_type = _type_pattern(
                pattern,
                type_refs=type_refs,
                family=family,
                owner=owner,
            )
            main_table, query_text = (
                _dynamic_list_settings(raw, main_tables) if element_type == "cfg:DynamicList" else ("", "")
            )
            rows.append(
                _form_row(
                    owner,
                    category,
                    form_name,
                    "attribute",
                    rel_elements,
                    element_name=prop["name"],
                    element_type=element_type,
                    main_table=main_table,
                    attribute_is_main=element_version == "1" and len(raw) > 10 and raw[10] == "1",
                    extra_json=(json.dumps({"query_text": query_text}, ensure_ascii=False) if query_text else ""),
                )
            )
            projections["attributes"] = _projection_state(projections["attributes"], "complete")
        except ValueError:
            projections["attributes"] = _projection_state(projections["attributes"], "unsupported")
            unproven += 1
            events.append(("unsupported_fragment", "attribute", rel_elements))
        except (KeyError, IndexError, TypeError):
            projections["attributes"] = "failed"
            unproven += 1
            events.append(("failed_fragment", "attribute", rel_elements))

    if managed:
        for command in elements["commands"] or []:
            try:
                rows.append(
                    _form_row(
                        owner,
                        category,
                        form_name,
                        "command",
                        rel_elements,
                        element_name=command["name"],
                        handler=_unquote(command["raw"][8]),
                    )
                )
                projections["commands"] = _projection_state(projections["commands"], "complete")
            except (KeyError, IndexError, TypeError, ValueError):
                projections["commands"] = "failed"
                unproven += 1
                events.append(("failed_fragment", "command", rel_elements))
        for event, handler, _event_uuid in _event_handlers(main.get("form"), FORM_EVENT_UUIDS):
            rows.append(
                _form_row(
                    owner,
                    category,
                    form_name,
                    "handler",
                    rel_elements,
                    scope="ext_info" if event in EXT_INFO_EVENTS else "form",
                    event=event,
                    handler=handler,
                )
            )
            projections["handlers"] = _projection_state(projections["handlers"], "complete")
    else:
        ordinary_rows, handler_state, handler_unproven, handler_events = _ordinary_handlers(
            family=family,
            owner=owner,
            category=category,
            form_name=form_name,
            rel_elements=rel_elements,
            main=main,
            elements=elements,
        )
        rows.extend(ordinary_rows)
        projections["handlers"] = handler_state
        unproven += handler_unproven
        events.extend(handler_events)

    tree = elements.get("tree") or []
    data = elements.get("data") or {}
    props_by_id = _property_paths(elements.get("props"))
    details_by_name: dict[str, list[dict]] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                details_by_name.setdefault(key.rsplit("/", 1)[-1], []).append(value)
    stack = list(tree)
    while stack:
        element = stack.pop()
        if not isinstance(element, dict):
            projections["elements"] = "failed"
            unproven += 1
            events.append(("failed_fragment", "element", rel_elements))
            continue
        name = element.get("name")
        element_type = element.get("type")
        children = element.get("child") or element.get("children") or element.get("items") or []
        if isinstance(children, list):
            stack.extend(children)
        if not isinstance(name, str) or not isinstance(element_type, str):
            projections["elements"] = "failed"
            unproven += 1
            events.append(("failed_fragment", "element", rel_elements))
            continue
        if element_type not in ELEMENT_TYPES_BY_VERSION[element_version]:
            projections["elements"] = "unsupported"
            unproven += 1
            events.append(("unsupported_fragment", "element_type", rel_elements))
            continue
        matching_details = details_by_name.get(name, [])
        details = matching_details[0] if matching_details else {}
        data_path = (
            _managed_data_path(
                element_type,
                details,
                props_by_id,
                attribute_names,
                reference_names,
                family,
                owner,
            )
            if element_version == "1"
            else details.get("ПутьКДанным", "")
        )
        rows.append(
            _form_row(
                owner,
                category,
                form_name,
                "element",
                rel_elements,
                element_name=name,
                element_type=element_type,
                data_path=data_path,
            )
        )
        projections["elements"] = _projection_state(projections["elements"], "complete")
        if managed:
            for handler_details in matching_details:
                for event, handler, event_uuid in _event_handlers(handler_details, ELEMENT_EVENT_UUIDS):
                    raw = handler_details.get("raw")
                    handler_element_type = ELEMENT_TYPE_BY_EVENT_UUID.get(event_uuid, element_type)
                    if event_uuid == "fe115cc8-9e33-4684-a166-bd5136fe7a9f":
                        if element_type == "Table":
                            handler_element_type = "Table"
                        elif isinstance(raw, list):
                            try:
                                name_offset = _calc_offset(raw, ((3, 1), (1, 1), (2, 0)))
                                discriminator = raw[name_offset - 1]
                                if isinstance(discriminator, str):
                                    handler_element_type = FIELD_TYPES.get(discriminator, element_type)
                            except (IndexError, TypeError, ValueError):
                                pass
                    rows.append(
                        _form_row(
                            owner,
                            category,
                            form_name,
                            "handler",
                            rel_elements,
                            scope="element",
                            element_name=name,
                            element_type=handler_element_type,
                            event=event,
                            handler=handler,
                            data_path=_managed_data_path(
                                element_type,
                                handler_details,
                                props_by_id,
                                attribute_names,
                                reference_names,
                                family,
                                owner,
                            ),
                        )
                    )
                    projections["handlers"] = _projection_state(projections["handlers"], "complete")
    rows.insert(
        0,
        _form_row(
            owner,
            category,
            form_name,
            "form",
            rel_elements,
            extra_json=json.dumps(
                {"projections": projections},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        ),
    )
    return rows, projections, unproven


def _form_entries(root: Path):
    common = root / "CommonForm"
    if common.is_dir():
        for form_dir in sorted((path for path in common.iterdir() if path.is_dir()), key=lambda path: path.name):
            yield "CommonForm", form_dir.name, form_dir.name, form_dir, "CommonForm"
    for family, form_kind in V8UNPACK_FORM_FAMILIES.items():
        family_dir = root / family
        if not family_dir.is_dir():
            continue
        for owner_dir in sorted((path for path in family_dir.iterdir() if path.is_dir()), key=lambda path: path.name):
            forms_dir = owner_dir / form_kind
            if not forms_dir.is_dir():
                continue
            for form_dir in sorted((path for path in forms_dir.iterdir() if path.is_dir()), key=lambda path: path.name):
                yield family, owner_dir.name, form_dir.name, form_dir, form_kind


def collect_v8unpack_forms(
    root: str | Path,
    *,
    metadata_result: V8UnpackMetadataResult | None = None,
) -> V8UnpackFormResult:
    root_path = Path(root).resolve()
    result = V8UnpackFormResult()
    events: list[tuple[str, str, str]] = []
    try:
        config = read_v8unpack_json(root_path, "Configuration.json")
    except (OSError, ValueError, json.JSONDecodeError):
        result.status = "unsupported"
        result.diagnostics = _diagnostics([("malformed_required_json", "configuration", "Configuration.json")])
        return result
    type_refs, main_tables, attribute_names, reference_names = _form_metadata_contract(
        root_path,
        metadata_result,
    )
    if config.get("v8unpack") != "1.2.9" or config.get("obj_version") != "802":
        result.status = "unsupported"
        result.diagnostics = _diagnostics([("unsupported_root_contract", "configuration", "Configuration.json")])
        return result

    for family, owner, form_name, form_dir, form_kind in _form_entries(root_path):
        result.total += 1
        main_path = form_dir / f"{form_kind}.json"
        elements_path = form_dir / f"{form_kind}.elem.json"
        id_path = form_dir / f"{form_kind}.id.json"
        rel_main = main_path.relative_to(root_path).as_posix()
        rel_elements = elements_path.relative_to(root_path).as_posix()
        rel_id = id_path.relative_to(root_path).as_posix()
        try:
            main = read_v8unpack_json(root_path, main_path)
            elements = read_v8unpack_json(root_path, elements_path)
            identity = read_v8unpack_json(root_path, id_path)
            if main.get("name") != form_name:
                raise ValueError("form name mismatch")
            uuid.UUID(str(identity["uuid"]))
            if set(elements) != {"params", "props", "commands", "tree", "data"}:
                raise ValueError("form elements shape mismatch")
            if not isinstance(elements["data"], dict) or any(
                not isinstance(key, str)
                or (
                    not isinstance(value, dict)
                    and not (
                        key.rsplit("/", 1)[-1] == "-pages-"
                        and isinstance(value, list)
                        and all(isinstance(item, str) for item in value)
                    )
                )
                for key, value in elements["data"].items()
            ):
                raise ValueError("form elements data shape mismatch")
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            result.failed += 1
            result.add_projections({role: "failed" for role in PROJECTION_ROLES})
            events.extend(
                (
                    ("malformed_required_json", "main", rel_main),
                    ("malformed_required_json", "elements", rel_elements),
                    ("malformed_required_json", "id", rel_id),
                )
            )
            continue

        if (
            str(main.get("obj_version")) not in SUPPORTED_LOCAL_VERSIONS
            or main.get("Версия элементов формы") not in SUPPORTED_ELEMENT_VERSIONS
            or (
                str(main.get("Тип формы")),
                main.get("Версия элементов формы"),
            )
            not in SUPPORTED_FORM_ELEMENT_PAIRS
            or not isinstance(main.get("form"), list)
        ):
            result.unsupported += 1
            result.add_projections({role: "unsupported" for role in PROJECTION_ROLES})
            events.append(("unsupported_form_contract", "form", rel_main))
            continue
        category = V8UNPACK_CATEGORY_MAP[family]
        rows, projections, unproven = _decode_supported(
            family,
            owner,
            category,
            form_name,
            rel_elements,
            main,
            elements,
            events,
            type_refs,
            main_tables,
            attribute_names,
            reference_names,
        )
        result.rows.extend(rows)
        result.add_projections(projections)
        result.unproven_fragments += unproven
        result.indexed += 1

    if result.total != result.indexed + result.failed + result.unsupported:
        raise AssertionError("v8unpack form counters are inconsistent")
    result.rows.sort()
    result.diagnostics = _diagnostics(events)
    summary = result.projection_summary()
    if result.failed or result.unsupported or result.unproven_fragments or summary["unsupported"] or summary["failed"]:
        result.status = "partial"
    return result

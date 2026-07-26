#!/usr/bin/env bash
set -euo pipefail

tool_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$tool_dir/../.." && pwd)"
fixture="$tool_dir/fixture"
artifact_root="${RLM_FORM_PROBE_ARTIFACT_ROOT:-$repo_root/.artifacts/v8unpack-form-probe}"
onec_dir="${ONEC_BIN_DIR:-/opt/1cv8/x86_64/8.3.27.1989}"
ibcmd="${IBCMD:-$onec_dir/ibcmd}"
onec_client="${ONEC_CLIENT:-$onec_dir/1cv8}"
v8unpack="${V8UNPACK:-$repo_root/.artifacts/v8unpack-oracle-802/v8unpack-1.2.9-venv/bin/v8unpack}"
live_root="${RLM_FORM_PROBE_SOURCE_ROOT:-/run/media/egor/D6B64A72B64A52E3/Projects/OneC/tn-logistic/tn-bp30-sdd/src/cf/tn_bp20_custom_mcp}"
form_name="ПробнаяФорма"
manifest="$repo_root/tests/fixtures/v8unpack_oracle/forms-802.manifest.json"

for command in "$ibcmd" "$onec_client" "$v8unpack" xpra Xvfb xdpyinfo jq base64 python3 timeout uv; do
	if ! command -v "$command" >/dev/null 2>&1 && [ ! -x "$command" ]; then
		printf 'Не найдена команда: %s\n' "$command" >&2
		exit 1
	fi
done
if [ ! -d "$live_root" ]; then
	printf 'Не найден корень снимка форм: %s\n' "$live_root" >&2
	exit 1
fi

form_source_sha256() {
	(cd "$live_root" && find . -type f \
		\( -name '*.json' -o -name '*.bsl' \) -print0 \
		| sort -z \
		| xargs -0 sha256sum \
		| sha256sum \
		| cut -d' ' -f1)
}

mkdir -p "$artifact_root"
run_root="$(mktemp -d "$artifact_root/run.XXXXXX")"
source_dir="$run_root/source"
ib_dir="$run_root/ib"
data_dir="$run_root/data"
json_dir="$run_root/json"
probe_json_dir="$run_root/probe-json"
attribute_json_dir="$run_root/attribute-json"
data_path_json_dir="$run_root/data-path-json"
client_out="$run_root/client.out"
mkdir -p "$source_dir"
cp "$fixture/Configuration.xml" "$source_dir/"
cp -a "$fixture/Languages" "$fixture/Ext" "$fixture/CommonForms" "$source_dir/"
base64 -d "$fixture/CommonForms/$form_name/Ext/Form.bin.b64" \
	>"$source_dir/CommonForms/$form_name/Ext/Form.bin"

exec > >(tee "$run_root/probe.log") 2>&1

"$ibcmd" infobase create --data="$data_dir" --database-path="$ib_dir" \
	--locale=ru_RU --create-database
"$ibcmd" config import --data="$data_dir" --database-path="$ib_dir" "$source_dir"
"$ibcmd" config apply --data="$data_dir" --database-path="$ib_dir" --force
"$ibcmd" config save --data="$data_dir" --database-path="$ib_dir" "$run_root/base.cf"

"$v8unpack" -E "$run_root/base.cf" "$json_dir"
main_json="$json_dir/CommonForm/$form_name/CommonForm.json"
managed_name="УправляемаяПробнаяФорма"
python3 "$tool_dir/verify.py" \
	"$fixture/CommonForms/$managed_name/Ext/Form.xml" \
	"$json_dir/CommonForm/$managed_name/CommonForm.json" \
	"$json_dir/CommonForm/$managed_name/CommonForm.elem.json" \
	"$run_root/managed-parity.json"
handler_paths="$run_root/handler-paths.json"
jq '[paths(scalars) as $path
	| select(getpath($path) == "\"ПриОткрытии\"")
	| $path]' "$main_json" >"$handler_paths"
jq -e '. == [
	["form", 0, 0, 4, 2, 2, 1],
	["form", 0, 0, 4, 2, 2, 2, 1]
]' "$handler_paths" >/dev/null
cp -a "$json_dir" "$probe_json_dir"
probe_main_json="$probe_json_dir/CommonForm/$form_name/CommonForm.json"
jq --slurpfile paths "$handler_paths" \
	'reduce $paths[0][] as $path (.;
		setpath($path; "\"ПробаПриОткрытии\""))' \
	"$main_json" >"$probe_main_json"
jq -ne --slurpfile base "$main_json" \
	--slurpfile probe "$probe_main_json" \
	--slurpfile paths "$handler_paths" \
	'($base[0] | reduce $paths[0][] as $path (.;
		setpath($path; ($probe[0] | getpath($path))))) == $probe[0]' \
	>/dev/null
cp "$fixture/probe/CommonForm.obj.bsl" \
	"$probe_json_dir/CommonForm/$form_name/CommonForm.obj.bsl"
"$v8unpack" -B "$probe_json_dir" "$run_root/probe.cf"

cp -a "$json_dir" "$attribute_json_dir"
attribute_elem_json="$attribute_json_dir/CommonForm/$form_name/CommonForm.elem.json"
jq '.props[0].name = "РеквизитПробника"
	| .props[0].raw[4] = "\"РеквизитПробника\""' \
	"$json_dir/CommonForm/$form_name/CommonForm.elem.json" >"$attribute_elem_json"
jq -ne \
	--slurpfile base "$json_dir/CommonForm/$form_name/CommonForm.elem.json" \
	--slurpfile probe "$attribute_elem_json" \
	'($base[0]
		| .props[0].name = "РеквизитПробника"
		| .props[0].raw[4] = "\"РеквизитПробника\"") == $probe[0]' \
	>/dev/null
"$v8unpack" -B "$attribute_json_dir" "$run_root/attribute.cf"

cp -a "$json_dir" "$data_path_json_dir"
data_path_main_json="$data_path_json_dir/CommonForm/$form_name/CommonForm.json"
jq '.form[0][0][2][3] = ["1", ["3", ["1", ["1"]]]]' \
	"$main_json" >"$data_path_main_json"
jq -ne --slurpfile base "$main_json" \
	--slurpfile probe "$data_path_main_json" \
	'($base[0] | .form[0][0][2][3] = ["1", ["3", ["1", ["1"]]]])
		== $probe[0]' \
	>/dev/null
"$v8unpack" -B "$data_path_json_dir" "$run_root/data-path.cf"

"$ibcmd" config load --data="$data_dir" --database-path="$ib_dir" "$run_root/attribute.cf"
"$ibcmd" config apply --data="$data_dir" --database-path="$ib_dir" --force
"$ibcmd" config save --data="$data_dir" --database-path="$ib_dir" "$run_root/attribute-roundtrip.cf"
"$v8unpack" -E "$run_root/attribute-roundtrip.cf" "$run_root/attribute-roundtrip-json"
jq -e '.props[0]
	| .name == "РеквизитПробника"
		and .raw[4] == "\"РеквизитПробника\""' \
	"$run_root/attribute-roundtrip-json/CommonForm/$form_name/CommonForm.elem.json" \
	>/dev/null

"$ibcmd" config load --data="$data_dir" --database-path="$ib_dir" "$run_root/data-path.cf"
"$ibcmd" config apply --data="$data_dir" --database-path="$ib_dir" --force
"$ibcmd" config save --data="$data_dir" --database-path="$ib_dir" "$run_root/data-path-roundtrip.cf"
"$v8unpack" -E "$run_root/data-path-roundtrip.cf" "$run_root/data-path-roundtrip-json"
jq -e '.data["Страница1/ПолеПробника"].prop == "Параметры"' \
	"$run_root/data-path-roundtrip-json/CommonForm/$form_name/CommonForm.elem.json" \
	>/dev/null

"$ibcmd" config load --data="$data_dir" --database-path="$ib_dir" "$run_root/probe.cf"
"$ibcmd" config apply --data="$data_dir" --database-path="$ib_dir" --force

display_number=190
while [ -S "/tmp/.X11-unix/X$display_number" ] \
	|| DISPLAY=":$display_number" xdpyinfo >/dev/null 2>&1; do
	display_number=$((display_number + 1))
done

client_command=(
	"$onec_client" ENTERPRISE "/F$ib_dir"
	/DisableStartupDialogs "/Out$client_out"
)
printf -v start_child '%q ' "${client_command[@]}"

# XAUTHORITY expands inside xpra.
# shellcheck disable=SC2016
env -u DISPLAY -u WAYLAND_DISPLAY timeout 90s xpra start-desktop ":$display_number" \
	--daemon=no \
	--attach=no \
	--mdns=no \
	--systemd-run=no \
	--exit-with-children=yes \
	--terminate-children=yes \
	--speaker=off \
	--microphone=off \
	--notifications=no \
	--printing=no \
	--webcam=no \
	--clipboard=no \
	--opengl=no \
	--html=off \
	--xvfb='Xvfb -screen 0 1280x800x24 -nolisten tcp -noreset -auth $XAUTHORITY' \
	--start-child="$start_child" \
	--log-file="$run_root/xpra.log" \
	>"$run_root/xpra-console.log" 2>&1

grep -oE '\{"action_id":"open-form".*\}' "$client_out" >"$run_root/events.jsonl"
jq -e '
	. == [
		{"action_id":"open-form","event":"ПередОткрытием","handler":"ПередОткрытием","sequence":1},
		{"action_id":"open-form","event":"ПриОткрытии","handler":"ПробаПриОткрытии","sequence":2}
	]' \
	--slurp "$run_root/events.jsonl" >/dev/null

source_tree_before_sha256="$(form_source_sha256)"
uv run --project "$repo_root" python -m rlm_tools_bsl.v8unpack_oracle \
	form-manifest verify \
	"$manifest"
uv run --project "$repo_root" python -m rlm_tools_bsl.v8unpack_oracle \
	form-inventory \
	--root "$live_root" \
	--manifest "$manifest" \
	--output "$run_root/inventory.json"
python3 "$tool_dir/matrix.py" \
	--inventory "$run_root/inventory.json" \
	--source-root "$live_root" \
	--skeleton-root "$json_dir" \
	--output "$run_root/matrix" \
	--v8unpack "$v8unpack" \
	--ibcmd "$ibcmd" \
	>"$run_root/matrix.out"
jq -e '.classes == 544 and .success == 544 and .failed == 0' \
	"$run_root/matrix/matrix.json" >/dev/null
jq -e --slurpfile inventory "$run_root/inventory.json" '
	.classes == ($inventory[0].structural_classes | length)
	and .structural_classes_sha256 == $inventory[0].structural_classes_sha256
	and .rows_sha256 == $inventory[0].rows_sha256
	and ([.results[].class_key] | unique | length) == .classes
' "$run_root/matrix/matrix.json" >/dev/null
jq -s -e '
	.[0].structural_classes_sha256 == .[1].ordinary_handler_registry.structural_classes_sha256
	and .[0].rows_sha256 == .[1].ordinary_handler_registry.rows_sha256
	and ([.[0].results[].class_key] | sort) == ([.[2].results[].class_key] | sort)
' "$run_root/matrix/matrix.json" "$manifest" \
	"$repo_root/tests/fixtures/v8unpack_oracle/forms-802.proof-matrix.json" >/dev/null
source_tree_after_sha256="$(form_source_sha256)"
test "$source_tree_before_sha256" = "$source_tree_after_sha256"

jq -n \
	--arg status success \
	--arg run_root "$run_root" \
	--arg platform_version "$("$ibcmd" --version | tail -1)" \
	--arg v8unpack_version "$("$v8unpack" --help | sed -n '1s/^usage: v8unpack \([^ ]*\).*/\1/p')" \
	--arg form "$form_name" \
	--arg event ПриОткрытии \
	--arg handler ПробаПриОткрытии \
	--arg canonical_event OnOpen \
	--arg virtual_display ":$display_number" \
	--arg base_cf_sha256 "$(sha256sum "$run_root/base.cf" | cut -d' ' -f1)" \
	--arg probe_cf_sha256 "$(sha256sum "$run_root/probe.cf" | cut -d' ' -f1)" \
	--arg base_form_json_sha256 "$(sha256sum "$main_json" | cut -d' ' -f1)" \
	--arg probe_form_json_sha256 "$(sha256sum "$probe_main_json" | cut -d' ' -f1)" \
	--arg attribute_cf_sha256 "$(sha256sum "$run_root/attribute.cf" | cut -d' ' -f1)" \
	--arg attribute_roundtrip_cf_sha256 "$(sha256sum "$run_root/attribute-roundtrip.cf" | cut -d' ' -f1)" \
	--arg data_path_cf_sha256 "$(sha256sum "$run_root/data-path.cf" | cut -d' ' -f1)" \
	--arg data_path_roundtrip_cf_sha256 "$(sha256sum "$run_root/data-path-roundtrip.cf" | cut -d' ' -f1)" \
	--arg managed_parity_sha256 "$(sha256sum "$run_root/managed-parity.json" | cut -d' ' -f1)" \
	--arg runtime_events_sha256 "$(sha256sum "$run_root/events.jsonl" | cut -d' ' -f1)" \
	--arg inventory_sha256 "$(sha256sum "$run_root/inventory.json" | cut -d' ' -f1)" \
	--arg matrix_sha256 "$(sha256sum "$run_root/matrix/matrix.json" | cut -d' ' -f1)" \
	--arg source_tree_before_sha256 "$source_tree_before_sha256" \
	--arg source_tree_after_sha256 "$source_tree_after_sha256" \
	--slurpfile handler_paths "$handler_paths" \
	--slurpfile runtime_events "$run_root/events.jsonl" \
	'{
		status: $status,
		run_root: $run_root,
		platform_version: $platform_version,
		v8unpack_version: $v8unpack_version,
		form: $form,
		event: $event,
		handler: $handler,
		handler_contract: {
			form_type: "0",
			element_version: "0-27",
			raw_event: "70001",
			raw_event_pointer: "/form/0/0/4/2/0",
			handler_pointer: "/form/0/0/4/2/2/1",
			handler_mirror_pointer: "/form/0/0/4/2/2/2/1",
			canonical_event: $canonical_event,
			scope: "form",
			element_name: "",
			element_type: "",
			data_path: ""
		},
		virtual_display: $virtual_display,
		runtime_events: $runtime_events,
		handler_paths: $handler_paths[0],
		static_probes: {
			attribute: {
				json_pointers: ["/props/0/name", "/props/0/raw/4"],
				before: "Параметры",
				after: "РеквизитПробника"
			},
			data_path: {
				json_pointer: "/form/0/0/2/3",
				element: "ПолеПробника",
				attribute: "Параметры"
			}
		},
		sha256: {
			base_cf: $base_cf_sha256,
			probe_cf: $probe_cf_sha256,
			base_form_json: $base_form_json_sha256,
			probe_form_json: $probe_form_json_sha256,
			attribute_cf: $attribute_cf_sha256,
			attribute_roundtrip_cf: $attribute_roundtrip_cf_sha256,
			data_path_cf: $data_path_cf_sha256,
			data_path_roundtrip_cf: $data_path_roundtrip_cf_sha256,
			managed_parity: $managed_parity_sha256,
			runtime_events: $runtime_events_sha256,
			inventory: $inventory_sha256,
			matrix: $matrix_sha256,
			source_tree_before: $source_tree_before_sha256,
			source_tree_after: $source_tree_after_sha256
		}
	}' >"$run_root/result.json"

printf '\nПробник выполнен: %s\n' "$run_root/result.json"
cat "$run_root/result.json"

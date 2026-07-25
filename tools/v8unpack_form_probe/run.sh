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
form_name="ПробнаяФорма"

for command in "$ibcmd" "$onec_client" "$v8unpack" xpra Xvfb xdpyinfo jq base64 timeout; do
	if ! command -v "$command" >/dev/null 2>&1 && [ ! -x "$command" ]; then
		printf 'Не найдена команда: %s\n' "$command" >&2
		exit 1
	fi
done

mkdir -p "$artifact_root"
run_root="$(mktemp -d "$artifact_root/run.XXXXXX")"
source_dir="$run_root/source"
ib_dir="$run_root/ib"
data_dir="$run_root/data"
json_dir="$run_root/json"
probe_json_dir="$run_root/probe-json"
client_out="$run_root/client.out"
mkdir -p "$source_dir/CommonForms/$form_name/Ext"
cp "$fixture/Configuration.xml" "$source_dir/"
cp -a "$fixture/Languages" "$fixture/Ext" "$source_dir/"
cp "$fixture/CommonForms/$form_name.xml" "$source_dir/CommonForms/"
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

event_json='{"action_id":"open-form","event":"ПриОткрытии","handler":"ПробаПриОткрытии","sequence":1}'
grep -oF "$event_json" "$client_out" >"$run_root/events.jsonl"
jq -e --argjson expected "$event_json" \
	'length == 1 and .[0] == $expected' \
	--slurp "$run_root/events.jsonl" >/dev/null

jq -n \
	--arg status success \
	--arg run_root "$run_root" \
	--arg platform_version "$("$ibcmd" --version | tail -1)" \
	--arg v8unpack_version "$("$v8unpack" --help | sed -n '1s/^usage: v8unpack \([^ ]*\).*/\1/p')" \
	--arg form "$form_name" \
	--arg event ПриОткрытии \
	--arg handler ПробаПриОткрытии \
	--arg virtual_display ":$display_number" \
	--arg base_cf_sha256 "$(sha256sum "$run_root/base.cf" | cut -d' ' -f1)" \
	--arg probe_cf_sha256 "$(sha256sum "$run_root/probe.cf" | cut -d' ' -f1)" \
	--arg base_form_json_sha256 "$(sha256sum "$main_json" | cut -d' ' -f1)" \
	--arg probe_form_json_sha256 "$(sha256sum "$probe_main_json" | cut -d' ' -f1)" \
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
		virtual_display: $virtual_display,
		runtime_events: $runtime_events,
		handler_paths: $handler_paths[0],
		sha256: {
			base_cf: $base_cf_sha256,
			probe_cf: $probe_cf_sha256,
			base_form_json: $base_form_json_sha256,
			probe_form_json: $probe_form_json_sha256
		}
	}' >"$run_root/result.json"

printf '\nПробник выполнен: %s\n' "$run_root/result.json"
cat "$run_root/result.json"

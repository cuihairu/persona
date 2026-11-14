-- Copyright 2026 cuihairu <chuihairu@gmail.com>
-- SPDX-License-Identifier: MIT

module("luci.controller.persona", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/persona") then
		return
	end

	entry({"admin", "services", "persona"},
		cbi("persona"),
		_("Persona Server"), 60).dependent = true

	entry({"admin", "services", "persona", "status"},
		template("persona/status"),
		_("运行状态"), 10).leaf = true

	entry({"admin", "services", "persona", "api", "status"},
		call("api_status")).leaf = true
end

-- Strip control characters and cap the length. The status page renders
-- through DOM textContent so HTML injection is impossible, but log-derived
-- lines still must not flood the response.
local function sanitize(value, max)
	if value == nil then
		return ""
	end
	local s = tostring(value):gsub("%c", "")
	if #s > max then
		s = s:sub(1, max) .. "…"
	end
	return s
end

function api_status()
	luci.http.prepare_content("application/json")
	local sys = require("luci.sys")
	local uci = require("luci.model.uci").cursor()
	local nixio = require("nixio")

	local out = {}

	-- procd service state via the rc.common wrapper (exit 0 = running,
	-- non-zero = stopped); report whether the service is UCI-enabled so
	-- the page can distinguish "disabled" from "stopped".
	local code = sys.call("/etc/init.d/persona status >/dev/null 2>&1")
	out.running = (code == 0)
	out.enabled = (uci:get("persona", "main", "enabled") == "1")

	out.host = sanitize(uci:get("persona", "main", "host") or "0.0.0.0", 64)
	local port = tonumber(uci:get("persona", "main", "port") or "3000") or 3000
	if port < 1 or port > 65535 then
		port = 3000
	end
	out.port = port

	-- Listen check: busybox netstat, match the local-address column ending
	-- in ":<port>". port is digits-only at this point, safe to interpolate.
	local listen_cmd = string.format(
		"netstat -ltn 2>/dev/null | awk '$4 ~ /:%d$/ { found=1 } END { exit !found }'",
		port)
	out.listening = (sys.call(listen_cmd) == 0)

	-- Database file: existence + size only. Path is UCI-managed (settings
	-- page); the default matches the init script so a fresh install with
	-- no UCI value still renders.
	local db = uci:get("persona", "main", "db") or "/etc/persona/persona.db"
	out.db = db
	local st = nixio.fs.stat(db)
	if st then
		out.db_size = st.size or 0
	else
		out.db_missing = true
	end

	-- Token file: report PRESENCE only, never content (zero-knowledge red
	-- line — credentials stay out of configs, logs and HTTP responses).
	local tokens_file = uci:get("persona", "main", "tokens_file") or "/etc/persona/tokens"
	out.tokens_file = tokens_file
	out.tokens_file_present = nixio.fs.access(tokens_file, "r") and true or false

	-- Recent service logs from syslog (procd forwards stdout/stderr).
	local raw = require("luci.util").exec("logread -e persona 2>/dev/null | tail -n 20")
	out.logs = {}
	if raw and raw ~= "" then
		for line in raw:gmatch("[^\r\n]+") do
			out.logs[#out.logs + 1] = sanitize(line, 200)
		end
	end

	luci.http.write_json(out)
end

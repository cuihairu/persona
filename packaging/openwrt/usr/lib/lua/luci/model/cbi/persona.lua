-- Copyright 2026 cuihairu <chuihairu@gmail.com>
-- SPDX-License-Identifier: MIT

m = Map("persona", translate("Persona Server"),
	translate("自托管同步服务（Rust + Axum + SQLite）：中继分身密文、备份与多设备账号。zero-knowledge——服务器只见密文。"))

-- Write-back safety (custos LUCI-RES-002 口径): the service restarts only
-- after a SUCCESSFUL CBI apply. CBI rejects invalid input (datatype /
-- validators below) before anything is committed, so on_commit cannot fire
-- for a broken config; init.d re-reads UCI on every start, which is what
-- makes the restart effective.
function m.on_commit()
	luci.sys.call("/etc/init.d/persona restart >/dev/null 2>&1")
end

s = m:section(NamedSection, "main", "main", translate("全局设置"))
s.addremove = false

-- Values travel through the procd environment; whitespace would break the
-- env word-splitting, so free-form fields reject it (same as custos).
local function no_space(self, value)
	if value and value:find("%s") then
		return nil, translate("不能包含空白字符")
	end
	return value
end

o = s:option(Flag, "enabled", translate("启用服务"))
o.rmempty = false

o = s:option(Value, "host", translate("监听地址"))
o.default = "0.0.0.0"
o.rmempty = false
o.validate = no_space
o.description = translate("HTTP API 绑定地址（0.0.0.0 = 所有接口）")

o = s:option(Value, "port", translate("监听端口"))
o.default = "3000"
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "db", translate("数据库路径"))
o.default = "/etc/persona/persona.db"
o.rmempty = false
o.validate = no_space
o.description = translate("SQLite 数据库文件（init 启动时自动建父目录；备份默认写入同目录 backups/）")

o = s:option(Value, "backup_dir", translate("备份目录"))
o.rmempty = true
o.validate = no_space
o.description = translate("留空 = 数据库同目录下的 backups/")

o = s:option(Value, "backup_max_versions", translate("备份版本上限"))
o.default = "0"
o.datatype = "uinteger"
o.rmempty = false
o.description = translate("保留的备份版本数，0 = 服务端默认")

o = s:option(Value, "ops_retention_days", translate("运维日志保留 (天)"))
o.default = "0"
o.datatype = "uinteger"
o.rmempty = false

o = s:option(Value, "events_retention_days", translate("事件保留 (天)"))
o.default = "0"
o.datatype = "uinteger"
o.rmempty = false

o = s:option(Value, "tokens_file", translate("设备令牌文件路径"))
o.default = "/etc/persona/tokens"
o.rmempty = false
o.validate = no_space
o.description = translate(
	"root-only 文件（0600），内容为一行 \"name:token,name:token\"。" ..
	"凭据只存在这个文件里，绝不写入 UCI（zero-knowledge 红线）。" ..
	"文件缺失或为空时 /api 保持关闭（fail-closed）。示例：" ..
	"echo 'phone:SECRET,laptop:SECRET2' > /etc/persona/tokens && chmod 600 /etc/persona/tokens")

return m

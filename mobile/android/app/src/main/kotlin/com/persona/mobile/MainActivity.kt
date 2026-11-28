package com.persona.mobile

import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.tabs.TabLayout
import org.json.JSONObject

/**
 * Native first screen: verifies JNI bridge connectivity (version number) and
 * exercises the init/unlock/lock lifecycle. After unlocking it enters the
 * three-tab business area (Data = credential list / Tools = refresh + lock /
 * Settings = bridge and vault info); the credential list is fetched through the
 * business FFI (`persona_credential_search`, envelope `{"ok":bool,"error"?,"data":[]}`)
 * and only metadata is displayed, with no decryption.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var status: TextView
    private lateinit var password: EditText
    private lateinit var lockScreen: View
    private lateinit var tabLayout: TabLayout
    private lateinit var tabContainer: View
    private lateinit var dataContainer: View
    private lateinit var toolsContainer: View
    private lateinit var settingsContainer: View
    private lateinit var credentialList: LinearLayout
    private lateinit var credentialCount: TextView
    private lateinit var credentialEmpty: TextView
    private lateinit var settingsBridge: TextView
    private lateinit var settingsVersion: TextView
    private lateinit var settingsVault: TextView
    private lateinit var settingsCount: TextView
    private lateinit var remoteServer: EditText
    private lateinit var remoteBootstrap: EditText
    private lateinit var remoteDevice: EditText
    private lateinit var remotePassword: EditText
    private lateinit var remoteStatus: TextView
    private lateinit var remoteDeviceList: LinearLayout

    /** Short-lived Bearer from the last SRP login (server TTL 15 min; held in
     * memory only — a process restart just logs in again). */
    @Volatile
    private var remoteToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        password = findViewById(R.id.master_password)
        lockScreen = findViewById(R.id.lock_screen)
        tabLayout = findViewById(R.id.tab_layout)
        tabContainer = findViewById(R.id.tab_container)
        dataContainer = findViewById(R.id.data_container)
        toolsContainer = findViewById(R.id.tools_container)
        settingsContainer = findViewById(R.id.settings_container)
        credentialList = findViewById(R.id.credential_list)
        credentialCount = findViewById(R.id.credential_count)
        credentialEmpty = findViewById(R.id.credential_empty)
        settingsBridge = findViewById(R.id.settings_bridge_value)
        settingsVersion = findViewById(R.id.settings_version_value)
        settingsVault = findViewById(R.id.settings_vault_value)
        settingsCount = findViewById(R.id.settings_count_value)
        remoteServer = findViewById(R.id.remote_server)
        remoteBootstrap = findViewById(R.id.remote_bootstrap)
        remoteDevice = findViewById(R.id.remote_device)
        remotePassword = findViewById(R.id.remote_password)
        remoteStatus = findViewById(R.id.remote_status)
        remoteDeviceList = findViewById(R.id.remote_device_list)

        // Default device name identifies this phone: the server's login-awareness
        // ledger keys on it (PERSONA-DEVALERT-001). Sanitized to the charset the
        // server's device-name validator accepts.
        remoteDevice.setText(
            "android-" + Build.MODEL.orEmpty().replace(Regex("[^A-Za-z0-9._-]"), "-")
                .trim('-').take(48)
        )

        status.text = runCatching {
            PersonaBridge.personaInit()
            // The version may be null when the runtime has not started — the display layer falls back to "unknown" rather than crashing
            "桥已连通 · persona ${PersonaBridge.personaVersion() ?: "未知"}"
        }.getOrElse { "桥加载失败：${it.message}" }

        val initButton = findViewById<Button>(R.id.init_button)
        val unlockButton = findViewById<Button>(R.id.unlock_button)
        val lockButton = findViewById<Button>(R.id.lock_button)
        val reloadButton = findViewById<Button>(R.id.reload_button)

        initButton.setOnClickListener { submit(initial = true) }
        unlockButton.setOnClickListener { submit(initial = false) }
        lockButton.setOnClickListener {
            val (ok, error) = PersonaBridge.parseResult(PersonaBridge.personaServiceLock())
            status.text = if (ok) "已锁定" else "锁定失败：$error"
            refreshUnlockState()
        }
        reloadButton.setOnClickListener {
            refreshDataTab()
            status.text = "凭据列表已刷新"
        }

        // Remote-auth wiring (Settings tab): widget text is read here on the
        // UI thread, then the bridge call runs on its own thread — the UI
        // thread must never wait on the network (the native side blocks on
        // its tokio runtime).
        findViewById<Button>(R.id.remote_register_button).setOnClickListener { view ->
            view.isEnabled = false
            Thread {
                remoteRegister(
                    remoteServer.text.toString().trim().trimEnd('/'),
                    remoteBootstrap.text.toString().trim(),
                    remoteDevice.text.toString().trim(),
                    remotePassword.text.toString(),
                    view,
                )
            }.start()
        }
        findViewById<Button>(R.id.remote_login_button).setOnClickListener { view ->
            view.isEnabled = false
            Thread {
                remoteLogin(
                    remoteServer.text.toString().trim().trimEnd('/'),
                    remoteDevice.text.toString().trim(),
                    remotePassword.text.toString(),
                    view,
                )
            }.start()
        }
        findViewById<Button>(R.id.remote_devices_button).setOnClickListener { _ ->
            Thread {
                refreshRemoteDevices(remoteServer.text.toString().trim().trimEnd('/'))
            }.start()
        }

        for (label in listOf(R.string.tab_data, R.string.tab_tools, R.string.tab_settings)) {
            tabLayout.addTab(tabLayout.newTab().setText(label))
        }
        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) = showTab(tab.position)
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })

        refreshUnlockState()
    }

    private fun submit(initial: Boolean) {
        val master = password.text.toString()
        if (master.isEmpty()) {
            status.text = "请输入主密码"
            return
        }
        val dbPath = getDatabasePath("persona.db").absolutePath
        // On first install the databases/ parent directory does not exist, and SQLite
        // mode=rwc creates the file but not the directory — create the directory first,
        // then hand it to the native layer (confirmed during the 2026-10-11 build walkthrough)
        getDatabasePath("persona.db").parentFile?.mkdirs()
        val json = if (initial) {
            PersonaBridge.personaServiceInit(dbPath, master)
        } else {
            PersonaBridge.personaServiceUnlock(master)
        }
        val (ok, error) = PersonaBridge.parseResult(json)
        status.text = if (ok) {
            if (initial) "初始化成功（已解锁）" else "解锁成功"
        } else {
            "${if (initial) "初始化" else "解锁"}失败：$error"
        }
        password.text.clear()
        refreshUnlockState()
    }

    private fun refreshUnlockState() {
        val unlocked = runCatching { PersonaBridge.personaServiceIsUnlocked() }.getOrDefault(false)
        findViewById<Button>(R.id.lock_button).visibility =
            if (unlocked) View.VISIBLE else View.GONE
        lockScreen.visibility = if (unlocked) View.GONE else View.VISIBLE
        tabLayout.visibility = if (unlocked) View.VISIBLE else View.GONE
        tabContainer.visibility = if (unlocked) View.VISIBLE else View.GONE
        if (unlocked) {
            settingsBridge.text = "已连通"
            settingsVersion.text = PersonaBridge.personaVersion() ?: "未知"
            settingsVault.text = getDatabasePath("persona.db").absolutePath
            showTab(tabLayout.selectedTabPosition.coerceAtLeast(0))
            refreshDataTab()
        }
    }

    private fun showTab(position: Int) {
        dataContainer.visibility = if (position == 0) View.VISIBLE else View.GONE
        toolsContainer.visibility = if (position == 1) View.VISIBLE else View.GONE
        settingsContainer.visibility = if (position == 2) View.VISIBLE else View.GONE
    }

    private fun refreshDataTab() {
        credentialList.removeAllViews()
        credentialEmpty.text = getString(R.string.credential_empty)
        val (ok, error, payload) =
            PersonaBridge.parseBusiness(PersonaBridge.personaCredentialSearch(""))
        if (!ok) {
            credentialCount.text = "加载失败"
            credentialEmpty.text = error ?: "未知错误"
            credentialEmpty.visibility = View.VISIBLE
            return
        }
        val items = payload?.optJSONArray("data") ?: org.json.JSONArray()
        credentialCount.text = "共 ${items.length()} 条凭据"
        settingsCount.text = "${items.length()} 条"
        credentialEmpty.visibility = if (items.length() == 0) View.VISIBLE else View.GONE
        for (i in 0 until items.length()) {
            val item = items.optJSONObject(i) ?: continue
            val row = layoutInflater.inflate(R.layout.credential_row, credentialList, false)
            row.findViewById<TextView>(R.id.row_name).text = item.optString("name")
            // org.json's optString returns the literal "null" for JSON null, so treat it as empty
            val meta = listOf(
                item.optString("username", "").takeIf { it.isNotBlank() && it != "null" },
                item.optString("credential_type", "").takeIf { it.isNotBlank() && it != "null" },
            ).filterNotNull().joinToString(" · ")
            row.findViewById<TextView>(R.id.row_meta).text = meta
            credentialList.addView(row)
        }
    }

    // ---- Remote auth (Settings tab): the mobile side of the server's
    // login-awareness surface — an SRP login IS the fingerprint report
    // (device name + peer IP + time land in the server ledger). ----

    private fun requireRemoteButton(button: View, enabled: Boolean) {
        runOnUiThread { button.isEnabled = enabled }
    }

    private fun remoteStatusText(text: String) {
        runOnUiThread { remoteStatus.text = text }
    }

    private fun remoteRegister(base: String, bearer: String, name: String, pass: String, button: View) {
        if (base.isEmpty() || bearer.isEmpty() || name.isEmpty() || pass.isEmpty()) {
            remoteStatusText("请填写服务器地址、引导令牌、设备名与设备密码")
            requireRemoteButton(button, true)
            return
        }
        val (ok, error, payload) =
            PersonaBridge.parseBusiness(PersonaBridge.personaRemoteRegisterDevice(base, bearer, name, pass))
        runOnUiThread {
            // payload is the whole envelope; the business value lives under data
            val device = payload?.optJSONObject("data")?.optString("device")
                ?.takeIf { it.isNotEmpty() } ?: name
            remoteStatus.text = if (ok) {
                "设备已注册：$device（密码即 SRP 登录密码）"
            } else {
                "注册失败：$error"
            }
            button.isEnabled = true
        }
    }

    private fun remoteLogin(base: String, name: String, pass: String, button: View) {
        if (base.isEmpty() || name.isEmpty() || pass.isEmpty()) {
            remoteStatusText("请填写服务器地址、设备名与设备密码")
            requireRemoteButton(button, true)
            return
        }
        val (ok, error, payload) =
            PersonaBridge.parseBusiness(PersonaBridge.personaRemoteLogin(base, name, pass))
        if (!ok) {
            remoteStatusText("登录失败：$error")
            requireRemoteButton(button, true)
            return
        }
        // payload is the whole envelope; the business value lives under data
        val data = payload?.optJSONObject("data")
        remoteToken = data?.optString("token")?.takeIf { it.isNotEmpty() }
        val expires = data?.optLong("expires_in_secs") ?: 0L
        val fingerprint = data?.optString("session_key_fingerprint").orEmpty().take(12)
        remoteStatusText("SRP 登录成功：$name（指纹已上报 · 令牌 ${expires}s · 会话 ${fingerprint}…）")
        requireRemoteButton(button, true)
        refreshRemoteDevices(base)
    }

    private fun refreshRemoteDevices(base: String) {
        val token = remoteToken
        if (base.isEmpty() || token == null) {
            remoteStatusText("先 SRP 登录拿到令牌，再刷新设备清单")
            return
        }
        val (ok, error, payload) =
            PersonaBridge.parseBusiness(PersonaBridge.personaRemoteDevices(base, token))
        if (!ok) {
            remoteStatusText("设备清单获取失败：$error")
            return
        }
        val devices = payload?.optJSONObject("data")?.optJSONArray("devices")
            ?: org.json.JSONArray()
        runOnUiThread {
            remoteDeviceList.removeAllViews()
            for (i in 0 until devices.length()) {
                val d = devices.optJSONObject(i) ?: continue
                val row = layoutInflater.inflate(R.layout.credential_row, remoteDeviceList, false)
                row.findViewById<TextView>(R.id.row_name).text = d.optString("device")
                val meta = listOf(
                    d.optString("last_ip", "").takeIf { it.isNotBlank() && it != "null" },
                    d.optString("last_geo", "").takeIf { it.isNotBlank() && it != "null" },
                    "ok=${d.optLong("ok_count", 0)}",
                    "fail=${d.optLong("fail_count", 0)}",
                ).filterNotNull().joinToString(" · ")
                row.findViewById<TextView>(R.id.row_meta).text = meta
                remoteDeviceList.addView(row)
            }
            remoteStatus.text = "设备清单（${devices.length()} 台）"
        }
    }
}

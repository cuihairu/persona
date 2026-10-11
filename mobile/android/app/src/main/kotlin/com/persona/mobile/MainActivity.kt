package com.persona.mobile

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
 * 原生首屏：验证 JNI 桥连通（版本号）+ 走通 init/unlock/lock 生命周期。
 * 解锁后进入三 tab 业务区（数据 = 凭据列表 / 工具 = 刷新·锁定 / 设置 =
 * 桥与保险库信息），凭据列表经业务 FFI（`persona_credential_search`，
 * 包络 `{"ok":bool,"error"?,"data":[]}`）取数，只展示元数据、不解密。
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

        status.text = runCatching {
            PersonaBridge.personaInit()
            // runtime 未起时版本可能为 null——展示层兜底"未知"，不当崩溃
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
        // 首装时 databases/ 父目录不存在，SQLite mode=rwc 只建文件不建目录——
        // 先建目录再交给 native（2026-10-11 出图走查实锤）
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
            val meta = listOf(
                item.optString("username", "").ifBlank { null },
                item.optString("credential_type", "").ifBlank { null },
            ).filterNotNull().joinToString(" · ")
            row.findViewById<TextView>(R.id.row_meta).text = meta
            credentialList.addView(row)
        }
    }
}

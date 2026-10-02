package com.persona.mobile

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * 原生骨架首屏：验证 JNI 桥连通（版本号）+ 走通 init/unlock/lock 生命周期。
 * 业务 UI（凭证库、TOTP、自动填充）在此基座上逐功能落地。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var status: TextView
    private lateinit var password: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        password = findViewById(R.id.master_password)
        val initButton = findViewById<Button>(R.id.init_button)
        val unlockButton = findViewById<Button>(R.id.unlock_button)
        val lockButton = findViewById<Button>(R.id.lock_button)

        status.text = runCatching {
            PersonaBridge.personaInit()
            "桥已连通 · persona ${PersonaBridge.personaVersion()}"
        }.getOrElse { "桥加载失败：${it.message}" }

        initButton.setOnClickListener { submit(initial = true) }
        unlockButton.setOnClickListener { submit(initial = false) }
        lockButton.setOnClickListener {
            val (ok, error) = PersonaBridge.parseResult(PersonaBridge.personaServiceLock())
            status.text = if (ok) "已锁定" else "锁定失败：$error"
            refreshUnlockState()
        }
        refreshUnlockState()
    }

    private fun submit(initial: Boolean) {
        val master = password.text.toString()
        if (master.isEmpty()) {
            status.text = "请输入主密码"
            return
        }
        val dbPath = getDatabasePath("persona.db").absolutePath
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
    }
}

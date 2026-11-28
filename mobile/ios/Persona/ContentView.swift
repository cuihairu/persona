import SwiftUI
import UIKit

/// Native skeleton first screen: verifies staticlib bridge connectivity (version number)
/// plus the init/unlock/lock lifecycle. The business UI (credential vault, TOTP, wallet)
/// lands feature by feature on this base; security layers such as high-sensitivity
/// re-authentication and content masking are implemented on feature integration, to the
/// same standard as the desktop.
struct ContentView: View {
    @State private var status = "正在加载 persona 桥…"
    @State private var masterPassword = ""
    @State private var unlocked = false

    // Remote login awareness (PERSONA-MOBILE-002 / DEVALERT-001): an SRP login IS
    // the fingerprint report — device name + peer IP + time land in the server
    // ledger. The FFI blocks on the native tokio runtime, so every remote call
    // runs on a background queue and hops back to the main thread for UI.
    @State private var remoteServer = ""
    @State private var remoteBootstrap = ""
    @State private var remoteDevice = ContentView.defaultDeviceName
    @State private var remotePassword = ""
    @State private var remoteStatus = ""
    @State private var remoteToken: String?
    @State private var deviceLines: [String] = []

    private static let defaultDeviceName: String = {
        let cleaned = ("ios-" + UIDevice.current.name)
            .replacingOccurrences(of: "[^A-Za-z0-9._-]", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String(cleaned.prefix(48))
    }()

    var body: some View {
        Form {
            Section {
                Text(status).font(.footnote)
            }
            Section("主密码") {
                SecureField("主密码", text: $masterPassword)
                Button("初始化 / 首次建户") { submit(initial: true) }
                Button("解锁") { submit(initial: false) }
                if unlocked {
                    Button("锁定", role: .destructive) {
                        settle(PersonaBridge.serviceLock())
                    }
                }
            }
            Section("服务器登录感知（登录即上报设备指纹）") {
                TextField("服务器地址（如 http://10.0.2.2:18903）", text: $remoteServer)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                TextField("引导令牌（bootstrap Bearer）", text: $remoteBootstrap)
                    .textInputAutocapitalization(.never)
                TextField("设备名", text: $remoteDevice)
                    .textInputAutocapitalization(.never)
                SecureField("设备密码", text: $remotePassword)
                HStack {
                    Button("注册设备") { remoteRegister() }
                    Button("SRP 登录") { remoteLogin() }
                    Button("刷新设备清单") { refreshRemoteDevices() }
                }
                if !remoteStatus.isEmpty {
                    Text(remoteStatus).font(.footnote)
                }
                ForEach(deviceLines, id: \.self) { line in
                    Text(line).font(.caption)
                }
            }
        }
        .onAppear {
            status = "桥已连通 · persona \(PersonaBridge.version)"
            refreshUnlockState()
        }
    }

    // ---- Remote auth (PERSONA-MOBILE-002): the mobile side of the server's
    // login-awareness surface. ----

    /// Validated input tuple; empty strings mean the user did not fill them yet.
    private var normalizedRemoteInputs: (base: String, name: String, pass: String) {
        (remoteServer.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "/")),
         remoteDevice.trimmingCharacters(in: .whitespaces),
         remotePassword)
    }

    private func remoteRegister() {
        let (base, name, pass) = normalizedRemoteInputs
        let bearer = remoteBootstrap.trimmingCharacters(in: .whitespaces)
        guard !base.isEmpty, !bearer.isEmpty, !name.isEmpty, !pass.isEmpty else {
            remoteStatus = "请填写服务器地址、引导令牌、设备名与设备密码"
            return
        }
        remoteStatus = "注册中…"
        DispatchQueue.global(qos: .userInitiated).async {
            let envelope = PersonaBridge.parseBusiness(
                PersonaBridge.remoteRegisterDevice(baseUrl: base, bearer: bearer,
                                                   deviceName: name, password: pass))
            DispatchQueue.main.async {
                remoteStatus = envelope.ok
                    ? "设备已注册：\((envelope.data?["device"] as? String) ?? name)（密码即 SRP 登录密码）"
                    : "注册失败：\(envelope.error ?? "未知错误")"
            }
        }
    }

    private func remoteLogin() {
        let (base, name, pass) = normalizedRemoteInputs
        guard !base.isEmpty, !name.isEmpty, !pass.isEmpty else {
            remoteStatus = "请填写服务器地址、设备名与设备密码"
            return
        }
        remoteStatus = "登录中…"
        DispatchQueue.global(qos: .userInitiated).async {
            let envelope = PersonaBridge.parseBusiness(
                PersonaBridge.remoteLogin(baseUrl: base, deviceName: name, password: pass))
            DispatchQueue.main.async {
                guard envelope.ok else {
                    remoteStatus = "登录失败：\(envelope.error ?? "未知错误")"
                    return
                }
                let data = envelope.data ?? [:]
                remoteToken = data["token"] as? String
                let expires = data["expires_in_secs"] as? Int ?? 0
                let fingerprint = (data["session_key_fingerprint"] as? String ?? "").prefix(12)
                remoteStatus = "SRP 登录成功：\(name)（指纹已上报 · 令牌 \(expires)s · 会话 \(fingerprint)…）"
                refreshRemoteDevices(base: base)
            }
        }
    }

    private func refreshRemoteDevices(base: String? = nil) {
        let (serverBase, _, _) = normalizedRemoteInputs
        let baseUrl = base ?? serverBase
        let token = remoteToken
        guard !baseUrl.isEmpty, token != nil else {
            remoteStatus = "先 SRP 登录拿到令牌，再刷新设备清单"
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let envelope = PersonaBridge.parseBusiness(
                PersonaBridge.remoteDevices(baseUrl: baseUrl, token: token!))
            DispatchQueue.main.async {
                guard envelope.ok,
                      let devices = (envelope.data?["devices"] as? [[String: Any]])
                else {
                    remoteStatus = "设备清单获取失败：\(envelope.error ?? "未知错误")"
                    return
                }
                deviceLines = devices.map { d in
                    "\(d["device"] as? String ?? "?") · \(d["last_ip"] as? String ?? "-") · " +
                        "\(d["last_geo"] as? String ?? "-") · ok=\(d["ok_count"] as? Int ?? 0)" +
                        " · fail=\(d["fail_count"] as? Int ?? 0)"
                }
                remoteStatus = "设备清单（\(devices.count) 台）"
            }
        }
    }

    private func submit(initial: Bool) {
        guard !masterPassword.isEmpty else {
            status = "请输入主密码"
            return
        }
        let dbPath = dbURL.path
        let result = initial
            ? PersonaBridge.serviceInit(dbPath: dbPath, masterPassword: masterPassword)
            : PersonaBridge.serviceUnlock(masterPassword: masterPassword)
        settle(result)
        masterPassword = ""
    }

    private func settle(_ result: Result<Void, String>) {
        switch result {
        case .success:
            status = unlockedMessage
        case .failure(let error):
            status = "失败：\(error)"
        }
        refreshUnlockState()
    }

    private var unlockedMessage: String {
        PersonaBridge.isUnlocked ? "已解锁" : "已锁定"
    }

    private func refreshUnlockState() {
        unlocked = PersonaBridge.isUnlocked
    }

    private var dbURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("persona.db")
    }
}

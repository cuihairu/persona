import SwiftUI

/// Native skeleton first screen: verifies staticlib bridge connectivity (version number)
/// plus the init/unlock/lock lifecycle. The business UI (credential vault, TOTP, wallet)
/// lands feature by feature on this base; security layers such as high-sensitivity
/// re-authentication and content masking are implemented on feature integration, to the
/// same standard as the desktop.
struct ContentView: View {
    @State private var status = "正在加载 persona 桥…"
    @State private var masterPassword = ""
    @State private var unlocked = false

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
        }
        .onAppear {
            status = "桥已连通 · persona \(PersonaBridge.version)"
            refreshUnlockState()
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

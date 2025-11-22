import SwiftUI

@main
struct PersonaSafariExtensionApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("Persona Safari Extension")
                .font(.title2)
            Text("This host app exists to allow Safari to enable the WebExtension. Build the shared JS bundle first, then open the generated Xcode project to run in Safari.")
                .font(.body)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(minWidth: 320, minHeight: 200)
    }
}

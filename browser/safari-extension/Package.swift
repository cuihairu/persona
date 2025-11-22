// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PersonaSafariExtension",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "PersonaSafariExtensionApp", targets: ["PersonaSafariExtensionApp"])
    ],
    targets: [
        .executableTarget(
            name: "PersonaSafariExtensionApp",
            path: "Sources/PersonaSafariExtensionApp"
        ),
        .target(
            name: "PersonaSafariExtensionExtension",
            path: "Sources/PersonaSafariExtensionExtension"
        )
    ]
)

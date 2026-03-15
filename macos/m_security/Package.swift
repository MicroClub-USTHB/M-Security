// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "m_security",
    platforms: [
        .macOS("10.11")
    ],
    products: [
        .library(name: "m-security", targets: ["m_security"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "m_security",
            dependencies: [],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        )
    ]
)

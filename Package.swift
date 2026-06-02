// swift-tools-version: 6.2
import PackageDescription

private let strictSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("StrictConcurrency"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
]

let package = Package(
    name: "FireAuthKit",
    platforms: [
        .iOS(.v18),
        .macOS(.v14),
    ],
    products: [
        .library(name: "FireAuthKit", targets: ["FireAuthKit"]),
        .library(name: "FireAuthKitSocial", targets: ["FireAuthKitSocial"]),
        .library(name: "FireAuthProvider", targets: ["FireAuthProvider"]),
        .library(name: "FireAuthProviderImpl", targets: ["FireAuthProviderImpl"]),
    ],
    targets: [
        .target(
            name: "FireAuthKit",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "FireAuthKitSocial",
            dependencies: [
                "FireAuthKit",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "FireAuthProvider",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "FireAuthProviderImpl",
            dependencies: [
                "FireAuthProvider",
                "FireAuthKit",
                "FireAuthKitSocial",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "FireAuthKitTests",
            dependencies: [
                "FireAuthKit",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "FireAuthProviderTests",
            dependencies: [
                "FireAuthProvider",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "FireAuthProviderImplTests",
            dependencies: [
                "FireAuthKit",
                "FireAuthProvider",
                "FireAuthProviderImpl",
            ],
            swiftSettings: strictSwiftSettings
        ),
    ]
)

#if TUIST
    import ProjectDescription

    let packageSettings = PackageSettings(
        productTypes: [
            "FireAuthKit": .framework,
            "FireAuthKitSocial": .framework,
            "FireAuthProvider": .framework,
            "FireAuthProviderImpl": .framework,
        ]
    )
#endif

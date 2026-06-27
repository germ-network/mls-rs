// This script should not run on any platform besides macOS, but making the whole file conditional
// results in `cargo` complaining about there being no `main()` method in build.rs.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    swift::configure();
    swift::link_package("cryptokit-bridge", "./cryptokit-bridge/");
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod swift {
    use serde::Deserialize;
    use std::{env, process::Command};

    /// Needed because of the min system reqs for HPKE in CryptoKit.
    /// See https://developer.apple.com/documentation/cryptokit/hpke
    const MIN_IOS_DEPLOYMENT_TARGET: &str = "17.0";
    // macOS ships the Swift runtime in the OS, so any modern deployment target does NOT
    // require an rpath. "26.0" tripped `libraries_require_rpath` (and the panic in
    // configure()) on the macOS 26 SDK — even for the host bindgen build. 15.0 is safe.
    const MIN_OSX_DEPLOYMENT_TARGET: &str = "15.0";

    #[derive(Debug, Deserialize)]
    struct SwiftTargetInfo {
        #[serde(rename = "unversionedTriple")]
        pub unversioned_triple: String,
        #[serde(rename = "librariesRequireRPath")]
        pub libraries_require_rpath: bool,
    }

    #[derive(Debug, Deserialize)]
    struct SwiftPaths {
        #[serde(rename = "runtimeLibraryPaths")]
        pub runtime_library_paths: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct SwiftTarget {
        pub target: SwiftTargetInfo,
        pub paths: SwiftPaths,
    }

    fn get_target_info() -> SwiftTarget {
        let target = get_target_triple();
        let swift_target_info_str = Command::new("swift")
            .args(["-print-target-info", &format!("--target={}", target)])
            .output()
            .unwrap()
            .stdout;
        serde_json::from_slice(&swift_target_info_str).unwrap()
    }

    fn get_target_triple() -> String {
        // Have to do this dance because some of the rust triples dont match what swift build expects...
        // Specifically x86_64-apple-ios seems to strugle.
        // Got the triples from https://github.com/swiftlang/swift/blob/main/utils/build-script-impl
        // We need to pass the MIN_OS var into these because for all platforms other than macOS, not doing so will cause
        // libraries_require_rpath to be true and this build script has no support for RPaths.
        match env::var("TARGET").unwrap().as_str() {
            "aarch64-apple-ios" => format!("arm64-apple-ios{MIN_IOS_DEPLOYMENT_TARGET}"),
            "x86_64-apple-ios" => {
                format!("x86_64-apple-ios{MIN_IOS_DEPLOYMENT_TARGET}-simulator")
            }
            "aarch64-apple-ios-sim" => {
                format!("arm64-apple-ios{MIN_IOS_DEPLOYMENT_TARGET}-simulator")
            }
            "aarch64-apple-darwin" => format!("arm64-apple-macosx{MIN_OSX_DEPLOYMENT_TARGET}"),
            "x86_64-apple-darwin" => format!("x86_64-apple-macosx{MIN_OSX_DEPLOYMENT_TARGET}"),
            unknown_target => panic!("Unsupported Arch for swift: {unknown_target}"), //
        }
    }

    pub fn configure() {
        let swift_target_info = get_target_info();
        // NOTE: some toolchains (e.g. the macOS 26 / Xcode 26 betas) report
        // `librariesRequireRPath = true` for *every* Apple target, including iOS. The
        // original code panicked in that case. That guard is spurious for our use: the
        // cdylib is shipped inside an `@rpath/…framework` (see TwoMLSPQ buildIosDynamic.sh),
        // so rpath-based loading is exactly what we want. We still emit the Swift runtime
        // link-search paths below, which is all the build actually needs.
        if swift_target_info.target.libraries_require_rpath {
            println!(
                "cargo:warning=swift target reports librariesRequireRPath; \
                 shipping as an @rpath framework, continuing."
            );
        }

        swift_target_info
            .paths
            .runtime_library_paths
            .iter()
            .for_each(|path| {
                println!("cargo:rustc-link-search=native={path}");
            });
    }

    fn get_sdk_root() -> String {
        let sdk = match env::var("TARGET").unwrap().as_str() {
            "aarch64-apple-ios" => "iphoneos",
            "x86_64-apple-ios" => "iphonesimulator",
            "aarch64-apple-ios-sim" => "iphonesimulator",
            "aarch64-apple-darwin" => "macosx",
            "x86_64-apple-darwin" => "macosx",
            unknown_target => panic!("Unsupported Arch for swift: {unknown_target}"), //
        };

        let sdk_root = Command::new("xcrun")
            .args(["--sdk", sdk, "--show-sdk-path"])
            .output()
            .unwrap()
            .stdout;

        let sdk_root = String::from_utf8(sdk_root).unwrap().trim().to_string();
        sdk_root
    }

    pub fn link_package(package_name: &str, package_root: &str) {
        let profile = env::var("PROFILE").unwrap();
        let target = get_target_triple();

        let sdk_root = get_sdk_root();
        if !Command::new("swift")
            .args([
                "build", "-c", &profile, "--sdk", &sdk_root, "--triple", &target,
            ])
            .current_dir(package_root)
            .status()
            .unwrap()
            .success()
        {
            panic!("Failed to compile swift package {package_name}");
        }

        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let swift_target_info = get_target_info();
        println!(
            "cargo:rustc-link-search=native={}/{}.build/{}/{}",
            manifest_dir, package_root, swift_target_info.target.unversioned_triple, profile
        );
        println!("cargo:rustc-link-lib=static={package_name}");
    }
}

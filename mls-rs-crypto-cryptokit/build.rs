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
    use std::{
        env,
        path::{Path, PathBuf},
        process::Command,
    };

    /// Needed because of the min system reqs for HPKE in CryptoKit.
    /// See https://developer.apple.com/documentation/cryptokit/hpke
    const MIN_IOS_DEPLOYMENT_TARGET: &str = "17.0";
    const MIN_OSX_DEPLOYMENT_TARGET: &str = "26.0";

    #[derive(Debug, Deserialize)]
    struct SwiftTargetInfo {
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
            .args(["-print-target-info", &format!("--target={}", &target)])
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
        if swift_target_info.target.libraries_require_rpath {
            panic!("Libraries require RPath! Change minimum MacOS value to fix.")
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
        let build_dir = format!("{manifest_dir}/{package_root}.build");

        // SwiftPM's output layout differs across toolchains: older `swift build`
        // emitted `.build/<unversioned-triple>/<profile>/`, while the Xcode 26 /
        // Swift 6.x build engine emits `.build/out/Products/<Config>/` (with a
        // `.build/<profile>` convenience symlink). Rather than hard-code either,
        // locate the archive `swift build` just produced and link against its dir.
        let lib_file = format!("lib{package_name}.a");
        let lib_dir = newest_lib_dir(Path::new(&build_dir), &lib_file).unwrap_or_else(|| {
            panic!("Could not find {lib_file} under {build_dir} after building {package_name}")
        });
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static={package_name}");
    }

    /// Recursively find the most recently modified `lib_file` under `root` and
    /// return the directory containing it. Symlinked directories are skipped so
    /// the same archive isn't discovered twice (the build engine symlinks
    /// `.build/<profile>` at the real product directory).
    fn newest_lib_dir(root: &Path, lib_file: &str) -> Option<PathBuf> {
        let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    if !path.is_symlink() {
                        stack.push(path);
                    }
                } else if entry.file_name() == std::ffi::OsStr::new(lib_file) {
                    let mtime = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH);
                    if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
                        best = Some((mtime, dir.clone()));
                    }
                }
            }
        }
        best.map(|(_, dir)| dir)
    }
}

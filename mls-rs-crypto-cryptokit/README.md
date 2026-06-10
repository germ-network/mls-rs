CryptoKit Crypto Provider
=========================

This crate implements a crypto provider for `mls-rs` based on Apple's CryptoKit
cryptographic library.  Because CryptoKit only exposes a Swift interface, we
include a Swift package `cryptokit-bridge` that implements a C interface that
can be called from Rust.

```
+-------------------------+
|          mls-rs         |
+------------+------------+
             |
             | Rust
             |
+------------+------------+
| mls-rs-crypto-cryptokit |
+------------+------------+
             |
             | C FFI
             |
+------------+------------+
|    cryptokit-bridge     |
+------------+------------+
             |
             | Swift
             |
+------------+------------+
|        CryptoKit        |
+-------------------------+
```

The Rust source files in this crate include only very basic testing, enough to
verify that the plumbing depicted above is working.  We rely on the crypto
provider tests in `mls-rs-core` for more thorough validation.

## Build requirements

The Swift bridge must be compiled with the Xcode 26 / Swift 6.2 toolchain because
`CryptoKit.MLKEM768` (FIPS 203) is only present in that SDK.  The package deployment
targets are iOS 16 / macOS 14; the ML-KEM entry points are individually guarded with
`@available(iOS 26.0, macOS 26.0, *)` so the library can be linked into apps that
support older OS versions while only activating ML-KEM at runtime on iOS 26+ / macOS 26+.

| Component | Value |
|-----------|-------|
| Swift toolchain (compile-time) | Swift 6.2 / Xcode 26 or later |
| macOS deployment target | 14.0 |
| iOS deployment target | 16.0 |
| ML-KEM runtime availability | macOS 26.0 / iOS 26.0 (`@available`-gated) |

The build script (`build.rs`) invokes `swift build` on `cryptokit-bridge/` at
compile time.  If the active toolchain does not include the macOS 26 SDK,
the build will fail because `CryptoKit.MLKEM768` is undefined.

### Feature flags

| Flag | Meaning |
|------|---------|
| `post-quantum` | Enables the ML-KEM-768 cipher suite backed by CryptoKit. Requires the Swift bridge to build successfully. |
| `awslc-interop` | Enables interoperability tests between this provider and `mls-rs-crypto-awslc`. Not required for production use; keep this gate disabled on CI builders that cannot build AWS-LC or the Swift bridge simultaneously. |

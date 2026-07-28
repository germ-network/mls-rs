// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;

#[cfg(any(test, feature = "external_client"))]
use alloc::vec;

use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[cfg(any(test, feature = "external_client"))]
use mls_rs_core::psk::PreSharedKeyStorage;

#[cfg(any(test, feature = "external_client"))]
use core::convert::Infallible;
use core::fmt::{self, Debug};

#[cfg(feature = "psk")]
use crate::{client::MlsError, CipherSuiteProvider};

#[cfg(feature = "psk")]
use mls_rs_core::error::IntoAnyError;

#[cfg(feature = "psk")]
pub(crate) mod resolver;
pub(crate) mod secret;

#[cfg(feature = "safe_extensions")]
use crate::group::component_operation::ComponentID;

pub use mls_rs_core::psk::{ExternalPskId, PreSharedKey};

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct PreSharedKeyID {
    pub key_id: JustPreSharedKeyID,
    pub psk_nonce: PskNonce,
}

impl PreSharedKeyID {
    #[cfg(feature = "psk")]
    pub(crate) fn new<P: CipherSuiteProvider>(
        key_id: JustPreSharedKeyID,
        cs: &P,
    ) -> Result<Self, MlsError> {
        Ok(Self {
            key_id,
            psk_nonce: PskNonce::random(cs)
                .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub(crate) enum JustPreSharedKeyID {
    External(ExternalPskId) = 1u8,
    Resumption(ResumptionPsk) = 2u8,
    #[cfg(feature = "safe_extensions")]
    Application(ApplicationPsk) = 3u8,
}

/// A pre-shared key identifier with `psk_type = application(3)` as defined in
/// draft-ietf-mls-extensions-08 Section 4.5:
///
/// ```text
/// struct {
///   PSKType psktype;
///   select (PreSharedKeyID.psktype) {
///     ...
///     case application:
///       ComponentID component_id;
///       opaque psk_id<V>;
///   };
///   opaque psk_nonce<V>;
/// } PreSharedKeyID;
/// ```
///
/// Application PSKs provide domain separation between pre-shared keys used by
/// the core MLS protocol and those used by application components, and
/// between different components.
#[cfg(feature = "safe_extensions")]
#[derive(Clone, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationPsk {
    pub(crate) component_id: ComponentID,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub(crate) psk_id: Vec<u8>,
}

#[cfg(feature = "safe_extensions")]
impl Debug for ApplicationPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationPsk")
            .field("component_id", &self.component_id)
            .field(
                "psk_id",
                &mls_rs_core::debug::pretty_bytes(&self.psk_id).named("psk_id"),
            )
            .finish()
    }
}

#[cfg(feature = "safe_extensions")]
impl ApplicationPsk {
    pub fn new(component_id: ComponentID, psk_id: Vec<u8>) -> Self {
        Self {
            component_id,
            psk_id,
        }
    }

    pub fn component_id(&self) -> ComponentID {
        self.component_id
    }

    pub fn psk_id(&self) -> &[u8] {
        &self.psk_id
    }

    /// The key under which the PSK value for this identifier is looked up in
    /// the group's [`PreSharedKeyStorage`](mls_rs_core::psk::PreSharedKeyStorage).
    ///
    /// The key is the MLS serialization of the `psktype` and the type-specific
    /// fields of the `PreSharedKeyID` (without the `psk_nonce`), i.e.
    /// `0x03 || component_id || psk_id<V>`, so it is component-bound and
    /// cannot collide with the storage key of a different application PSK.
    /// Every member must insert the PSK value under this key before
    /// committing or processing a commit that references this identifier.
    ///
    /// Note that these keys live in the same [`ExternalPskId`] namespace as
    /// the identifiers of genuine external PSKs; an application that also
    /// uses external PSKs should avoid ids that start with the byte `0x03`
    /// (or otherwise ensure they cannot equal a serialized application PSK
    /// identifier). The MLS key schedule itself stays domain-separated
    /// either way, since it binds the full typed `PreSharedKeyID`.
    pub fn storage_id(&self) -> Result<ExternalPskId, MlsError> {
        JustPreSharedKeyID::Application(self.clone())
            .mls_encode_to_vec()
            .map(ExternalPskId::new)
            .map_err(Into::into)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct PskGroupId(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub Vec<u8>,
);

impl Debug for PskGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        mls_rs_core::debug::pretty_bytes(&self.0)
            .named("PskGroupId")
            .fmt(f)
    }
}

#[derive(Clone, Eq, Hash, PartialEq, PartialOrd, Ord, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct PskNonce(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub Vec<u8>,
);

impl Debug for PskNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        mls_rs_core::debug::pretty_bytes(&self.0)
            .named("PskNonce")
            .fmt(f)
    }
}

#[cfg(feature = "psk")]
impl PskNonce {
    pub fn random<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> Result<Self, <P as CipherSuiteProvider>::Error> {
        Ok(Self(cipher_suite_provider.random_bytes_vec(
            cipher_suite_provider.kdf_extract_size(),
        )?))
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct ResumptionPsk {
    pub usage: ResumptionPSKUsage,
    pub psk_group_id: PskGroupId,
    pub psk_epoch: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub(crate) enum ResumptionPSKUsage {
    Application = 1u8,
    Reinit = 2u8,
    Branch = 3u8,
}

#[cfg(feature = "psk")]
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode)]
struct PSKLabel<'a> {
    id: &'a PreSharedKeyID,
    index: u16,
    count: u16,
}

#[cfg(any(test, feature = "external_client"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct AlwaysFoundPskStorage;

#[cfg(any(test, feature = "external_client"))]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl PreSharedKeyStorage for AlwaysFoundPskStorage {
    type Error = Infallible;

    async fn get(&self, _: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        Ok(Some(vec![].into()))
    }
}

#[cfg(feature = "psk")]
#[cfg(test)]
pub(crate) mod test_utils {
    use crate::crypto::test_utils::test_cipher_suite_provider;

    use super::PskNonce;
    use mls_rs_core::crypto::CipherSuite;

    #[cfg(not(mls_build_async))]
    use mls_rs_core::{crypto::CipherSuiteProvider, psk::ExternalPskId};

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[cfg(not(mls_build_async))]
    pub(crate) fn make_external_psk_id<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> ExternalPskId {
        ExternalPskId::new(
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .unwrap(),
        )
    }

    pub(crate) fn make_nonce(cipher_suite: CipherSuite) -> PskNonce {
        PskNonce::random(&test_cipher_suite_provider(cipher_suite)).unwrap()
    }
}

#[cfg(feature = "psk")]
#[cfg(test)]
mod tests {
    use crate::crypto::test_utils::TestCryptoProvider;
    use core::iter;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::test_utils::make_nonce;

    #[test]
    fn random_generation_of_nonces_is_random() {
        let good = TestCryptoProvider::all_supported_cipher_suites()
            .into_iter()
            .all(|cipher_suite| {
                let nonce = make_nonce(cipher_suite);
                iter::repeat_with(|| make_nonce(cipher_suite))
                    .take(1000)
                    .all(|other| other != nonce)
            });

        assert!(good);
    }

    mod codec {
        use alloc::vec;
        use alloc::vec::Vec;
        use mls_rs_codec::{MlsDecode, MlsEncode};
        use mls_rs_core::psk::ExternalPskId;

        use crate::psk::{
            JustPreSharedKeyID, PreSharedKeyID, PskGroupId, PskNonce, ResumptionPSKUsage,
            ResumptionPsk,
        };

        #[cfg(feature = "safe_extensions")]
        use crate::psk::ApplicationPsk;

        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        fn round_trip(id: &PreSharedKeyID) -> Vec<u8> {
            let encoded = id.mls_encode_to_vec().unwrap();
            let decoded = PreSharedKeyID::mls_decode(&mut &*encoded).unwrap();
            assert_eq!(id, &decoded);
            encoded
        }

        // The external and resumption variants of PreSharedKeyID must stay
        // byte-identical to RFC 9420 Section 8.4.
        #[test]
        fn external_psk_id_wire_format() {
            let id = PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId::new(vec![7, 8])),
                psk_nonce: PskNonce(vec![0xAA, 0xBB, 0xCC]),
            };

            let expected = [1u8, 2, 7, 8, 3, 0xAA, 0xBB, 0xCC];

            assert_eq!(round_trip(&id), expected);
        }

        #[test]
        fn resumption_psk_id_wire_format() {
            let id = PreSharedKeyID {
                key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage: ResumptionPSKUsage::Application,
                    psk_group_id: PskGroupId(vec![9]),
                    psk_epoch: 5,
                }),
                psk_nonce: PskNonce(vec![0xAA, 0xBB]),
            };

            let expected = [1u8 + 1, 1, 1, 9, 0, 0, 0, 0, 0, 0, 0, 5, 2, 0xAA, 0xBB];

            assert_eq!(round_trip(&id), expected);
        }

        // psk_type = application(3) from draft-ietf-mls-extensions-08
        // Section 4.5, with the uint32 ComponentID of that draft revision.
        #[cfg(feature = "safe_extensions")]
        #[test]
        fn application_psk_id_wire_format() {
            let id = PreSharedKeyID {
                key_id: JustPreSharedKeyID::Application(ApplicationPsk::new(
                    0x01020304,
                    vec![7, 8, 9],
                )),
                psk_nonce: PskNonce(vec![0xAA, 0xBB]),
            };

            let expected = [3u8, 1, 2, 3, 4, 3, 7, 8, 9, 2, 0xAA, 0xBB];

            assert_eq!(round_trip(&id), expected);
        }

        // The storage key is the serialized psktype and type-specific fields,
        // without the nonce.
        #[cfg(feature = "safe_extensions")]
        #[test]
        fn application_psk_storage_id() {
            let psk = ApplicationPsk::new(0x01020304, vec![7, 8, 9]);

            let expected = [3u8, 1, 2, 3, 4, 3, 7, 8, 9];

            assert_eq!(
                psk.storage_id().unwrap(),
                ExternalPskId::new(expected.to_vec())
            );
        }
    }
}

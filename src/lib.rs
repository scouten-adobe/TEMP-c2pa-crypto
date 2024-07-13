// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#![deny(warnings)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg, doc_cfg_hide))]

//! This library supports reading, creating and embedding C2PA data
//! with a variety of asset types.
//!
//! We have a new experimental Builder/Reader API that will eventually replace
//! the existing methods of reading and writing C2PA data.
//! The new API focuses on stream support and can do more with fewer methods.
//! It will be supported in all language bindings and build environments.

/// The internal name of the C2PA SDK
pub const NAME: &str = "c2pa-crypto";

/// The version of this C2PA SDK
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Public modules
pub mod cose_sign;
#[cfg(feature = "openssl_sign")]
pub mod create_signer;
pub(crate) mod settings;
pub mod validation_status;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Public exports
pub use error::{Error, Result};
pub use hash_utils::{hash_stream_by_alg, HashRange};
pub use signer::{AsyncSigner, RemoteSigner, Signer};
pub use signing_alg::SigningAlg;
pub use utils::mime::format_from_path;

// Internal modules
#[allow(dead_code, clippy::enum_variant_names)]
pub(crate) mod asn1;
pub mod cose_validator; // [scouten 2024-06-27]: Hacking to make public.
pub(crate) mod error;
pub(crate) mod hashed_uri;
pub(crate) mod ocsp_utils;
#[cfg(feature = "openssl")]
pub mod openssl; // [scouten 2024-06-27]: Hacking to make public.
pub(crate) mod salt;
pub(crate) mod signer;
pub(crate) mod signing_alg;
pub mod status_tracker; // [scouten 2024-06-27]: Hacking to make this public.
                        // pub(crate) mod store;
pub(crate) mod time_stamp;
pub mod trust_handler; // [scouten 2024-06-27]: Hacking to make public.
pub(crate) mod utils;
pub(crate) use utils::hash_utils;
pub mod validator; // [scouten 2024-06-27]: Hacking to make public.

pub use cose_validator::{VerifyOcspFetch, VerifyTrustChain};

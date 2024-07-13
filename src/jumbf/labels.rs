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

#![deny(missing_docs)]

//! Labels for JUMBF boxes as defined in C2PA 1.0 Specification.
//!
//! See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.

/// Label for the C2PA manifest store.
///
/// This value should be used when possible, since it may contain a version
/// suffix when needed to support a future version of the spec.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const MANIFEST_STORE: &str = "c2pa";

/// Label for the C2PA assertion store box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const ASSERTIONS: &str = "c2pa.assertions";

/// Label for the C2PA claim box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const CLAIM: &str = "c2pa.claim";

/// Label for the C2PA claim signature box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const SIGNATURE: &str = "c2pa.signature";

/// Label for the credentials store box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_credential_storage>.
pub const CREDENTIALS: &str = "c2pa.credentials";

/// Label for the DataBox store box.
///
/// See <https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_data_storage>.
pub const DATABOXES: &str = "c2pa.databoxes";

// Split off JUMBF prefix.
pub(crate) fn to_normalized_uri(uri: &str) -> String {
    let uri_parts: Vec<&str> = uri.split('=').collect();

    let output = if uri_parts.len() == 1 {
        uri_parts[0].to_string()
    } else {
        uri_parts[1].to_string()
    };

    // Add leading "/" if needed.
    let mut manifest_store_part = MANIFEST_STORE.to_string();
    manifest_store_part.push('/');

    if !output.is_empty() && output.starts_with(&manifest_store_part) {
        format!("{}{}", "/", output)
    } else {
        output
    }
}

// Extract an assertion label from a JUMBF URI.
#[allow(dead_code)]
pub(crate) fn assertion_label_from_uri(uri: &str) -> Option<String> {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();
    if parts.len() > 4 && parts[1] == MANIFEST_STORE && parts[3] == ASSERTIONS {
        Some(parts[4].to_string())
    } else if parts[0] == ASSERTIONS {
        Some(parts[1].to_string())
    } else {
        None
    }
}

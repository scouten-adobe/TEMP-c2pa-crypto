// Copyright 2023 Adobe. All rights reserved.
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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
/// A reference to a resource to be used in JSON serialization.
pub struct ResourceRef {
    /// The mime type of the referenced resource.
    pub format: String,

    /// A URI that identifies the resource as referenced from the manifest.
    ///
    /// This may be a JUMBF URI, a file path, a URL or any other string.
    /// Relative JUMBF URIs will be resolved with the manifest label.
    /// Relative file paths will be resolved with the base path if provided.
    pub identifier: String,

    /// The algorithm used to hash the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The hash of the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Resource store to contain binary objects referenced from JSON serializable
/// structures
#[derive(Debug, Serialize)]
pub struct ResourceStore {
    resources: HashMap<String, Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

impl ResourceStore {
    /// Create a new resource reference.
    pub fn new() -> Self {
        ResourceStore {
            resources: HashMap::new(),
            label: None,
        }
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        ResourceStore::new()
    }
}

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
use serde_json::Value;

/// Description of the claim generator, or the software used in generating the
/// claim.
///
/// This structure is also used for actions softwareAgent
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimGeneratorInfo {
    /// A human readable string naming the claim_generator
    pub name: String,
    /// A human readable string of the product's version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    // Any other values that are not part of the standard
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

impl Default for ClaimGeneratorInfo {
    fn default() -> Self {
        Self {
            name: crate::NAME.to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            other: HashMap::new(),
        }
    }
}

impl ClaimGeneratorInfo {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            version: None,
            other: HashMap::new(),
        }
    }

    /// Sets the version of the generator.
    pub fn set_version<S: Into<String>>(&mut self, version: S) -> &mut Self {
        self.version = Some(version.into());
        self
    }

    /// Adds a new key/value pair to the generator info.
    pub fn insert<K, V>(&mut self, key: K, value: V) -> &Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.other.insert(key.into(), value.into());
        self
    }

    /// Gets additional values by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}

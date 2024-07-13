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

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Assertion data as binary CBOR or JSON depending upon
/// the Assertion type (see spec).
/// For JSON assertions the data is a JSON string and a Vec of u8 values for
/// binary data and JSON data to be CBOR encoded.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone)]
pub enum AssertionData {
    Json(String),          // json encoded data
    Binary(Vec<u8>),       // binary data
    Cbor(Vec<u8>),         // binary cbor encoded data
    Uuid(String, Vec<u8>), // user defined content (uuid, data)
}

impl fmt::Debug for AssertionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Json(s) => write!(f, "{s:?}"), // json encoded data
            Self::Binary(_) => write!(f, "<omitted>"),
            Self::Uuid(uuid, _) => {
                write!(f, "uuid: {uuid}, <omitted>")
            }
            Self::Cbor(s) => {
                let buf: Vec<u8> = Vec::new();
                let mut from = serde_cbor::Deserializer::from_slice(s);
                let mut to = serde_json::Serializer::pretty(buf);

                serde_transcode::transcode(&mut from, &mut to).map_err(|_err| fmt::Error)?;
                let buf2 = to.into_inner();

                let decoded: Value = serde_json::from_slice(&buf2).map_err(|_err| fmt::Error)?;

                write!(f, "{:?}", decoded.to_string())
            }
        }
    }
}

/// Internal Assertion structure
///
/// Each assertion type will
/// contain its AssertionData.  For the User Assertion type we
/// allow a String to set the label. The AssertionData contains
/// the data payload for the assertion and the version number for its schema (if
/// supported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    label: String,
    version: Option<usize>,
    data: AssertionData,
    content_type: String,
}

impl Assertion {}

#[allow(dead_code)] // TODO: temp, see #498
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct JsonAssertionData {
    label: String,
    data: Value,
    is_cbor: bool,
}

/// This error type is returned when an assertion can not be decoded.
#[non_exhaustive]
pub struct AssertionDecodeError {
    pub label: String,
    pub version: Option<usize>,
    pub content_type: String,
    pub source: AssertionDecodeErrorCause,
}

impl AssertionDecodeError {
    fn fmt_internal(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "could not decode assertion {} (version {}, content type {}): {}",
            self.label,
            self.version
                .map_or("(no version)".to_string(), |v| v.to_string()),
            self.content_type,
            self.source
        )
    }
}

impl std::fmt::Debug for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl std::fmt::Display for AssertionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(f)
    }
}

impl std::error::Error for AssertionDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// This error type is used inside `AssertionDecodeError` to describe the
/// root cause for the decoding error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AssertionDecodeErrorCause {
    /// The assertion had an unexpected data type.
    #[error("the assertion had an unexpected data type: expected {expected}, found {found}")]
    UnexpectedDataType { expected: String, found: String },

    /// The assertion has a version that is newer that this toolkit can
    /// understand.
    #[error("the assertion version is too new: expected no later than {max}, found {found}")]
    AssertionTooNew { max: usize, found: usize },

    /// Binary data could not be interpreted as UTF-8.
    #[error("binary data could not be interpreted as UTF-8")]
    BinaryDataNotUtf8,

    /// Assertion data did not match hash link.
    #[error("the assertion data did not match the hash embedded in the link")]
    AssertionDataIncorrect,

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),
}

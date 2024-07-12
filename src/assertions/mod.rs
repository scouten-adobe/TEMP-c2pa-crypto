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

//! Assertion helpers to build, validate, and parse assertions.

mod box_hash;
pub(crate) use box_hash::{BoxMap, C2PA_BOXHASH};

// mod data_hash;
// pub use data_hash::DataHash;

pub mod labels;

mod metadata;
#[allow(unused_imports)] // TEMPORARY while working on actions
pub use metadata::{Actor, AssetType, DataBox, Metadata, ReviewRating};

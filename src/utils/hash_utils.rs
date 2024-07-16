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

// multihash versions
use multihash::{Sha1, Sha2_256};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

/// Compare two byte vectors return true if match, false otherwise
pub(crate) fn vec_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) &&  // zip stops at the shortest
     va.iter()
       .zip(vb)
       .all(|(a,b)| a == b)
}

/// Return a Sha256 hash of array of bytes
#[allow(dead_code)]
pub(crate) fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mh = Sha2_256::digest(data);
    let digest = mh.digest();

    digest.to_vec()
}

pub(crate) fn hash_sha1(data: &[u8]) -> Vec<u8> {
    let mh = Sha1::digest(data);
    let digest = mh.digest();
    digest.to_vec()
}

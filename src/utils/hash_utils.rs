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
use multihash::{Multihash, Sha1, Sha2_256, Sha2_512, Sha3_256, Sha3_384, Sha3_512};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

/// Compare two byte vectors return true if match, false otherwise
pub(crate) fn vec_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) &&  // zip stops at the shortest
     va.iter()
       .zip(vb)
       .all(|(a,b)| a == b)
}

/// Generate hash of type hash_type for supplied data array.  The
/// hash_type are those specified in the multihash specification.  Currently
/// we only support Sha2-256/512 or Sha2-256/512.
/// Returns hash or None if incompatible type
pub(crate) fn hash_by_type(hash_type: u8, data: &[u8]) -> Option<Multihash> {
    match hash_type {
        0x12 => Some(Sha2_256::digest(data)),
        0x13 => Some(Sha2_512::digest(data)),
        0x14 => Some(Sha3_512::digest(data)),
        0x15 => Some(Sha3_384::digest(data)),
        0x16 => Some(Sha3_256::digest(data)),
        _ => None,
    }
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

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
use multibase::{decode, encode};
use multihash::{wrap, Code, Multihash, Sha1, Sha2_256, Sha2_512, Sha3_256, Sha3_384, Sha3_512};
use serde::{Deserialize, Serialize};
// direct sha functions
use sha2::{Digest, Sha256, Sha384, Sha512};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct HashRange {
    start: usize,
    length: usize,
}

impl HashRange {
    pub(crate) fn new(start: usize, length: usize) -> Self {
        HashRange { start, length }
    }

    /// update the start value
    #[allow(dead_code)]
    pub(crate) fn set_start(&mut self, start: usize) {
        self.start = start;
    }

    /// return start as usize
    pub(crate) fn start(&self) -> usize {
        self.start
    }

    /// return length as usize
    pub(crate) fn length(&self) -> usize {
        self.length
    }

    pub(crate) fn set_length(&mut self, length: usize) {
        self.length = length;
    }
}

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

#[derive(Clone)]
pub(crate) enum Hasher {
    SHA256(Sha256),
    SHA384(Sha384),
    SHA512(Sha512),
}

impl Hasher {
    // update hash value with new data
    pub(crate) fn update(&mut self, data: &[u8]) {
        use Hasher::*;
        // update the hash
        match self {
            SHA256(ref mut d) => d.update(data),
            SHA384(ref mut d) => d.update(data),
            SHA512(ref mut d) => d.update(data),
        }
    }

    // consume hasher and return the final digest
    pub(crate) fn finalize(hasher_enum: Hasher) -> Vec<u8> {
        use Hasher::*;
        // return the hash
        match hasher_enum {
            SHA256(d) => d.finalize().to_vec(),
            SHA384(d) => d.finalize().to_vec(),
            SHA512(d) => d.finalize().to_vec(),
        }
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

/// Verify muiltihash against input data.  True if match,
/// false if no match or unsupported.  The hash value should be
/// be multibase encoded string.
pub(crate) fn verify_hash(hash: &str, data: &[u8]) -> bool {
    match decode(hash) {
        Ok((_code, mh)) => {
            if mh.len() < 2 {
                return false;
            }

            // multihash lead bytes
            let hash_type = mh[0]; // hash type
            let _hash_len = mh[1]; // hash data length

            // hash with the same algorithm as target
            if let Some(data_hash) = hash_by_type(hash_type, data) {
                vec_compare(data_hash.digest(), &mh.as_slice()[2..])
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Return the hash of data in the same hash format in_hash
pub(crate) fn hash_as_source(in_hash: &str, data: &[u8]) -> Option<String> {
    match decode(in_hash) {
        Ok((code, mh)) => {
            if mh.len() < 2 {
                return None;
            }

            // multihash lead bytes
            let hash_type = mh[0]; // hash type

            // hash with the same algorithm as target
            match hash_by_type(hash_type, data) {
                Some(hash) => {
                    let digest = hash.digest();

                    let wrapped = match hash_type {
                        0x12 => wrap(Code::Sha2_256, digest),
                        0x13 => wrap(Code::Sha2_512, digest),
                        0x14 => wrap(Code::Sha3_512, digest),
                        0x15 => wrap(Code::Sha3_384, digest),
                        0x16 => wrap(Code::Sha3_256, digest),
                        _ => return None,
                    };

                    // Return encoded hash.
                    Some(encode(code, wrapped.as_bytes()))
                }
                None => None,
            }
        }
        Err(_) => None,
    }
}

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

use std::io::{Cursor, Read, Seek, SeekFrom};

use multibase::{decode, encode};
use multihash::{wrap, Code, Multihash, Sha1, Sha2_256, Sha2_512, Sha3_256, Sha3_384, Sha3_512};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::Result;

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

pub(crate) fn hash_by_alg(alg: &str, data: &[u8]) -> Vec<u8> {
    hash_stream_internal(alg, data).unwrap_or_default()
}

fn hash_stream_internal(alg: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut data = Cursor::new(data);

    use Hasher::*;
    let mut hasher_enum = match alg {
        "sha256" => SHA256(Sha256::new()),
        "sha384" => SHA384(Sha384::new()),
        "sha512" => SHA512(Sha512::new()),
        _ => {
            warn!(
                "Unsupported hashing algorithm: {}, substituting sha256",
                alg
            );
            SHA256(Sha256::new())
        }
    };

    let mut data_len = data.seek(SeekFrom::End(0))?;
    data.rewind()?;

    while data_len > 0 {
        let mut chunk = vec![0u8; std::cmp::min(data_len as usize, MAX_HASH_BUF)];
        data.read_exact(&mut chunk)?;
        hasher_enum.update(&chunk);

        data_len -= chunk.len() as u64;
    }

    Ok(Hasher::finalize(hasher_enum))
}

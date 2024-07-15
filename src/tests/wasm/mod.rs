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

mod webcrypto_validator;
mod webpki_trust_handler;

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn capture_coverage() {
    const BINARY_NAME: &str = env!("CARGO_PKG_NAME");
    let mut coverage = vec![];
    wasmcov::minicov::capture_coverage(&mut coverage).unwrap();
    // Invoke a function to preserve the coverage data or use `println!` for
    // debugging.
}

#[test]
fn add_coverage() {
    capture_coverage();
}

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

use std::io::Cursor;

use crate::{
    openssl::{
        temp_signer::{self},
        verify_trust, OpenSSLTrustHandlerConfig,
    },
    trust_handler::TrustHandlerConfig,
    Signer, SigningAlg,
};

#[test]
fn test_trust_store() {
    let cert_dir = crate::utils::test::fixture_path("test_certs");

    let mut th = OpenSSLTrustHandlerConfig::new();
    th.clear();

    th.load_default_trust().unwrap();

    // test all the certs
    let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
    let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
    let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
    let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
    let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
    let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
    let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

    let ps256_certs = ps256.certs().unwrap();
    let ps384_certs = ps384.certs().unwrap();
    let ps512_certs = ps512.certs().unwrap();
    let es256_certs = es256.certs().unwrap();
    let es384_certs = es384.certs().unwrap();
    let es512_certs = es512.certs().unwrap();
    let ed25519_certs = ed25519.certs().unwrap();

    assert!(verify_trust(&th, &ps256_certs[1..], &ps256_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps384_certs[1..], &ps384_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps512_certs[1..], &ps512_certs[0]).unwrap());
    assert!(verify_trust(&th, &es256_certs[1..], &es256_certs[0]).unwrap());
    assert!(verify_trust(&th, &es384_certs[1..], &es384_certs[0]).unwrap());
    assert!(verify_trust(&th, &es512_certs[1..], &es512_certs[0]).unwrap());
    assert!(verify_trust(&th, &ed25519_certs[1..], &ed25519_certs[0]).unwrap());
}

#[test]
fn test_broken_trust_chain() {
    let cert_dir = crate::utils::test::fixture_path("test_certs");
    let ta = include_bytes!("../fixtures/test_certs/test_cert_root_bundle.pem");

    let mut th = OpenSSLTrustHandlerConfig::new();
    th.clear();

    // load the trust store
    let mut reader = Cursor::new(ta);
    th.load_trust_anchors_from_data(&mut reader).unwrap();

    // test all the certs
    let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
    let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
    let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
    let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
    let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
    let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
    let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

    let ps256_certs = ps256.certs().unwrap();
    let ps384_certs = ps384.certs().unwrap();
    let ps512_certs = ps512.certs().unwrap();
    let es256_certs = es256.certs().unwrap();
    let es384_certs = es384.certs().unwrap();
    let es512_certs = es512.certs().unwrap();
    let ed25519_certs = ed25519.certs().unwrap();

    assert!(!verify_trust(&th, &ps256_certs[2..], &ps256_certs[0]).unwrap());
    assert!(!verify_trust(&th, &ps384_certs[2..], &ps384_certs[0]).unwrap());
    assert!(!verify_trust(&th, &ps512_certs[2..], &ps512_certs[0]).unwrap());
    assert!(!verify_trust(&th, &es256_certs[2..], &es256_certs[0]).unwrap());
    assert!(!verify_trust(&th, &es384_certs[2..], &es384_certs[0]).unwrap());
    assert!(!verify_trust(&th, &es512_certs[2..], &es512_certs[0]).unwrap());
    assert!(!verify_trust(&th, &ed25519_certs[2..], &ed25519_certs[0]).unwrap());
}

#[test]
fn test_allowed_list() {
    let cert_dir = crate::utils::test::fixture_path("test_certs");

    let mut th = OpenSSLTrustHandlerConfig::new();
    th.clear();

    let mut allowed_list_path = crate::utils::test::fixture_path("allow_list");
    allowed_list_path = allowed_list_path.join("allowed_list.pem");

    let mut allowed_list = std::fs::File::open(&allowed_list_path).unwrap();

    th.load_allowed_list(&mut allowed_list).unwrap();

    // test all the certs
    let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
    let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
    let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
    let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
    let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
    let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
    let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

    let ps256_certs = ps256.certs().unwrap();
    let ps384_certs = ps384.certs().unwrap();
    let ps512_certs = ps512.certs().unwrap();
    let es256_certs = es256.certs().unwrap();
    let es384_certs = es384.certs().unwrap();
    let es512_certs = es512.certs().unwrap();
    let ed25519_certs = ed25519.certs().unwrap();

    assert!(verify_trust(&th, &ps256_certs[1..], &ps256_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps384_certs[1..], &ps384_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps512_certs[1..], &ps512_certs[0]).unwrap());
    assert!(verify_trust(&th, &es256_certs[1..], &es256_certs[0]).unwrap());
    assert!(verify_trust(&th, &es384_certs[1..], &es384_certs[0]).unwrap());
    assert!(verify_trust(&th, &es512_certs[1..], &es512_certs[0]).unwrap());
    assert!(verify_trust(&th, &ed25519_certs[1..], &ed25519_certs[0]).unwrap());
}

#[test]
fn test_allowed_list_hashes() {
    let cert_dir = crate::utils::test::fixture_path("test_certs");

    let mut th = OpenSSLTrustHandlerConfig::new();
    th.clear();

    let mut allowed_list_path = crate::utils::test::fixture_path("allow_list");
    allowed_list_path = allowed_list_path.join("allowed_list.hash");

    let mut allowed_list = std::fs::File::open(&allowed_list_path).unwrap();

    th.load_allowed_list(&mut allowed_list).unwrap();

    // test all the certs
    let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
    let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
    let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
    let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
    let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
    let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
    let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

    let ps256_certs = ps256.certs().unwrap();
    let ps384_certs = ps384.certs().unwrap();
    let ps512_certs = ps512.certs().unwrap();
    let es256_certs = es256.certs().unwrap();
    let es384_certs = es384.certs().unwrap();
    let es512_certs = es512.certs().unwrap();
    let ed25519_certs = ed25519.certs().unwrap();

    assert!(verify_trust(&th, &ps256_certs[1..], &ps256_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps384_certs[1..], &ps384_certs[0]).unwrap());
    assert!(verify_trust(&th, &ps512_certs[1..], &ps512_certs[0]).unwrap());
    assert!(verify_trust(&th, &es256_certs[1..], &es256_certs[0]).unwrap());
    assert!(verify_trust(&th, &es384_certs[1..], &es384_certs[0]).unwrap());
    assert!(verify_trust(&th, &es512_certs[1..], &es512_certs[0]).unwrap());
    assert!(verify_trust(&th, &ed25519_certs[1..], &ed25519_certs[0]).unwrap());
}

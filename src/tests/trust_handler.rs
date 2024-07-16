// Copyright 2024 Adobe. All rights reserved.
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

mod load_eku_configuration {
    use std::io::Cursor;

    use crate::trust_handler;

    #[test]
    fn openssl_store_cfg() {
        let oids = include_bytes!("../openssl/store.cfg");
        let mut cursor = Cursor::new(oids);

        let ekus = trust_handler::load_eku_configuration(&mut cursor).unwrap();

        let mut eku_iter = ekus.iter();

        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.36");

        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.8");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.9");
        assert_eq!(
            eku_iter.next().unwrap().as_str(),
            "1.3.6.1.4.1.311.76.59.1.9"
        );
        assert!(eku_iter.next().is_none());
    }

    #[test]
    fn skips_non_oids() {
        let oids = "1.3.6.1.5.5.7.3.4\nbogus\n1.3.6.1.5.5.7.3.36";
        let mut cursor = Cursor::new(oids);

        let ekus = trust_handler::load_eku_configuration(&mut cursor).unwrap();

        let mut eku_iter = ekus.iter();
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(eku_iter.next().unwrap().as_str(), "1.3.6.1.5.5.7.3.36");
        assert!(eku_iter.next().is_none());
    }
}

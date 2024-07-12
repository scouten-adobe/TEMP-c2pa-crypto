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

use std::{collections::HashMap, io::Cursor};

use lazy_static::lazy_static;

use crate::{
    asset_handlers::{c2pa_io::C2paIO, jpeg_io::JpegIO},
    asset_io::{AssetIO, CAIRead, CAIReader, CAIWriter},
    error::{Error, Result},
};

// initialize asset handlers
lazy_static! {
    static ref ASSET_HANDLERS: HashMap<String, Box<dyn AssetIO>> = {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
        ];

        let mut handler_map = HashMap::new();

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                handler_map.insert(supported_type.to_string(), h.get_handler(supported_type));
            }
        }

        handler_map
    };
}

// initialize streaming write handlers
lazy_static! {
    static ref CAI_WRITERS: HashMap<String, Box<dyn CAIWriter>> = {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
        ];
        let mut handler_map = HashMap::new();

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                if let Some(writer) = h.get_writer(supported_type) { // get streaming writer if supported
                    handler_map.insert(supported_type.to_string(), writer);
                }
            }
        }

        handler_map
    };
}

/// Return jumbf block from in memory asset
#[allow(dead_code)]
pub fn load_jumbf_from_memory(asset_type: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut buf_reader = Cursor::new(data);

    load_jumbf_from_stream(asset_type, &mut buf_reader)
}

/// Return jumbf block from stream asset
pub fn load_jumbf_from_stream(asset_type: &str, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let cai_block = match get_cailoader_handler(asset_type) {
        Some(asset_handler) => asset_handler.read_cai(input_stream)?,
        None => return Err(Error::UnsupportedType),
    };
    if cai_block.is_empty() {
        return Err(Error::JumbfNotFound);
    }
    Ok(cai_block)
}

pub(crate) fn get_cailoader_handler(asset_type: &str) -> Option<&dyn CAIReader> {
    let asset_type = asset_type.to_lowercase();

    ASSET_HANDLERS.get(&asset_type).map(|h| h.get_reader())
}

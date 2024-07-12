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

use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek},
};

use lazy_static::lazy_static;

use crate::{
    asset_handlers::{c2pa_io::C2paIO, jpeg_io::JpegIO},
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
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
/// writes the jumbf data in store_bytes
/// reads an asset of asset_type from reader, adds jumbf data and then writes to
/// writer
pub fn save_jumbf_to_stream(
    asset_type: &str,
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
    store_bytes: &[u8],
) -> Result<()> {
    match get_caiwriter_handler(asset_type) {
        Some(asset_handler) => asset_handler.write_cai(input_stream, output_stream, store_bytes),
        None => Err(Error::UnsupportedType),
    }
}

pub(crate) fn get_assetio_handler(ext: &str) -> Option<&dyn AssetIO> {
    let ext = ext.to_lowercase();

    ASSET_HANDLERS.get(&ext).map(|h| h.as_ref())
}

pub(crate) fn get_cailoader_handler(asset_type: &str) -> Option<&dyn CAIReader> {
    let asset_type = asset_type.to_lowercase();

    ASSET_HANDLERS.get(&asset_type).map(|h| h.get_reader())
}

pub(crate) fn get_caiwriter_handler(asset_type: &str) -> Option<&dyn CAIWriter> {
    let asset_type = asset_type.to_lowercase();

    CAI_WRITERS.get(&asset_type).map(|h| h.as_ref())
}

struct CAIReadAdapter<R> {
    pub reader: R,
}

impl<R> Read for CAIReadAdapter<R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R> Seek for CAIReadAdapter<R>
where
    R: Read + Seek,
{
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)
    }
}

pub(crate) fn object_locations_from_stream<R>(
    format: &str,
    stream: &mut R,
) -> Result<Vec<HashObjectPositions>>
where
    R: Read + Seek + Send + ?Sized,
{
    let mut reader = CAIReadAdapter { reader: stream };

    match get_caiwriter_handler(format) {
        Some(handler) => handler.get_object_locations_from_stream(&mut reader),
        _ => Err(Error::UnsupportedType),
    }
}

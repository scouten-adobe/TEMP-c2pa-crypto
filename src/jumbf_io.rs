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
    asset_handlers::{c2pa_io::C2paIO, jpeg_io::JpegIO, riff_io::RiffIO, tiff_io::TiffIO},
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    error::{Error, Result},
};

// initialize asset handlers
lazy_static! {
    static ref ASSET_HANDLERS: HashMap<String, Box<dyn AssetIO>> = {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
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
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
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

/// writes the jumbf data in store_bytes into an asset in data and returns the
/// newly created asset
pub fn save_jumbf_to_memory(asset_type: &str, data: &[u8], store_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut input_stream = Cursor::new(data);
    let output_vec: Vec<u8> = Vec::with_capacity(data.len() + store_bytes.len() + 1024);
    let mut output_stream = Cursor::new(output_vec);

    save_jumbf_to_stream(
        asset_type,
        &mut input_stream,
        &mut output_stream,
        store_bytes,
    )?;
    Ok(output_stream.into_inner())
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

/// returns a list of supported file extensions and mime types
pub fn get_supported_types() -> Vec<String> {
    ASSET_HANDLERS.keys().map(|k| k.to_owned()).collect()
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Seek;

    use super::*;
    use crate::{
        asset_io::RemoteRefEmbedType,
        utils::test::{create_test_store, temp_signer},
    };

    #[test]
    fn test_get_assetio() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_assetio_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_get_reader() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_cailoader_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_get_writer() {
        let handlers: Vec<Box<dyn AssetIO>> =
            vec![Box::new(JpegIO::new("")), Box::new(RiffIO::new(""))];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_caiwriter_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_get_supported_list() {
        let supported = get_supported_types();

        assert!(supported.iter().any(|s| s == "jpg"));
        assert!(supported.iter().any(|s| s == "jpeg"));
        assert!(supported.iter().any(|s| s == "avi"));
        assert!(supported.iter().any(|s| s == "webp"));
        assert!(supported.iter().any(|s| s == "wav"));
        assert!(supported.iter().any(|s| s == "tif"));
        assert!(supported.iter().any(|s| s == "tiff"));
        assert!(supported.iter().any(|s| s == "dng"));
    }

    fn test_jumbf(asset_type: &str, reader: &mut dyn CAIRead) {
        let mut writer = Cursor::new(Vec::new());
        let store = create_test_store().unwrap();
        let signer = temp_signer();
        let jumbf = store.to_jumbf(&*signer).unwrap();
        save_jumbf_to_stream(asset_type, reader, &mut writer, &jumbf).unwrap();
        writer.set_position(0);
        let jumbf2 = load_jumbf_from_stream(asset_type, &mut writer).unwrap();
        assert_eq!(jumbf, jumbf2);

        // test removing cai store
        writer.set_position(0);
        let handler = get_caiwriter_handler(asset_type).unwrap();
        let mut removed = Cursor::new(Vec::new());
        handler
            .remove_cai_store_from_stream(&mut writer, &mut removed)
            .unwrap();
        removed.set_position(0);
        let result = load_jumbf_from_stream(asset_type, &mut removed);
        if (asset_type != "wav") && (asset_type != "webp") {
            assert!(matches!(&result.err().unwrap(), Error::JumbfNotFound));
        }
        //assert!(matches!(result.err().unwrap(), Error::JumbfNotFound));
    }

    fn test_remote_ref(asset_type: &str, reader: &mut dyn CAIRead) {
        const REMOTE_URL: &str = "https://example.com/remote_manifest";
        let asset_handler = get_assetio_handler(asset_type).unwrap();
        let remote_ref_writer = asset_handler.remote_ref_writer_ref().unwrap();
        let mut writer = Cursor::new(Vec::new());
        let embed_ref = RemoteRefEmbedType::Xmp(REMOTE_URL.to_string());
        remote_ref_writer
            .embed_reference_to_stream(reader, &mut writer, embed_ref)
            .unwrap();
        writer.set_position(0);
        let xmp = asset_handler.get_reader().read_xmp(&mut writer).unwrap();
        let loaded = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();
        assert_eq!(loaded, REMOTE_URL.to_string());
    }

    #[test]
    fn test_streams_jpeg() {
        let mut reader = std::fs::File::open("tests/fixtures/IMG_0003.jpg").unwrap();
        test_jumbf("jpeg", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("jpeg", &mut reader);
    }

    #[test]
    fn test_streams_webp() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.webp").unwrap();
        test_jumbf("webp", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("webp", &mut reader);
    }

    #[test]
    fn test_streams_wav() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.wav").unwrap();
        test_jumbf("wav", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("wav", &mut reader);
    }

    #[test]
    fn test_streams_tiff() {
        let mut reader = std::fs::File::open("tests/fixtures/TUSCANY.TIF").unwrap();
        test_jumbf("tiff", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("tiff", &mut reader);
    }

    #[test]
    fn test_streams_c2pa() {
        let mut reader = std::fs::File::open("tests/fixtures/cloud_manifest.c2pa").unwrap();
        test_jumbf("c2pa", &mut reader);
    }
}

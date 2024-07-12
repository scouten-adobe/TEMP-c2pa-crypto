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

use std::{fs::File, path::Path};

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions,
    },
    error::Result,
};

static SUPPORTED_TYPES: [&str; 3] = [
    "c2pa",
    "application/c2pa",
    "application/x-c2pa-manifest-store",
];

/// Supports working with ".c2pa" files containing only manifest store data
pub struct C2paIO {}

impl CAIReader for C2paIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut cai_data = Vec::new();
        // read the whole file
        asset_reader.read_to_end(&mut cai_data)?;
        Ok(cai_data)
    }

    // C2PA files have no xmp data
    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for C2paIO {
    fn write_cai(
        &self,
        _input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        // just write the store bytes and ingore the input stream
        output_stream.write_all(store_bytes)?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        __input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // there is no data to hash
        Ok(vec![])
    }
}

impl AssetIO for C2paIO {
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn get_object_locations(
        &self,
        _asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let hop = HashObjectPositions {
            offset: 0,
            length: 0,
            htype: HashBlockObjectType::Cai,
        };

        Ok(vec![hop])
    }

    fn remove_cai_store(&self, _asset_path: &Path) -> Result<()> {
        Ok(())
    }

    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        C2paIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(C2paIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(C2paIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

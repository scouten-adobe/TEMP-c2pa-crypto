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

use std::{fs::File, io::Cursor, path::*};

use byteorder::{BigEndian, ReadBytesExt};
use img_parts::{
    jpeg::{
        markers::{self},
        Jpeg, JpegSegment,
    },
    Bytes, DynImage,
};

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::xmp_inmemory_utils::{add_provenance, MIN_XMP},
};

static SUPPORTED_TYPES: [&str; 3] = ["jpg", "jpeg", "image/jpeg"];

const XMP_SIGNATURE: &[u8] = b"http://ns.adobe.com/xap/1.0/";
const XMP_SIGNATURE_BUFFER_SIZE: usize = XMP_SIGNATURE.len() + 1; // skip null or space char at end

const MAX_JPEG_MARKER_SIZE: usize = 64000; // technically it's 64K but a bit smaller is fine

const C2PA_MARKER: [u8; 4] = [0x63, 0x32, 0x70, 0x61];

fn vec_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) &&  // zip stops at the shortest
     va.iter()
       .zip(vb)
       .all(|(a,b)| a == b)
}

// Return contents of APP1 segment if it is an XMP segment.
fn extract_xmp(seg: &JpegSegment) -> Option<String> {
    let contents = seg.contents();
    if contents.starts_with(XMP_SIGNATURE) {
        let rest = contents.slice(XMP_SIGNATURE_BUFFER_SIZE..);
        String::from_utf8(rest.to_vec()).ok()
    } else {
        None
    }
}

// Extract XMP from bytes.
fn xmp_from_bytes(asset_bytes: &[u8]) -> Option<String> {
    if let Ok(jpeg) = Jpeg::from_bytes(Bytes::copy_from_slice(asset_bytes)) {
        let segs = jpeg.segments_by_marker(markers::APP1);
        let xmp: String = segs.filter_map(extract_xmp).collect();
        Some(xmp)
    } else {
        None
    }
}

fn add_required_segs_to_stream(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    input_stream.rewind()?;
    input_stream.read_to_end(&mut buf).map_err(Error::IoError)?;
    input_stream.rewind()?;

    let dimg_opt = DynImage::from_bytes(buf.into())
        .map_err(|_err| Error::InvalidAsset("Could not parse input JPEG".to_owned()))?;

    if let Some(DynImage::Jpeg(jpeg)) = dimg_opt {
        // check for JUMBF Seg
        let cai_app11 = get_cai_segments(&jpeg)?; // make sure we only check for C2PA segments

        if cai_app11.is_empty() {
            // create dummy JUMBF seg
            let mut no_bytes: Vec<u8> = vec![0; 50]; // enough bytes to be valid
            no_bytes.splice(16..20, C2PA_MARKER); // cai UUID signature
            let aio = JpegIO {};
            aio.write_cai(input_stream, output_stream, &no_bytes)?;
        } else {
            // just clone
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
        }
    } else {
        return Err(Error::UnsupportedType);
    }

    Ok(())
}

// all cai specific segments
fn get_cai_segments(jpeg: &img_parts::jpeg::Jpeg) -> Result<Vec<usize>> {
    let mut cai_segs: Vec<usize> = Vec::new();

    let segments = jpeg.segments();

    let mut cai_en: Vec<u8> = Vec::new();
    let mut cai_seg_cnt: u32 = 0;

    for (i, segment) in segments.iter().enumerate() {
        let raw_bytes = segment.contents();
        let seg_type = segment.marker();

        if raw_bytes.len() > 16 && seg_type == markers::APP11 {
            // we need at least 16 bytes in each segment for CAI
            let mut raw_vec = raw_bytes.to_vec();
            let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
            let en = raw_vec.as_mut_slice()[2..4].to_vec();
            let mut z_vec = Cursor::new(raw_vec.as_mut_slice()[4..8].to_vec());
            let _z = z_vec.read_u32::<BigEndian>()?;

            let is_cai_continuation = vec_compare(&cai_en, &en);

            if cai_seg_cnt > 0 && is_cai_continuation {
                cai_seg_cnt += 1;
                cai_segs.push(i);
            } else {
                // check if this is a CAI JUMBF block
                let jumb_type = &raw_vec.as_mut_slice()[24..28];
                let is_cai = vec_compare(&C2PA_MARKER, jumb_type);
                if is_cai {
                    cai_segs.push(i);
                    cai_seg_cnt = 1;
                    cai_en.clone_from(&en); // store the identifier
                }
            }
        }
    }

    Ok(cai_segs)
}

// delete cai segments
fn delete_cai_segments(jpeg: &mut img_parts::jpeg::Jpeg) -> Result<()> {
    let cai_segs = get_cai_segments(jpeg)?;
    let jpeg_segs = jpeg.segments_mut();

    // remove cai segments
    for seg in cai_segs.iter().rev() {
        jpeg_segs.remove(*seg);
    }
    Ok(())
}

pub struct JpegIO {}

impl CAIReader for JpegIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::new();

        let mut manifest_store_cnt = 0;

        // load the bytes
        let mut buf: Vec<u8> = Vec::new();

        asset_reader.rewind()?;
        asset_reader.read_to_end(&mut buf).map_err(Error::IoError)?;

        let dimg_opt = DynImage::from_bytes(buf.into())
            .map_err(|_err| Error::InvalidAsset("Could not parse input JPEG".to_owned()))?;

        if let Some(dimg) = dimg_opt {
            match dimg {
                DynImage::Jpeg(jpeg) => {
                    let app11 = jpeg.segments_by_marker(markers::APP11);
                    let mut cai_en: Vec<u8> = Vec::new();
                    let mut cai_seg_cnt: u32 = 0;
                    for segment in app11 {
                        let raw_bytes = segment.contents();
                        if raw_bytes.len() > 16 {
                            // we need at least 16 bytes in each segment for CAI
                            let mut raw_vec = raw_bytes.to_vec();
                            let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
                            let en = raw_vec.as_mut_slice()[2..4].to_vec();
                            let mut z_vec = Cursor::new(raw_vec.as_mut_slice()[4..8].to_vec());
                            let z = z_vec.read_u32::<BigEndian>()?;

                            let is_cai_continuation = vec_compare(&cai_en, &en);

                            if cai_seg_cnt > 0 && is_cai_continuation {
                                // make sure this is a cai segment for additional segments,
                                if z <= cai_seg_cnt {
                                    // this a non contiguous segment with same "en" so a bad set of
                                    // data reset and continue
                                    // to search
                                    cai_en = Vec::new();
                                    continue;
                                }
                                // take out LBox & TBox
                                buffer.append(&mut raw_vec.as_mut_slice()[16..].to_vec());

                                cai_seg_cnt += 1;
                            } else if raw_vec.len() > 28 {
                                // must be at least 28 bytes for this to be a valid JUMBF box
                                // check if this is a CAI JUMBF block
                                let jumb_type = &raw_vec.as_mut_slice()[24..28];
                                let is_cai = vec_compare(&C2PA_MARKER, jumb_type);

                                if is_cai {
                                    if manifest_store_cnt == 1 {
                                        return Err(Error::TooManyManifestStores);
                                    }

                                    buffer.append(&mut raw_vec.as_mut_slice()[8..].to_vec());
                                    cai_seg_cnt = 1;
                                    cai_en.clone_from(&en); // store the identifier

                                    manifest_store_cnt += 1;
                                }
                            }
                        }
                    }
                }
                _ => return Err(Error::InvalidAsset("Unknown image format".to_owned())),
            };
        } else {
            return Err(Error::UnsupportedType);
        }

        if buffer.is_empty() {
            return Err(Error::JumbfNotFound);
        }

        Ok(buffer)
    }

    // Get XMP block
    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        // load the bytes
        let mut buf: Vec<u8> = Vec::new();
        match asset_reader.read_to_end(&mut buf) {
            Ok(_) => xmp_from_bytes(&buf),
            Err(_) => None,
        }
    }
}

impl CAIWriter for JpegIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let mut buf = Vec::new();
        // read the whole asset
        input_stream.rewind()?;
        input_stream.read_to_end(&mut buf).map_err(Error::IoError)?;
        let mut jpeg = Jpeg::from_bytes(buf.into()).map_err(|_err| Error::EmbeddingError)?;

        // remove existing CAI segments
        delete_cai_segments(&mut jpeg)?;

        let jumbf_len = store_bytes.len();
        let num_segments = (jumbf_len / MAX_JPEG_MARKER_SIZE) + 1;
        let mut seg_chucks = store_bytes.chunks(MAX_JPEG_MARKER_SIZE);

        for seg in 1..num_segments + 1 {
            /*
                If the size of the box payload is less than 2^32-8 bytes,
                then all fields except the XLBox field, that is: Le, CI, En, Z, LBox and TBox,
                shall be present in all JPEG XT marker segment representing this box,
                regardless of whether the marker segments starts this box,
                or continues a box started by a former JPEG XT Marker segment.
            */
            // we need to prefix the JUMBF with the JPEG XT markers (ISO 19566-5)
            // CI: JPEG extensions marker - JP
            // En: Box Instance Number  - 0x0001
            //          (NOTE: can be any unique ID, so we pick one that shouldn't conflict)
            // Z: Packet sequence number - 0x00000001...
            let ci = vec![0x4a, 0x50];
            let en = vec![0x02, 0x11];
            let z: u32 = u32::try_from(seg)
                .map_err(|_| Error::InvalidAsset("Too many JUMBF segments".to_string()))?; //seg.to_be_bytes();

            let mut seg_data = Vec::new();
            seg_data.extend(ci);
            seg_data.extend(en);
            seg_data.extend(z.to_be_bytes());
            if seg > 1 {
                // the LBox and TBox are already in the JUMBF
                // but we need to duplicate them in all other segments
                let lbox_tbox = &store_bytes[..8];
                seg_data.extend(lbox_tbox);
            }
            if seg_chucks.len() > 0 {
                // make sure we have some...
                if let Some(next_seg) = seg_chucks.next() {
                    seg_data.extend(next_seg);
                }
            } else {
                seg_data.extend(store_bytes);
            }

            let seg_bytes = Bytes::from(seg_data);
            let app11_segment = JpegSegment::new_with_contents(markers::APP11, seg_bytes);
            jpeg.segments_mut().insert(seg, app11_segment); // we put this in
                                                            // the beginning...
        }

        output_stream.rewind()?;
        jpeg.encoder()
            .write_to(output_stream)
            .map_err(|_err| Error::InvalidAsset("JPEG write error".to_owned()))?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut cai_en: Vec<u8> = Vec::new();
        let mut cai_seg_cnt: u32 = 0;

        let mut positions: Vec<HashObjectPositions> = Vec::new();
        let mut curr_offset = 2; // start after JPEG marker

        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);
        // make sure the file has the required segments so we can generate all the
        // required offsets
        add_required_segs_to_stream(input_stream, &mut output_stream)?;

        let buf: Vec<u8> = output_stream.into_inner();

        let dimg = DynImage::from_bytes(buf.into())
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .ok_or(Error::UnsupportedType)?;

        match dimg {
            DynImage::Jpeg(jpeg) => {
                for seg in jpeg.segments() {
                    match seg.marker() {
                        markers::APP11 => {
                            // JUMBF marker
                            let raw_bytes = seg.contents();

                            if raw_bytes.len() > 16 {
                                // we need at least 16 bytes in each segment for CAI
                                let mut raw_vec = raw_bytes.to_vec();
                                let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
                                let en = raw_vec.as_mut_slice()[2..4].to_vec();

                                let is_cai_continuation = vec_compare(&cai_en, &en);

                                if cai_seg_cnt > 0 && is_cai_continuation {
                                    cai_seg_cnt += 1;

                                    let v = HashObjectPositions {
                                        offset: curr_offset,
                                        length: seg.len_with_entropy(),
                                        htype: HashBlockObjectType::Cai,
                                    };
                                    positions.push(v);
                                } else {
                                    // check if this is a CAI JUMBF block
                                    let jumb_type = raw_vec.as_mut_slice()[24..28].to_vec();
                                    let is_cai = vec_compare(&C2PA_MARKER, &jumb_type);
                                    if is_cai {
                                        cai_seg_cnt = 1;
                                        cai_en.clone_from(&en); // store the identifier

                                        let v = HashObjectPositions {
                                            offset: curr_offset,
                                            length: seg.len_with_entropy(),
                                            htype: HashBlockObjectType::Cai,
                                        };

                                        positions.push(v);
                                    } else {
                                        // save other for completeness sake
                                        let v = HashObjectPositions {
                                            offset: curr_offset,
                                            length: seg.len_with_entropy(),
                                            htype: HashBlockObjectType::Other,
                                        };
                                        positions.push(v);
                                    }
                                }
                            }
                        }
                        markers::APP1 => {
                            // XMP marker or EXIF or Extra XMP
                            let v = HashObjectPositions {
                                offset: curr_offset,
                                length: seg.len_with_entropy(),
                                htype: HashBlockObjectType::Xmp,
                            };
                            // todo: pick the app1 that is the xmp (not crucial as it gets hashed
                            // either way)
                            positions.push(v);
                        }
                        _ => {
                            // save other for completeness sake
                            let v = HashObjectPositions {
                                offset: curr_offset,
                                length: seg.len_with_entropy(),
                                htype: HashBlockObjectType::Other,
                            };

                            positions.push(v);
                        }
                    }
                    curr_offset += seg.len_with_entropy();
                }
            }
            _ => return Err(Error::InvalidAsset("Unknown image format".to_owned())),
        }

        Ok(positions)
    }
}

impl AssetIO for JpegIO {
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;

        self.read_cai(&mut f)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        self.get_object_locations_from_stream(&mut file)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let input = std::fs::read(asset_path).map_err(Error::IoError)?;

        let mut jpeg = Jpeg::from_bytes(input.into()).map_err(|_err| Error::EmbeddingError)?;

        // remove existing CAI segments
        delete_cai_segments(&mut jpeg)?;

        // save updated file
        let output = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        jpeg.encoder()
            .write_to(output)
            .map_err(|_err| Error::InvalidAsset("JPEG write error".to_owned()))?;

        Ok(())
    }

    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        JpegIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(JpegIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(JpegIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl RemoteRefEmbed for JpegIO {
    #[allow(unused_variables)]
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: crate::asset_io::RemoteRefEmbedType,
    ) -> Result<()> {
        match &embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(_manifest_uri) => {
                let mut file = std::fs::File::open(asset_path)?;
                let mut temp = Cursor::new(Vec::new());
                self.embed_reference_to_stream(&mut file, &mut temp, embed_ref)?;
                let mut output = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .open(asset_path)
                    .map_err(Error::IoError)?;
                temp.set_position(0);
                std::io::copy(&mut temp, &mut output).map_err(Error::IoError)?;
                Ok(())
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                let mut buf = Vec::new();
                // read the whole asset
                source_stream.rewind()?;
                source_stream
                    .read_to_end(&mut buf)
                    .map_err(Error::IoError)?;
                let mut jpeg =
                    Jpeg::from_bytes(buf.into()).map_err(|_err| Error::EmbeddingError)?;

                // find any existing XMP segment and remember where it was
                let mut xmp = MIN_XMP.to_string(); // default minimal XMP
                let mut xmp_index = None;
                let segments = jpeg.segments_mut();
                for (i, seg) in segments.iter().enumerate() {
                    if seg.marker() == markers::APP1 && seg.contents().starts_with(XMP_SIGNATURE) {
                        xmp = extract_xmp(seg).unwrap_or_else(|| xmp.clone());
                        xmp_index = Some(i);
                        break;
                    }
                }
                // add provenance and JPEG XMP prefix
                let xmp = format!(
                    "http://ns.adobe.com/xap/1.0/\0 {}",
                    add_provenance(&xmp, &manifest_uri)?
                );
                let segment = JpegSegment::new_with_contents(markers::APP1, Bytes::from(xmp));
                // insert or add the segment
                match xmp_index {
                    Some(i) => segments[i] = segment,
                    None => segments.insert(1, segment),
                }

                jpeg.encoder()
                    .write_to(output_stream)
                    .map_err(|_err| Error::InvalidAsset("JPEG write error".to_owned()))?;
                Ok(())
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

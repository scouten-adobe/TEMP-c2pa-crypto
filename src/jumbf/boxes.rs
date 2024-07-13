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

//! This is a library for generating ISO BMFF/JUMBF boxes
//!
//! It is based on the work of Takeru Ohta <phjgt308@gmail.com>
//! and [mse_fmp4](https://github.com/sile/mse_fmp4) and enhanced
//! by Leonard Rosenthol <lrosenth@adobe.com>
//
//!  # References
//!
//!  - [ISO BMFF Byte Stream Format](https://w3c.github.io/media-source/isobmff-byte-stream-format.html)
//!  - [JPEG universal metadata box format](https://www.iso.org/standard/73604.html)

#![allow(dead_code)] // TEMPORARY: will likely fall away soon

use std::{
    any::Any,
    ffi::CString,
    fmt,
    io::{Read, Result as IoResult, Seek, SeekFrom, Write},
};

use byteorder::{BigEndian, ReadBytesExt};
use hex::FromHex;
use log::debug;
use thiserror::Error;

use crate::jumbf::{boxio, labels};

/// `JumbfParseError` enumerates errors detected while parsing JUMBF data
/// structures.
#[derive(Debug, Error)]
pub enum JumbfParseError {
    // TODO before merging PR: Add doc comments for these.
    // Is there more to say than the description string?
    #[error("unexpected end of file")]
    UnexpectedEof,

    #[error("invalid box start")]
    InvalidBoxStart,

    #[error("invalid box header")]
    InvalidBoxHeader,

    #[error("invalid box range")]
    InvalidBoxRange,

    #[error("invalid JUMBF header")]
    InvalidJumbfHeader,

    #[error("invalid JUMB box")]
    InvalidJumbBox,

    #[error("invalid UUID label")]
    InvalidUuidValue,

    #[error("invalid JSON box")]
    InvalidJsonBox,

    #[error("invalid CBOR box")]
    InvalidCborBox,

    #[error("invalid JP2C box")]
    InvalidJp2cBox,

    #[error("invalid UUID box")]
    InvalidUuidBox,

    #[error("invalid embedded file box")]
    InvalidEmbeddedFileBox,

    #[error("invalid box of unknown type")]
    InvalidUnknownBox,

    #[error("expected JUMD")]
    ExpectedJumdError,

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("assertion salt must be 16 bytes or greater")]
    InvalidSalt,

    #[error("invalid JUMD box")]
    InvalidDescriptionBox,
}

/// A specialized `JumbfParseResult` type for JUMBF parsing operations.
pub type JumbfParseResult<T> = std::result::Result<T, JumbfParseError>;

//-----------------
// ANCHOR ISO BMFF
//-----------------
macro_rules! write_u8 {
    ($w:expr, $n:expr) => {{
        use byteorder::WriteBytesExt;
        $w.write_u8($n)?
    }};
}
// macro_rules! write_u16 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_u16::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_i16 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_i16::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_u24 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_uint::<BigEndian>($n as u64, 3)?;
//     }};
// }
macro_rules! write_u32 {
    ($w:expr, $n:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};
        $w.write_u32::<BigEndian>($n)?;
    }};
}
// macro_rules! write_i32 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_i32::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_u64 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_u64::<BigEndian>($n)?;
//     }};
// }
macro_rules! write_all {
    ($w:expr, $n:expr) => {
        $w.write_all($n)?;
    };
}
// macro_rules! write_zeroes {
//     ($w:expr, $n:expr) => {
//         $w.write_all(&[0; $n][..])?;
//     };
// }
// macro_rules! write_box {
//     ($w:expr, $b:expr) => {
//         $b.write_box(&mut $w)?;
//     };
// }
// macro_rules! write_boxes {
//     ($w:expr, $bs:expr) => {
//         for b in $bs {
//             b.write_box(&mut $w)?;
//         }
//     };
// }
macro_rules! box_size {
    ($b:expr) => {
        $b.box_size()?
    };
}
// macro_rules! optional_box_size {
//     ($b:expr) => {
//         if let Some(ref b) = $b.as_ref() {
//             b.box_size()?
//         } else {
//             0
//         }
//     };
// }
macro_rules! boxes_size {
    ($b:expr) => {{
        let mut size = 0;
        for b in $b.iter() {
            size += box_size!(b);
        }
        size
    }};
}

/// ISO BMFF box.
pub trait BMFFBox: Any {
    // "Any is the closest thing to reflection there is in Rust"
    /// Box type code.
    fn box_type(&self) -> &'static [u8; 4];

    /// Box UUID (used by JUMBF)
    #[allow(dead_code)]
    fn box_uuid(&self) -> &'static str;

    /// Box size.
    fn box_size(&self) -> IoResult<u32> {
        // if it a real box...
        let mut size = if self.box_type() != b"    " { 8 } else { 0 };
        size += self.box_payload_size()?;

        Ok(size)
    }

    /// Payload size of the box.
    fn box_payload_size(&self) -> IoResult<u32>;

    /// Writes the box to the given writer.
    fn write_box(&self, writer: &mut dyn Write) -> IoResult<()> {
        if self.box_type() != b"    " {
            // it's a real box...
            write_u32!(writer, self.box_size()?);
            write_all!(writer, self.box_type());
        }

        self.write_box_payload(writer)?;
        Ok(())
    }

    /// Writes the payload of the box to the given writer.
    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()>;

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any;
}

impl fmt::Debug for dyn BMFFBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BMFFBox")
            .field("type", self.box_type())
            .field("size", &self.box_size())
            .finish()
    }
}

//---------------
// SECTION JUMBF
//---------------
pub const JUMB_FOURCC: &str = "6A756D62";
pub const JUMD_FOURCC: &str = "6A756D64";

// ANCHOR JUMBF superbox
/// JUMBF superbox (ISO 19566-5:2019, Annex A)
#[derive(Debug)]
pub struct JUMBFSuperBox {
    desc_box: JUMBFDescriptionBox,
    data_boxes: Vec<Box<dyn BMFFBox>>,
}

#[allow(dead_code)]
impl JUMBFSuperBox {
    pub fn new(box_label: &str, a_type: Option<&str>) -> Self {
        JUMBFSuperBox {
            desc_box: JUMBFDescriptionBox::new(box_label, a_type),
            data_boxes: vec![],
        }
    }

    pub fn from(a_box: JUMBFDescriptionBox) -> Self {
        JUMBFSuperBox {
            desc_box: a_box,
            data_boxes: vec![],
        }
    }

    // add a data box *WITHOUT* taking ownership of the box
    pub fn add_data_box(&mut self, b: Box<dyn BMFFBox>) {
        self.data_boxes.push(b)
    }

    // getters
    pub fn desc_box(&self) -> &JUMBFDescriptionBox {
        &self.desc_box
    }

    pub fn data_box_count(&self) -> usize {
        self.data_boxes.len()
    }

    pub fn data_box_as_superbox(&self, index: usize) -> Option<&JUMBFSuperBox> {
        let da_box = &self.data_boxes[index];
        da_box.as_ref().as_any().downcast_ref::<JUMBFSuperBox>()
    }

    pub fn data_box_as_json_box(&self, index: usize) -> Option<&JUMBFJSONContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFJSONContentBox>()
    }

    pub fn data_box_as_cbor_box(&self, index: usize) -> Option<&JUMBFCBORContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFCBORContentBox>()
    }

    pub fn data_box_as_uuid_box(&self, index: usize) -> Option<&JUMBFUUIDContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFUUIDContentBox>()
    }

    pub fn data_box_as_embedded_file_content_box(
        &self,
        index: usize,
    ) -> Option<&JUMBFEmbeddedFileContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileContentBox>()
    }

    pub fn data_box_as_embedded_media_type_box(
        &self,
        index: usize,
    ) -> Option<&JUMBFEmbeddedFileDescriptionBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileDescriptionBox>()
    }
}

impl BMFFBox for JUMBFSuperBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumb"
    }

    fn box_uuid(&self) -> &'static str {
        JUMB_FOURCC
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let mut size = 0;
        size += box_size!(self.desc_box);
        if !self.data_boxes.is_empty() {
            size += boxes_size!(self.data_boxes)
        }
        Ok(size)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        let res = self.desc_box.write_box(writer);
        for b in &self.data_boxes {
            b.write_box(writer)?;
        }
        res
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMBF Description box
/// JUMBF Description box (ISO 19566-5:2019, Annex A)
#[derive(Debug)]
pub struct JUMBFDescriptionBox {
    box_uuid: [u8; 16],                 // a 128-bit UUID for the type
    toggles: u8,                        // bit field for valid values
    label: CString,                     // Null terminated UTF-8 string (OPTIONAL)
    box_id: Option<u32>,                // user assigned value (OPTIONAL)
    signature: Option<[u8; 32]>,        // SHA-256 hash of the payload (OPTIONAL)
    private: Option<CAISaltContentBox>, // private salt content box
}

impl JUMBFDescriptionBox {
    /// Makes a new `JUMBFDescriptionBox` instance.
    pub fn new(box_label: &str, a_type: Option<&str>) -> Self {
        JUMBFDescriptionBox {
            box_uuid: match a_type {
                Some(ref t) => <[u8; 16]>::from_hex(t).unwrap_or([0u8; 16]),
                None => [0u8; 16], // init to all zeros
            },
            toggles: 3, // 0x11 (Requestable + Label Present)
            label: CString::new(box_label).unwrap_or_default(),
            box_id: None,
            signature: None,
            private: None,
        }
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        if salt.len() < 16 {
            return Err(JumbfParseError::InvalidSalt);
        }

        self.private = Some(CAISaltContentBox::new(salt));
        self.toggles = 19; // 0x10011 (Requestable + Label Present + Private)

        Ok(())
    }

    /// Makes a new `JUMBFDescriptionBox` instance from read in data
    #[allow(dead_code)]
    pub fn from(
        uuid: &[u8; 16],
        togs: u8,
        box_label: Vec<u8>,
        bxid: Option<u32>,
        sig: Option<[u8; 32]>,
        private: Option<CAISaltContentBox>,
    ) -> Self {
        let c_string: CString;
        unsafe {
            c_string = CString::from_vec_unchecked(box_label);
        }
        JUMBFDescriptionBox {
            box_uuid: *uuid,
            toggles: togs, // will always be 0x11 (Requestable + Label Present)
            label: c_string,
            box_id: bxid,
            signature: sig,
            private,
        }
    }

    #[allow(dead_code)]
    pub fn label(&self) -> String {
        self.label.clone().into_string().unwrap_or_default()
    }
}

impl BMFFBox for JUMBFDescriptionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumd"
    }

    fn box_uuid(&self) -> &'static str {
        JUMD_FOURCC
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_all!(writer, &self.box_uuid);
        write_u8!(writer, self.toggles);

        if self.label.to_str().unwrap_or_default().chars().count() > 0 {
            write_all!(writer, self.label.as_bytes_with_nul());
        }

        if let Some(x) = self.box_id {
            write_u32!(writer, x);
        }

        if let Some(x) = self.signature {
            write_all!(writer, &x);
        }

        if let Some(salt) = &self.private {
            salt.write_box(writer)?;
        }

        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMBF UUIDs
pub const JUMBF_CODESTREAM_UUID: &str = "6579D6FBDBA2446BB2AC1B82FEEB89D1";
pub const JUMBF_JSON_UUID: &str = "6A736F6E00110010800000AA00389B71";
pub const JUMBF_CBOR_UUID: &str = "63626F7200110010800000AA00389B71";
// pub const JUMBF_XML_UUID: &str = "786D6C2000110010800000AA00389B71";
pub const JUMBF_UUID_UUID: &str = "7575696400110010800000AA00389B71";
pub const JUMBF_EMBEDDED_FILE_UUID: &str = "40CB0C32BB8A489DA70B2AD6F47F4369";
// ANCHOR JUMBF Content box
/// JUMBF Content box (ISO 19566-5:2019, Annex B)
#[derive(Debug, Default)]
pub struct JUMBFContentBox;

impl BMFFBox for JUMBFContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumd"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        Ok(0) // it isn't a real box, just a base class
    }

    fn write_box_payload(&self, _writer: &mut dyn Write) -> IoResult<()> {
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMB Padding Box
#[derive(Debug, Default)]
pub struct JUMBFPaddingContentBox {
    padding: Vec<u8>, // arbitrary number of zero'd bytes...
}

impl BMFFBox for JUMBFPaddingContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"free"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.padding.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.padding.is_empty() {
            write_all!(writer, &self.padding);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFPaddingContentBox {
    #[allow(dead_code)]
    pub fn new_with_vec(padding: Vec<u8>) -> Self {
        JUMBFPaddingContentBox { padding }
    }

    // we do not take a vec to ensure the box contains only zeros
    #[allow(dead_code)]
    pub fn new(box_size: usize) -> Self {
        JUMBFPaddingContentBox {
            padding: vec![0; box_size],
        }
    }
}

// ANCHOR JUMBF JSON Content box
/// JUMBF JSON Content box (ISO 19566-5:2019, Annex B.4)
#[derive(Debug, Default)]
pub struct JUMBFJSONContentBox {
    json: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFJSONContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"json"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_JSON_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.json.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.json.is_empty() {
            write_all!(writer, &self.json);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFJSONContentBox {
    // the content box takes ownership of the data!
    pub fn new(json_in: Vec<u8>) -> Self {
        JUMBFJSONContentBox { json: json_in }
    }

    // getter
    #[allow(dead_code)]
    pub fn json(&self) -> &Vec<u8> {
        &self.json
    }
}

pub struct JUMBFCBORContentBox {
    cbor: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFCBORContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"cbor"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_CBOR_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.cbor.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.cbor.is_empty() {
            write_all!(writer, &self.cbor);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFCBORContentBox {
    // the content box takes ownership of the data!
    #[allow(dead_code)]
    pub fn new(cbor_in: Vec<u8>) -> Self {
        JUMBFCBORContentBox { cbor: cbor_in }
    }

    // getter
    #[allow(dead_code)]
    pub fn cbor(&self) -> &Vec<u8> {
        &self.cbor
    }
}

// ANCHOR JUMBF Codestream Content box
/// JUMBF Codestream Content box (ISO 19566-5:2019, Annex B.2)
#[derive(Debug, Default)]
pub struct JUMBFCodestreamContentBox {
    data: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFCodestreamContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jp2c"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_CODESTREAM_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFCodestreamContentBox {
    // the content box takes ownership of the data!
    #[allow(dead_code)]
    pub fn new(data_in: Vec<u8>) -> Self {
        JUMBFCodestreamContentBox { data: data_in }
    }
}

// ANCHOR JUMBF UUID Content box
/// JUMBF UUID Content box (ISO 19566-5:2019, Annex B.5)
#[derive(Debug, Default)]
pub struct JUMBFUUIDContentBox {
    uuid: [u8; 16], // a 128-bit UUID for the type
    data: Vec<u8>,  // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFUUIDContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"uuid"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_UUID_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = 16 /*UUID*/ + self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.uuid);
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFUUIDContentBox {
    // the content box takes ownership of the data!
    pub fn new(uuid_in: &[u8; 16], data_in: Vec<u8>) -> Self {
        let mut u: [u8; 16] = Default::default();
        u.copy_from_slice(uuid_in);

        JUMBFUUIDContentBox {
            uuid: u,
            data: data_in,
        }
    }

    // getters
    #[allow(dead_code)]
    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    // getter
    #[allow(dead_code)]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

// !SECTION

//---------------
// SECTION CAI
//---------------
pub const CAI_BLOCK_UUID: &str = "6332706100110010800000AA00389B71"; // c2pa
pub const CAI_STORE_UUID: &str = "63326D6100110010800000AA00389B71"; // c2ma
pub const CAI_UPDATE_MANIFEST_UUID: &str = "6332756D00110010800000AA00389B71"; // c2um
pub const CAI_ASSERTION_STORE_UUID: &str = "6332617300110010800000AA00389B71"; // c2as
pub const CAI_JSON_ASSERTION_UUID: &str = "6A736F6E00110010800000AA00389B71"; // json
pub const CAI_CBOR_ASSERTION_UUID: &str = "63626F7200110010800000AA00389B71"; // cbor
pub const CAI_CLAIM_UUID: &str = "6332636C00110010800000AA00389B71"; // c2cl
pub const CAI_SIGNATURE_UUID: &str = "6332637300110010800000AA00389B71"; // c2cs
                                                                         // pub const CAI_EMBEDDED_FILE_UUID: &str = "40CB0C32BB8A489DA70B2AD6F47F4369";
pub const CAI_EMBEDDED_FILE_DESCRIPTION_UUID: &str = "6266646200110010800000AA00389B71"; // bfdb
pub const CAI_EMBEDDED_FILE_DATA_UUID: &str = "6269646200110010800000AA00389B71"; // bidb
pub const CAI_VERIFIABLE_CREDENTIALS_STORE_UUID: &str = "6332766300110010800000AA00389B71"; // c2vc
pub const CAI_UUID_ASSERTION_UUID: &str = "7575696400110010800000AA00389B71"; // uuid
pub const CAI_DATABOXES_STORE_UUID: &str = "6332646200110010800000AA00389B71"; // c2db

// ANCHOR Salt Content Box
/// Salt Content Box
#[derive(Debug)]
pub struct CAISaltContentBox {
    salt: Vec<u8>, // salt data...
}

impl BMFFBox for CAISaltContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"c2sh"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.salt.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_all!(writer, &self.salt);
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAISaltContentBox {
    pub fn new(data_in: Vec<u8>) -> Self {
        CAISaltContentBox { salt: data_in }
    }
}

// ANCHOR Signature Box
/// Signature Box
#[derive(Debug)]
pub struct CAISignatureBox {
    sig_box: JUMBFSuperBox,
}

impl BMFFBox for CAISignatureBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_SIGNATURE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.sig_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAISignatureBox {
    pub fn new() -> Self {
        CAISignatureBox {
            sig_box: JUMBFSuperBox::new(labels::SIGNATURE, Some(CAI_SIGNATURE_UUID)),
        }
    }

    // add a signature content box *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_signature(&mut self, b: Box<dyn BMFFBox>) {
        self.sig_box.add_data_box(b)
    }
}

impl Default for CAISignatureBox {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR Claim Box
/// Claim Box
#[derive(Debug)]
pub struct CAIClaimBox {
    claim_box: JUMBFSuperBox,
}

impl BMFFBox for CAIClaimBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_CLAIM_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.claim_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIClaimBox {
    pub fn new() -> Self {
        CAIClaimBox {
            claim_box: JUMBFSuperBox::new(labels::CLAIM, Some(CAI_CLAIM_UUID)),
        }
    }

    // add a JUMBFCBORContentBox box, with the claim's CBOR
    // *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_claim(&mut self, b: Box<dyn BMFFBox>) {
        self.claim_box.add_data_box(b)
    }
}

impl Default for CAIClaimBox {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR UUID Assertion Box
/// UUID Assertion Box
#[derive(Debug)]
pub struct CAIUUIDAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAIUUIDAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_UUID_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIUUIDAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAIUUIDAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_UUID_ASSERTION_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the assertion's JSON
    // takes ownership of the JSON
    pub fn add_uuid(&mut self, uuid_str: &str, data: Vec<u8>) -> JumbfParseResult<()> {
        let uuid = hex::decode(uuid_str).map_err(|_e| JumbfParseError::InvalidUuidValue)?;
        if uuid.len() != 16 {
            // the uuid is defined a as 16 bytes
            return Err(JumbfParseError::InvalidUuidValue);
        }

        let mut u: [u8; 16] = Default::default();
        u.copy_from_slice(&uuid);
        let assertion_content = JUMBFUUIDContentBox::new(&u, data);
        self.assertion_box.add_data_box(Box::new(assertion_content));

        Ok(())
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

// ANCHOR JSON Assertion Box
/// JSON Assertion Box
#[derive(Debug)]
pub struct CAIJSONAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAIJSONAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_JSON_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIJSONAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAIJSONAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_JSON_ASSERTION_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the assertion's JSON
    // takes ownership of the JSON
    pub fn add_json(&mut self, json_in: Vec<u8>) {
        let assertion_content = JUMBFJSONContentBox::new(json_in);
        self.assertion_box.add_data_box(Box::new(assertion_content));
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

pub struct CAICBORAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAICBORAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_CBOR_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAICBORAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAICBORAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_CBOR_ASSERTION_UUID)),
        }
    }

    // add a JUMBFCBORContentBox box, with the assertion's CBOR
    // takes ownership of the CBOR
    pub fn add_cbor(&mut self, cbor_in: Vec<u8>) {
        let assertion_content = JUMBFCBORContentBox::new(cbor_in);
        self.assertion_box.add_data_box(Box::new(assertion_content));
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

// ANCHOR Assertion Store
/// Assertion Store
#[derive(Debug)]
pub struct CAIAssertionStore {
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIAssertionStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_ASSERTION_STORE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIAssertionStore {
    pub fn new() -> Self {
        CAIAssertionStore {
            store: JUMBFSuperBox::new(labels::ASSERTIONS, Some(CAI_ASSERTION_STORE_UUID)),
        }
    }

    // add an assertion box (of various types) *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_assertion(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }
}

impl Default for CAIAssertionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct CAIDataboxStore {
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIDataboxStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_DATABOXES_STORE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIDataboxStore {
    pub fn new() -> Self {
        CAIDataboxStore {
            store: JUMBFSuperBox::new(labels::DATABOXES, Some(CAI_DATABOXES_STORE_UUID)),
        }
    }

    // add an assertion box (of various types) *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_databox(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }
}

impl Default for CAIDataboxStore {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR Verifiable Credential Store
/// Ingredients Store
#[derive(Debug)]
pub struct CAIVerifiableCredentialStore {
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIVerifiableCredentialStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_VERIFIABLE_CREDENTIALS_STORE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIVerifiableCredentialStore {
    pub fn new() -> Self {
        CAIVerifiableCredentialStore {
            store: JUMBFSuperBox::new(
                labels::CREDENTIALS,
                Some(CAI_VERIFIABLE_CREDENTIALS_STORE_UUID),
            ),
        }
    }

    // add an credential box *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_credential(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }
}

impl Default for CAIVerifiableCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR CAI Store
/// CAI Store
#[derive(Debug)]
pub struct CAIStore {
    is_update_manifest: bool,
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        if self.is_update_manifest {
            CAI_UPDATE_MANIFEST_UUID
        } else {
            CAI_STORE_UUID
        }
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIStore {
    #[allow(dead_code)]
    pub fn new(box_label: &str, update_manifest: bool) -> Self {
        let id = if update_manifest {
            Some(CAI_UPDATE_MANIFEST_UUID)
        } else {
            Some(CAI_STORE_UUID)
        };
        let sbox = JUMBFSuperBox::new(box_label, id);
        CAIStore {
            is_update_manifest: update_manifest,
            store: sbox,
        }
    }

    /// add a box (of various types) *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_box(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }

    // getters
    #[allow(dead_code)]
    pub fn super_box(&self) -> &JUMBFSuperBox {
        &self.store
    }

    #[allow(dead_code)]
    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.store.desc_box.set_salt(salt)
    }
}

// ANCHOR CAI Block
/// CAI Block
#[derive(Debug)]
pub struct Cai {
    sbox: JUMBFSuperBox,
}

impl BMFFBox for Cai {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_BLOCK_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.sbox.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Cai {
    pub fn new() -> Self {
        Cai {
            sbox: JUMBFSuperBox::new(labels::MANIFEST_STORE, Some(CAI_BLOCK_UUID)),
        }
    }

    #[allow(dead_code)]
    pub fn from(in_box: JUMBFSuperBox) -> Self {
        Cai { sbox: in_box }
    }

    /// add a box (of various types) *WITHOUT* taking ownership of the box
    #[allow(dead_code)]
    pub fn add_box(&mut self, b: Box<dyn BMFFBox>) {
        self.sbox.add_data_box(b)
    }

    #[allow(dead_code)]
    pub fn desc_box(&self) -> &JUMBFDescriptionBox {
        &self.sbox.desc_box
    }

    #[allow(dead_code)]
    pub fn data_box_count(&self) -> usize {
        self.sbox.data_boxes.len()
    }

    #[allow(dead_code)]
    pub fn data_box_as_superbox(&self, index: usize) -> Option<&JUMBFSuperBox> {
        let da_box = &self.sbox.data_boxes[index];
        da_box.as_ref().as_any().downcast_ref::<JUMBFSuperBox>()
    }
}

impl Default for Cai {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JumbfEmbeddedFileBox {
    embedding_box: JUMBFSuperBox,
}

impl BMFFBox for JumbfEmbeddedFileBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_EMBEDDED_FILE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.embedding_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JumbfEmbeddedFileBox {
    pub fn new(box_label: &str) -> Self {
        JumbfEmbeddedFileBox {
            embedding_box: JUMBFSuperBox::new(box_label, Some(JUMBF_EMBEDDED_FILE_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the claim's JSON
    // *WITHOUT* taking ownership of the box
    pub fn add_data(&mut self, data: Vec<u8>, media_type: String, file_name: Option<String>) {
        // add media type box
        let m = JUMBFEmbeddedFileDescriptionBox::new(media_type, file_name);
        self.embedding_box.add_data_box(Box::new(m));

        // add data box
        let d = JUMBFEmbeddedFileContentBox::new(data);
        self.embedding_box.add_data_box(Box::new(d));
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.embedding_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.embedding_box
    }
}

impl Default for JumbfEmbeddedFileBox {
    fn default() -> Self {
        Self::new("")
    }
}
#[derive(Debug, Default)]
pub struct JUMBFEmbeddedFileContentBox {
    data: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFEmbeddedFileContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"bidb"
    }

    fn box_uuid(&self) -> &'static str {
        CAI_EMBEDDED_FILE_DATA_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFEmbeddedFileContentBox {
    // the content box takes ownership of the data!
    pub fn new(data_in: Vec<u8>) -> Self {
        JUMBFEmbeddedFileContentBox { data: data_in }
    }

    // getter
    #[allow(dead_code)]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Debug)]
pub struct JUMBFEmbeddedFileDescriptionBox {
    toggles: u8,         // media togles
    media_type: CString, // file media type
    #[allow(dead_code)]
    file_name: Option<CString>, // optional file name
}

impl BMFFBox for JUMBFEmbeddedFileDescriptionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"bfdb"
    }

    fn box_uuid(&self) -> &'static str {
        CAI_EMBEDDED_FILE_DESCRIPTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_u8!(writer, self.toggles);
        if self.media_type.to_str().unwrap_or_default().chars().count() > 0 {
            write_all!(writer, self.media_type.as_bytes_with_nul());
        }
        /*
        if let Some(name) = &self.file_name {
            if name
                .to_str()
                .expect("Incompatible string representation")
                .chars()
                .count()
                > 0
            {
                write_all!(writer, name.as_bytes_with_nul())
            }
        }
        */
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFEmbeddedFileDescriptionBox {
    pub fn new(media_type: String, file_name: Option<String>) -> Self {
        let mut new_toggles = 0;

        let cfile_name = match file_name {
            Some(f) => {
                new_toggles = 1;
                Some(CString::new(f).unwrap_or_default())
            }
            None => None,
        };

        JUMBFEmbeddedFileDescriptionBox {
            toggles: new_toggles,
            media_type: CString::new(media_type).unwrap_or_default(),
            file_name: cfile_name,
        }
    }

    #[allow(dead_code)]
    fn to_rust_str(&self, s: &CString) -> String {
        let bytes = s.clone().into_bytes();

        let nul_range_end = bytes
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(bytes.len());

        if let Ok(r_str) = String::from_utf8(bytes[0..nul_range_end].to_vec()) {
            r_str
        } else {
            String::new()
        }
    }

    #[allow(dead_code)]
    pub fn media_type(&self) -> String {
        self.to_rust_str(&self.media_type)
    }

    /// Makes a new `JUMBFDescriptionBox` instance from read in data
    #[allow(dead_code)]
    pub fn from(togs: u8, mt_bytes: Vec<u8>, fn_bytes: Option<Vec<u8>>) -> Self {
        let mt_cstring: CString = unsafe { CString::from_vec_unchecked(mt_bytes) };
        let fn_cstring = fn_bytes.map(|b| unsafe { CString::from_vec_unchecked(b) });

        JUMBFEmbeddedFileDescriptionBox {
            toggles: togs,          // media togles
            media_type: mt_cstring, // file media type
            file_name: fn_cstring,  // optional file name
        }
    }
}

// !SECTION

//---------------
// SECTION Box Reader
//---------------

#[allow(dead_code)]
const HEADER_SIZE: u64 = 8;
#[allow(dead_code)]
const TOGGLE_SIZE: u64 = 1;

/// method for getting the current position
#[allow(dead_code)]
pub fn current_pos<R: Seek>(seeker: &mut R) -> JumbfParseResult<u64> {
    Ok(seeker.stream_position()?)
}

/// method for skipping backwards `size` bytes
#[allow(dead_code)]
pub fn unread_bytes<S: Seek>(seeker: &mut S, size: u64) -> JumbfParseResult<()> {
    let new_loc = -(size as i64);
    seeker.seek(SeekFrom::Current(new_loc))?;
    Ok(())
}

/// macro for dealing with the type of a BMFF/JUMBF box
macro_rules! boxtype {
    ($( $name:ident => $value:expr ),*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum BoxType {
            $( $name, )*
            UnknownBox(u32),
        }

        impl From<u32> for BoxType {
            fn from(t: u32) -> BoxType {
                match t {
                    $( $value => BoxType::$name, )*
                    _ => BoxType::UnknownBox(t),
                }
            }
        }

    }
}

boxtype! {
    Empty => 0x0000_0000,
    Jumb => 0x6A75_6D62,
    Jumd => 0x6A75_6D64,
    Padding => 0x6672_6565,
    SaltHash => 0x6332_7368,
    Json => 0x6A73_6F6E,
    Uuid => 0x7575_6964,
    Jp2c => 0x6A70_3263,
    Cbor => 0x6362_6F72,
    EmbedMediaDesc => 0x6266_6462,
    EmbedContent => 0x6269_6462
}

// ANCHOR BlockHeader
/// class for storing the header of a block
pub struct BoxHeader {
    pub name: BoxType,
    pub size: u64,
}
impl BoxHeader {
    pub fn new(name: BoxType, size: u64) -> Self {
        Self { name, size }
    }
}

// ANCHOR BoxReader
/// class for reading BMFF/JUMBF boxes
pub struct BoxReader {}

impl BoxReader {
    #[allow(dead_code)]
    pub fn read_header<R: Read>(reader: &mut R) -> JumbfParseResult<BoxHeader> {
        // Create and read to buf.
        let mut buf = [0u8; 8]; // 8 bytes for box header.
        let bytes_read = reader.read(&mut buf)?;

        if bytes_read == 0 {
            // end of file!
            return Ok(BoxHeader::new(BoxType::Empty, 0));
        }

        // Get size.
        let s = buf[0..4]
            .try_into()
            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        let size = u32::from_be_bytes(s);

        // Get box type string.
        let t = buf[4..8]
            .try_into()
            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        let typ = u32::from_be_bytes(t);

        // Get large size if size is 1
        if size == 1 {
            reader.read_exact(&mut buf)?;
            let s = buf; //.try_into().unwrap();
            let large_size = u64::from_be_bytes(s);

            Ok(BoxHeader {
                name: BoxType::from(typ),
                size: large_size,
            })
        } else {
            Ok(BoxHeader {
                name: BoxType::from(typ),
                size: size as u64,
            })
        }
    }

    #[allow(dead_code)]
    pub fn read_desc_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFDescriptionBox> {
        let mut bytes_left = size;
        let mut uuid = [0u8; 16]; // 16 bytes for the UUID
        let bytes_read = reader.read(&mut uuid)?;
        if bytes_read == 0 {
            // end of file!
            return Ok(JUMBFDescriptionBox::new("", None));
        }
        bytes_left -= bytes_read as u64;

        let mut togs = [0u8]; // 1 byte of toggles
        reader.read_exact(&mut togs)?;
        bytes_left -= 1;

        let mut sbuf = Vec::with_capacity(64);
        if togs[0] & 0x03 == 0x03 {
            // must be requestable and labeled
            // read label
            loop {
                let mut buf = [0; 1];
                reader.read_exact(&mut buf)?;
                bytes_left -= 1;
                if buf[0] == 0x00 {
                    break;
                } else {
                    sbuf.push(buf[0]);
                }
            }
        } else {
            return Err(JumbfParseError::InvalidDescriptionBox);
        }

        // box id
        let bxid = if togs[0] & 0x04 == 0x04 {
            let idbuf = reader.read_u32::<BigEndian>()?;
            bytes_left -= 4;
            Some(idbuf)
        } else {
            None
        };

        // if there is a signature, we need to read it...
        let sig = if togs[0] & 0x08 == 0x08 {
            let mut sigbuf: [u8; 32] = [0; 32];
            reader.read_exact(&mut sigbuf)?;
            bytes_left -= 32;
            Some(sigbuf)
        } else {
            None
        };

        // read private box if necessary
        let private = if togs[0] & 0x10 == 0x10 {
            let header =
                BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
            if header.size == 0 {
                // bad read,
                return Err(JumbfParseError::InvalidBoxHeader);
            } else if header.size != bytes_left - HEADER_SIZE {
                // this means that we started w/o the header...
                unread_bytes(reader, HEADER_SIZE)?;
            }

            if header.name == BoxType::SaltHash {
                let data_len = header.size - HEADER_SIZE;
                let mut buf = vec![0u8; data_len as usize];
                reader.read_exact(&mut buf)?;

                bytes_left -= header.size;

                Some(CAISaltContentBox::new(buf))
            } else {
                return Err(JumbfParseError::InvalidBoxHeader);
            }
        } else {
            None
        };

        if bytes_left != HEADER_SIZE {
            // make sure we have consumed the entire box
            return Err(JumbfParseError::InvalidBoxHeader);
        }

        Ok(JUMBFDescriptionBox::from(
            &uuid, togs[0], sbuf, bxid, sig, private,
        ))
    }

    #[allow(dead_code)]
    pub fn read_json_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFJSONContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFJSONContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let json_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; json_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFJSONContentBox::new(buf))
    }

    #[allow(dead_code)]
    pub fn read_cbor_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFCBORContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFCBORContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let cbor_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; cbor_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFCBORContentBox::new(buf))
    }

    #[allow(dead_code)]
    pub fn read_padding_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFPaddingContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFPaddingContentBox::new(0));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let padding_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; padding_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFPaddingContentBox::new_with_vec(buf))
    }

    #[allow(dead_code)]
    pub fn read_jp2c_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFCodestreamContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFCodestreamContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // read the data itself...
        let data_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFCodestreamContentBox::new(buf))
    }

    #[allow(dead_code)]
    pub fn read_uuid_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFUUIDContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFUUIDContentBox::new(&[0u8; 16], Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // now read the UUID
        let mut uuid = [0u8; 16]; // 16 bytes of UUID
        reader.read_exact(&mut uuid)?;

        // and finally the data itself...
        let data_len = size - HEADER_SIZE - 16 /*UUID*/;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFUUIDContentBox::new(&uuid, buf))
    }

    #[allow(dead_code)]
    pub fn read_embedded_media_desc_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFEmbeddedFileDescriptionBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFEmbeddedFileDescriptionBox::new("".to_string(), None));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        //toggles: u8,                // media togles
        //media_type: CString,        // file media type
        //file_name: Option<CString>, // optional file name

        // now read the media_type
        let mut togs = [0u8]; // 1 byte of toggles
        reader.read_exact(&mut togs)?;

        // read the data itself...
        let data_len = size - HEADER_SIZE - TOGGLE_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        let (media_type, file_name) = match togs[0] {
            1 => {
                // there may be two c strings in this vec
                match buf.iter().position(|&x| x == 0) {
                    Some(pos) => {
                        if pos != buf.len() - 1 {
                            (buf, None)
                        } else {
                            let (first, second) = buf.split_at(pos);
                            (first.to_vec(), Some(second.to_vec()))
                        }
                    }
                    None => (buf, None),
                }
            }
            _ => {
                // we do not store the trailing 0 on load
                if buf[buf.len() - 1] == 0 {
                    buf.pop();
                }

                (buf, None)
            }
        };

        Ok(JUMBFEmbeddedFileDescriptionBox::from(
            togs[0], media_type, file_name,
        ))
    }

    #[allow(dead_code)]
    pub fn read_embedded_content_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFEmbeddedFileContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFEmbeddedFileContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // read data itself...
        let data_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFEmbeddedFileContentBox::new(buf))
    }

    #[allow(dead_code)]
    pub fn read_super_box<R: Read + Seek>(reader: &mut R) -> JumbfParseResult<JUMBFSuperBox> {
        // find out where we're starting...
        let start_pos = current_pos(reader).map_err(|_| JumbfParseError::InvalidBoxRange)?;

        // start with the initial jumb
        let jumb_header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidJumbfHeader)?;
        if jumb_header.name == BoxType::Empty {
            return Err(JumbfParseError::UnexpectedEof);
        } else if jumb_header.name != BoxType::Jumb {
            return Err(JumbfParseError::InvalidJumbfHeader);
        }

        // figure out where this particular box ends...
        let dest_pos = start_pos + jumb_header.size;

        // now let's load the jumd
        let jumd_header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::ExpectedJumdError)?;
        if jumb_header.name == BoxType::Empty {
            return Err(JumbfParseError::UnexpectedEof);
        } else if jumd_header.name != BoxType::Jumd {
            return Err(JumbfParseError::ExpectedJumdError);
        }

        // load the description box & create a new superbox from it
        let jdesc = BoxReader::read_desc_box(reader, jumd_header.size)
            .map_err(|_| JumbfParseError::UnexpectedEof)?;

        if jdesc.label().is_empty() {
            return Err(JumbfParseError::UnexpectedEof);
        }
        let box_label = jdesc.label();
        debug!(
            "{}",
            format!("START#Label: {box_label:?}" /* jdesc.label() */)
        );
        let mut sbox = JUMBFSuperBox::from(jdesc);

        // read each following box and add it to the sbox
        let mut found = true;
        while found {
            let box_header =
                BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidJumbfHeader)?;
            if box_header.name == BoxType::Empty {
                found = false;
            } else {
                unread_bytes(reader, HEADER_SIZE)?; // seek back to the beginning of the box
                let next_box: Box<dyn BMFFBox> = match box_header.name {
                    BoxType::Jumb => Box::new(
                        BoxReader::read_super_box(reader)?, //.map_err(|_| JumbfParseError::InvalidJumbBox)?,
                    ),
                    BoxType::Json => Box::new(
                        BoxReader::read_json_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidJsonBox)?,
                    ),
                    BoxType::Cbor => Box::new(
                        BoxReader::read_cbor_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidCborBox)?,
                    ),
                    BoxType::Padding => Box::new(
                        BoxReader::read_padding_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidCborBox)?,
                    ),
                    BoxType::Jp2c => Box::new(
                        BoxReader::read_jp2c_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidJp2cBox)?,
                    ),

                    BoxType::Uuid => Box::new(
                        BoxReader::read_uuid_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidUuidBox)?,
                    ),
                    BoxType::EmbedMediaDesc => Box::new(
                        BoxReader::read_embedded_media_desc_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidEmbeddedFileBox)?,
                    ),
                    BoxType::EmbedContent => Box::new(
                        BoxReader::read_embedded_content_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidEmbeddedFileBox)?,
                    ),
                    _ => {
                        debug!("{}", format!("Unknown Boxtype: {:?}", box_header.name));
                        // per the jumbf spec ignore unknown boxes so skip by if possible
                        let header = BoxReader::read_header(reader)
                            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
                        if header.size == 0 {
                            // bad read, return empty box...
                            return Err(JumbfParseError::InvalidUnknownBox);
                        } else if header.size != box_header.size {
                            // this means that we started w/o the header...
                            unread_bytes(reader, HEADER_SIZE)?;
                        }

                        // read data itself...
                        let data_len = box_header.size - HEADER_SIZE;
                        let mut buf = vec![0u8; data_len as usize];
                        reader.read_exact(&mut buf)?;
                        continue;
                    }
                };
                sbox.add_data_box(next_box);
            }

            // if our current position is past the size, bail out...
            if let Ok(p) = current_pos(reader) {
                if p >= dest_pos {
                    found = false;
                }
            }
        }

        debug!(
            "{}",
            format!("END#Label: {box_label:?}" /* jdesc.label() */)
        );

        // return the filled out sbox
        Ok(sbox)
    }
}

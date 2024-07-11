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

/// Converts a file extension to a MIME type
pub fn extension_to_mime(extension: &str) -> Option<&'static str> {
    Some(match extension {
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "psd" => "image/vnd.adobe.photoshop",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" => "video/mpeg",
        "mp4" => "video/mp4",
        "avi" => "video/avi",
        "avif" => "image/avif",
        "mov" | "qt" => "video/quicktime",
        "m4a" => "audio/mp4",
        "mid" | "rmi" => "audio/mid",
        "wav" => "audio/wav",
        "aif" | "aifc" | "aiff" => "audio/aiff",
        "ogg" => "audio/ogg",
        "ai" => "application/postscript",
        "arw" => "image/x-sony-arw",
        "nef" => "image/x-nikon-nef",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "application/c2pa",
        _ => return None,
    })
}

/// Convert a format to a MIME type
/// formats can be passed in as extensions, e.g. "jpg" or "jpeg"
/// or as MIME types, e.g. "image/jpeg"
pub fn format_to_mime(format: &str) -> String {
    match extension_to_mime(format) {
        Some(mime) => mime,
        None => format,
    }
    .to_string()
}

/// Return a MIME type given a file path.
///
/// This function will use the file extension to determine the MIME type.
pub fn format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    path.as_ref()
        .extension()
        .map(|ext| crate::utils::mime::format_to_mime(ext.to_string_lossy().as_ref()))
}

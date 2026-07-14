use super::super::read;
use super::display_path;
use flate2::read::ZlibDecoder;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const JPEG_SOI: &[u8; 2] = b"\xff\xd8";
const XMP_JPEG_HEADER: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const EXTENDED_XMP_JPEG_HEADER: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const PHOTOSHOP_HEADER: &[u8] = b"Photoshop 3.0\0";

#[derive(Clone, Copy)]
pub(super) enum ImageKind {
    Png,
    Jpeg,
    Tiff,
    Webp,
}

pub(super) struct Extraction {
    pub(super) chunks: Vec<Chunk>,
    pub(super) coverage_error: Option<SourceError>,
}

pub(super) fn probe_kind(path: &Path, ext: &str) -> Result<Option<ImageKind>, std::io::Error> {
    let candidate = if ext.eq_ignore_ascii_case("png") {
        ImageKind::Png
    } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
        ImageKind::Jpeg
    } else if ext.eq_ignore_ascii_case("tif") || ext.eq_ignore_ascii_case("tiff") {
        ImageKind::Tiff
    } else if ext.eq_ignore_ascii_case("webp") {
        ImageKind::Webp
    } else {
        return Ok(None);
    };
    let mut prefix = [0u8; 12];
    let read = read::read_file_prefix_safe(path, &mut prefix)?;
    let recognized = match candidate {
        ImageKind::Png => read >= 8 && &prefix[..8] == PNG_SIGNATURE,
        ImageKind::Jpeg => read >= 2 && &prefix[..2] == JPEG_SOI,
        ImageKind::Tiff => {
            read >= 4 && matches!(&prefix[..4], [b'I', b'I', 42, 0] | [b'M', b'M', 0, 42])
        }
        ImageKind::Webp => read >= 12 && &prefix[..4] == b"RIFF" && &prefix[8..12] == b"WEBP",
    };
    Ok(recognized.then_some(candidate))
}

pub(super) fn extract(
    path: &Path,
    kind: ImageKind,
    file_size: u64,
    mtime_ns: Option<u64>,
    max_size: u64,
) -> Result<Extraction, SourceError> {
    let mut file = read::open_file_safe(path).map_err(|error| {
        SourceError::Other(format!(
            "failed to scan image metadata for '{}': cannot open image ({error}); image metadata was not scanned",
            display_path(path)
        ))
    })?;
    let budget_u64 = super::extraction_total_budget(max_size).min(file_size);
    let budget = usize::try_from(budget_u64).map_err(|_| {
        image_error(
            path,
            "metadata extraction budget does not fit this platform",
        )
    })?;
    let mut collector = Collector {
        chunks: Vec::new(),
        path: display_path(path),
        mtime_ns,
        file_size,
        remaining: budget,
    };

    let result = match kind {
        ImageKind::Png => parse_png(&mut file, file_size, &mut collector),
        ImageKind::Jpeg => parse_jpeg(&mut file, file_size, &mut collector),
        ImageKind::Tiff => parse_tiff(&mut file, file_size, 0, &mut collector),
        ImageKind::Webp => parse_webp(&mut file, file_size, &mut collector),
    };
    let coverage_error = result.err().map(|reason| image_error(path, &reason));
    Ok(Extraction {
        chunks: collector.chunks,
        coverage_error,
    })
}

fn image_error(path: &Path, reason: &str) -> SourceError {
    SourceError::Other(format!(
        "failed to scan image metadata for '{}': {reason}; image metadata coverage is incomplete",
        display_path(path)
    ))
}

struct Collector {
    chunks: Vec<Chunk>,
    path: String,
    mtime_ns: Option<u64>,
    file_size: u64,
    remaining: usize,
}

impl Collector {
    fn emit(&mut self, source: &str, tag: &str, offset: u64, text: String) -> Result<(), String> {
        if text.is_empty() {
            return Ok(());
        }
        if text.len() > self.remaining {
            return Err(format!(
                "{tag} metadata exceeds the remaining {}-byte extraction budget",
                self.remaining
            ));
        }
        let base_offset = usize::try_from(offset)
            .map_err(|_| format!("{tag} metadata offset does not fit this platform"))?;
        self.remaining -= text.len();
        self.chunks.push(Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: format!("filesystem/image-metadata/{source}").into(),
                path: Some(format!("{}#metadata[{tag}@{offset}]", self.path).into()),
                base_offset,
                mtime_ns: self.mtime_ns,
                size_bytes: Some(self.file_size),
                ..Default::default()
            },
        });
        Ok(())
    }

    fn reserve_input(&self, tag: &str, size: usize) -> Result<(), String> {
        if size > self.remaining {
            Err(format!(
                "{tag} metadata declares {size} bytes, exceeding the remaining {}-byte extraction budget",
                self.remaining
            ))
        } else {
            Ok(())
        }
    }
}

fn parse_png<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let mut signature = [0u8; 8];
    read_exact(reader, &mut signature, "PNG signature")?;
    if &signature != PNG_SIGNATURE {
        return Err("invalid PNG signature".to_string());
    }

    let mut saw_iend = false;
    while position(reader)? < file_size {
        let chunk_start = position(reader)?;
        let mut header = [0u8; 8];
        read_exact(reader, &mut header, "PNG chunk header")?;
        let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| "invalid PNG length")?);
        let length_usize = usize::try_from(length).map_err(|_| "PNG chunk is too large")?;
        let payload_offset = chunk_start
            .checked_add(8)
            .ok_or("PNG chunk offset overflow")?;
        let chunk_end = payload_offset
            .checked_add(u64::from(length))
            .and_then(|end| end.checked_add(4))
            .ok_or("PNG chunk length overflow")?;
        if chunk_end > file_size {
            return Err(format!(
                "PNG chunk declares {length} payload bytes beyond the image boundary"
            ));
        }
        let kind: [u8; 4] = header[4..8]
            .try_into()
            .map_err(|_| "invalid PNG chunk type")?;

        match &kind {
            b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" => {
                let label = std::str::from_utf8(&kind).map_err(|_| "invalid PNG chunk type")?;
                collector.reserve_input(label, length_usize)?;
                let mut payload = vec![0u8; length_usize];
                read_exact(reader, &mut payload, "PNG metadata payload")?;
                match &kind {
                    b"tEXt" => parse_png_text(&payload, payload_offset, collector)?,
                    b"zTXt" => parse_png_ztxt(&payload, payload_offset, collector)?,
                    b"iTXt" => parse_png_itxt(&payload, payload_offset, collector)?,
                    b"eXIf" => {
                        let mut cursor = Cursor::new(payload);
                        parse_tiff(&mut cursor, u64::from(length), payload_offset, collector)?;
                    }
                    _ => return Err("PNG metadata chunk dispatch is inconsistent".to_string()),
                }
            }
            b"IEND" => {
                if length != 0 {
                    return Err("PNG IEND chunk is not empty".to_string());
                }
                saw_iend = true;
            }
            _ => seek_to(
                reader,
                chunk_end
                    .checked_sub(4)
                    .ok_or("PNG chunk offset underflow")?,
                "PNG chunk payload",
            )?,
        }
        seek_to(reader, chunk_end, "PNG chunk CRC")?;
        if saw_iend {
            break;
        }
    }
    if !saw_iend {
        return Err("PNG image has no IEND chunk".to_string());
    }
    Ok(())
}

fn parse_png_text(
    payload: &[u8],
    payload_offset: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let separator = find_nul(payload).ok_or("PNG tEXt chunk has no keyword separator")?;
    validate_png_keyword(&payload[..separator])?;
    let text_offset = checked_offset(payload_offset, separator + 1, "PNG tEXt")?;
    let text = latin1_to_string(&payload[separator + 1..]);
    collector.emit("png", "PNG:tEXt", text_offset, text)
}

fn parse_png_ztxt(
    payload: &[u8],
    payload_offset: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let separator = find_nul(payload).ok_or("PNG zTXt chunk has no keyword separator")?;
    validate_png_keyword(&payload[..separator])?;
    let method = *payload
        .get(separator + 1)
        .ok_or("PNG zTXt chunk has no compression method")?;
    if method != 0 {
        return Err("PNG zTXt chunk uses an unsupported compression method".to_string());
    }
    let compressed = payload
        .get(separator + 2..)
        .ok_or("PNG zTXt payload is truncated")?;
    let text = inflate_latin1(compressed, collector.remaining, "PNG zTXt")?;
    let offset = checked_offset(payload_offset, separator + 2, "PNG zTXt")?;
    collector.emit("png", "PNG:zTXt", offset, text)
}

fn parse_png_itxt(
    payload: &[u8],
    payload_offset: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let keyword_end = find_nul(payload).ok_or("PNG iTXt chunk has no keyword separator")?;
    validate_png_keyword(&payload[..keyword_end])?;
    let compression_flag = *payload
        .get(keyword_end + 1)
        .ok_or("PNG iTXt chunk has no compression flag")?;
    let method = *payload
        .get(keyword_end + 2)
        .ok_or("PNG iTXt chunk has no compression method")?;
    if compression_flag > 1 || method != 0 {
        return Err("PNG iTXt chunk has unsupported compression fields".to_string());
    }
    let language_start = keyword_end + 3;
    let language_end = find_nul(
        payload
            .get(language_start..)
            .ok_or("PNG iTXt language field is truncated")?,
    )
    .ok_or("PNG iTXt language field has no terminator")?
        + language_start;
    let translated_start = language_end + 1;
    let translated_end = find_nul(
        payload
            .get(translated_start..)
            .ok_or("PNG iTXt translated keyword is truncated")?,
    )
    .ok_or("PNG iTXt translated keyword has no terminator")?
        + translated_start;
    let text_start = translated_end + 1;
    let raw = payload
        .get(text_start..)
        .ok_or("PNG iTXt text is truncated")?;
    let text = if compression_flag == 0 {
        std::str::from_utf8(raw)
            .map_err(|_| "PNG iTXt text is not valid UTF-8")?
            .to_string()
    } else {
        inflate_utf8(raw, collector.remaining, "PNG iTXt")?
    };
    let offset = checked_offset(payload_offset, text_start, "PNG iTXt")?;
    let tag = if payload[..keyword_end] == *b"XML:com.adobe.xmp" {
        "XMP"
    } else {
        "PNG:iTXt"
    };
    let source = if tag == "XMP" { "xmp" } else { "png" };
    collector.emit(source, tag, offset, text)
}

fn parse_jpeg<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let mut soi = [0u8; 2];
    read_exact(reader, &mut soi, "JPEG SOI")?;
    if &soi != JPEG_SOI {
        return Err("invalid JPEG SOI marker".to_string());
    }

    loop {
        if position(reader)? >= file_size {
            return Err("JPEG ended before SOS or EOI".to_string());
        }
        let mut prefix = [0u8; 1];
        read_exact(reader, &mut prefix, "JPEG marker prefix")?;
        if prefix[0] != 0xff {
            return Err("JPEG contains bytes outside a marker segment".to_string());
        }
        let marker = loop {
            read_exact(reader, &mut prefix, "JPEG marker")?;
            if prefix[0] != 0xff {
                break prefix[0];
            }
        };
        if marker == 0xd9 || marker == 0xda {
            return Ok(());
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if marker == 0x00 {
            return Err("JPEG has an escaped byte outside entropy data".to_string());
        }
        let mut length_bytes = [0u8; 2];
        read_exact(reader, &mut length_bytes, "JPEG segment length")?;
        let segment_length = u16::from_be_bytes(length_bytes);
        if segment_length < 2 {
            return Err("JPEG segment length is smaller than its header".to_string());
        }
        let payload_length = usize::from(segment_length - 2);
        let payload_offset = position(reader)?;
        let segment_end = payload_offset
            .checked_add(u64::try_from(payload_length).map_err(|_| "JPEG length overflow")?)
            .ok_or("JPEG segment offset overflow")?;
        if segment_end > file_size {
            return Err("JPEG segment extends beyond the image boundary".to_string());
        }

        if marker == 0xe1 || marker == 0xed {
            collector.reserve_input("JPEG APP metadata", payload_length)?;
            let mut payload = vec![0u8; payload_length];
            read_exact(reader, &mut payload, "JPEG APP metadata")?;
            if marker == 0xe1 {
                parse_jpeg_app1(&payload, payload_offset, collector)?;
            } else {
                parse_jpeg_app13(&payload, payload_offset, collector)?;
            }
        } else {
            seek_to(reader, segment_end, "JPEG segment")?;
        }
    }
}

fn parse_jpeg_app1(
    payload: &[u8],
    payload_offset: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    if let Some(tiff) = payload.strip_prefix(b"Exif\0\0") {
        let mut cursor = Cursor::new(tiff);
        return parse_tiff(
            &mut cursor,
            u64::try_from(tiff.len()).map_err(|_| "EXIF length overflow")?,
            payload_offset
                .checked_add(6)
                .ok_or("JPEG EXIF provenance offset overflow")?,
            collector,
        );
    }
    if let Some(xmp) = payload.strip_prefix(XMP_JPEG_HEADER) {
        let text = std::str::from_utf8(xmp)
            .map_err(|_| "JPEG XMP packet is not valid UTF-8")?
            .to_string();
        return collector.emit(
            "xmp",
            "XMP",
            checked_offset(payload_offset, XMP_JPEG_HEADER.len(), "JPEG XMP")?,
            text,
        );
    }
    if payload.starts_with(EXTENDED_XMP_JPEG_HEADER) {
        return Err("extended JPEG XMP packets are not assembled".to_string());
    }
    Ok(())
}

fn parse_jpeg_app13(
    payload: &[u8],
    payload_offset: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let Some(mut cursor) = payload
        .strip_prefix(PHOTOSHOP_HEADER)
        .map(|_| PHOTOSHOP_HEADER.len())
    else {
        return Ok(());
    };
    while cursor < payload.len() {
        let signature_end = cursor.checked_add(4).ok_or("IPTC offset overflow")?;
        if payload.get(cursor..signature_end) != Some(b"8BIM") {
            return Err("Photoshop APP13 resource signature is malformed".to_string());
        }
        cursor = signature_end;
        let resource_id = read_be_u16_slice(payload, cursor, "Photoshop resource id")?;
        cursor = cursor.checked_add(2).ok_or("IPTC resource id overflow")?;
        let name_len = usize::from(
            *payload
                .get(cursor)
                .ok_or("Photoshop resource name is truncated")?,
        );
        let name_field = 1usize
            .checked_add(name_len)
            .ok_or("IPTC name length overflow")?;
        cursor = cursor
            .checked_add(name_field)
            .ok_or("IPTC name offset overflow")?;
        if name_field % 2 != 0 {
            cursor = cursor.checked_add(1).ok_or("IPTC name padding overflow")?;
        }
        let data_len = usize::try_from(read_be_u32_slice(
            payload,
            cursor,
            "Photoshop resource length",
        )?)
        .map_err(|_| "Photoshop resource length is too large")?;
        cursor = cursor
            .checked_add(4)
            .ok_or("IPTC resource length offset overflow")?;
        let data_end = cursor
            .checked_add(data_len)
            .ok_or("IPTC data length overflow")?;
        let data = payload
            .get(cursor..data_end)
            .ok_or("Photoshop resource data is truncated")?;
        if resource_id == 0x0404 {
            parse_iptc(
                data,
                checked_offset(payload_offset, cursor, "JPEG IPTC")?,
                collector,
            )?;
        }
        cursor = data_end;
        if data_len % 2 != 0 {
            cursor = cursor.checked_add(1).ok_or("IPTC data padding overflow")?;
        }
        if cursor > payload.len() {
            return Err("Photoshop resource padding is truncated".to_string());
        }
    }
    Ok(())
}

fn parse_iptc(data: &[u8], base_offset: u64, collector: &mut Collector) -> Result<(), String> {
    let mut cursor = 0usize;
    while cursor < data.len() {
        if data[cursor] != 0x1c {
            return Err("IPTC dataset marker is malformed".to_string());
        }
        let record = *data.get(cursor + 1).ok_or("IPTC record is truncated")?;
        let dataset = *data.get(cursor + 2).ok_or("IPTC dataset is truncated")?;
        cursor = cursor
            .checked_add(3)
            .ok_or("IPTC dataset header overflow")?;
        let initial = read_be_u16_slice(data, cursor, "IPTC dataset length")?;
        cursor = cursor
            .checked_add(2)
            .ok_or("IPTC dataset length offset overflow")?;
        let value_len = if initial & 0x8000 == 0 {
            usize::from(initial)
        } else {
            let length_bytes = usize::from(initial & 0x7fff);
            if !(1..=4).contains(&length_bytes) {
                return Err("IPTC extended dataset length is invalid".to_string());
            }
            let end = cursor
                .checked_add(length_bytes)
                .ok_or("IPTC length overflow")?;
            let raw = data
                .get(cursor..end)
                .ok_or("IPTC extended length is truncated")?;
            cursor = end;
            raw.iter().try_fold(0usize, |value, byte| {
                value
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or("IPTC extended length overflow")
            })?
        };
        let value_end = cursor
            .checked_add(value_len)
            .ok_or("IPTC value length overflow")?;
        let value = data
            .get(cursor..value_end)
            .ok_or("IPTC dataset value is truncated")?;
        let value_offset = checked_offset(base_offset, cursor, "IPTC value")?;
        if !value.is_empty() {
            let text = latin1_to_string(value);
            collector.emit(
                "iptc",
                &format!("IPTC:{record}:{dataset}"),
                value_offset,
                text,
            )?;
        }
        cursor = value_end;
    }
    Ok(())
}

fn parse_webp<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    let mut header = [0u8; 12];
    read_exact(reader, &mut header, "WebP header")?;
    if &header[..4] != b"RIFF" || &header[8..12] != b"WEBP" {
        return Err("invalid WebP RIFF header".to_string());
    }
    let riff_size = u64::from(u32::from_le_bytes(
        header[4..8].try_into().map_err(|_| "invalid WebP size")?,
    ));
    let riff_end = riff_size.checked_add(8).ok_or("WebP RIFF size overflow")?;
    if riff_end > file_size || riff_end < 12 {
        return Err("WebP RIFF size is outside the image boundary".to_string());
    }
    while position(reader)? < riff_end {
        let chunk_start = position(reader)?;
        let mut chunk_header = [0u8; 8];
        read_exact(reader, &mut chunk_header, "WebP chunk header")?;
        let length = u32::from_le_bytes(
            chunk_header[4..8]
                .try_into()
                .map_err(|_| "invalid WebP chunk length")?,
        );
        let payload_offset = chunk_start
            .checked_add(8)
            .ok_or("WebP chunk offset overflow")?;
        let padded = u64::from(length)
            .checked_add(u64::from(length % 2))
            .ok_or("WebP padded chunk length overflow")?;
        let chunk_end = payload_offset
            .checked_add(padded)
            .ok_or("WebP chunk length overflow")?;
        if chunk_end > riff_end {
            return Err("WebP chunk extends beyond the RIFF boundary".to_string());
        }
        match &chunk_header[..4] {
            b"EXIF" | b"XMP " => {
                let length_usize =
                    usize::try_from(length).map_err(|_| "WebP metadata is too large")?;
                collector.reserve_input("WebP metadata", length_usize)?;
                let mut payload = vec![0u8; length_usize];
                read_exact(reader, &mut payload, "WebP metadata")?;
                if &chunk_header[..4] == b"EXIF" {
                    let tiff = payload.strip_prefix(b"Exif\0\0").unwrap_or(&payload); // LAW10: optional EXIF signature absence preserves the whole payload for TIFF parsing.
                    let tiff_prefix = u64::try_from(payload.len() - tiff.len())
                        .map_err(|_| "WebP EXIF offset overflow")?;
                    let mut cursor = Cursor::new(tiff);
                    parse_tiff(
                        &mut cursor,
                        u64::try_from(tiff.len()).map_err(|_| "WebP EXIF length overflow")?,
                        payload_offset
                            .checked_add(tiff_prefix)
                            .ok_or("WebP EXIF provenance offset overflow")?,
                        collector,
                    )?;
                } else {
                    let text = std::str::from_utf8(&payload)
                        .map_err(|_| "WebP XMP packet is not valid UTF-8")?
                        .to_string();
                    collector.emit("xmp", "XMP", payload_offset, text)?;
                }
            }
            _ => seek_to(
                reader,
                payload_offset
                    .checked_add(u64::from(length))
                    .ok_or("WebP chunk offset overflow")?,
                "WebP chunk payload",
            )?,
        }
        seek_to(reader, chunk_end, "WebP chunk padding")?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn parse_tiff<R: Read + Seek>(
    reader: &mut R,
    region_len: u64,
    provenance_base: u64,
    collector: &mut Collector,
) -> Result<(), String> {
    ensure_region(0, 8, region_len, "TIFF header")?;
    seek_to(reader, 0, "TIFF header")?;
    let mut header = [0u8; 8];
    read_exact(reader, &mut header, "TIFF header")?;
    let endian = match &header[..2] {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return Err("TIFF byte order marker is invalid".to_string()),
    };
    if endian.u16(&header[2..4])? != 42 {
        return Err("TIFF magic is invalid".to_string());
    }
    let first_ifd = u64::from(endian.u32(&header[4..8])?);
    let mut pending = vec![first_ifd];
    let mut visited = HashSet::new();
    while let Some(ifd_offset) = pending.pop() {
        if ifd_offset == 0 {
            continue;
        }
        if !visited.insert(ifd_offset) {
            return Err(format!("TIFF IFD cycle detected at offset {ifd_offset}"));
        }
        ensure_region(ifd_offset, 2, region_len, "TIFF IFD count")?;
        let count = usize::from(read_u16_at(
            reader,
            ifd_offset,
            region_len,
            endian,
            "TIFF IFD count",
        )?);
        let entries_bytes = count
            .checked_mul(12)
            .ok_or("TIFF IFD entry count overflow")?;
        let entries_bytes_u64 =
            u64::try_from(entries_bytes).map_err(|_| "TIFF table is too large")?;
        let table_end = ifd_offset
            .checked_add(2)
            .and_then(|offset| offset.checked_add(entries_bytes_u64))
            .ok_or("TIFF IFD table overflow")?;
        let table_length = entries_bytes_u64
            .checked_add(6)
            .ok_or("TIFF IFD table length overflow")?;
        ensure_region(ifd_offset, table_length, region_len, "TIFF IFD table")?;

        for index in 0..count {
            let entry_delta = index.checked_mul(12).ok_or("TIFF entry offset overflow")?;
            let entry_offset = checked_offset(
                ifd_offset
                    .checked_add(2)
                    .ok_or("TIFF entry offset overflow")?,
                entry_delta,
                "TIFF entry",
            )?;
            let mut entry = [0u8; 12];
            read_at(
                reader,
                entry_offset,
                &mut entry,
                region_len,
                "TIFF IFD entry",
            )?;
            let tag = endian.u16(&entry[..2])?;
            let field_type = endian.u16(&entry[2..4])?;
            let field_count = u64::from(endian.u32(&entry[4..8])?);
            let unit = tiff_type_size(field_type).ok_or_else(|| {
                format!("TIFF tag {tag:#06x} uses unsupported field type {field_type}")
            })?;
            let byte_len = field_count
                .checked_mul(unit)
                .ok_or("TIFF field length overflow")?;
            let value_offset = if byte_len <= 4 {
                entry_offset
                    .checked_add(8)
                    .ok_or("TIFF inline value offset overflow")?
            } else {
                u64::from(endian.u32(&entry[8..12])?)
            };
            ensure_region(value_offset, byte_len, region_len, "TIFF field value")?;

            match tag {
                0x9286 => {
                    let value = read_tiff_value(
                        reader,
                        value_offset,
                        byte_len,
                        region_len,
                        collector,
                        "EXIF UserComment",
                    )?;
                    let (text, text_delta) = decode_user_comment(&value, endian)?;
                    let text_offset = checked_offset(
                        provenance_base
                            .checked_add(value_offset)
                            .ok_or("EXIF UserComment provenance offset overflow")?,
                        text_delta,
                        "EXIF UserComment text",
                    )?;
                    collector.emit("exif", "EXIF:UserComment", text_offset, text)?;
                }
                0x02bc => {
                    let value = read_tiff_value(
                        reader,
                        value_offset,
                        byte_len,
                        region_len,
                        collector,
                        "XMP",
                    )?;
                    let text = std::str::from_utf8(&value)
                        .map_err(|_| "TIFF XMP packet is not valid UTF-8")?
                        .trim_end_matches('\0')
                        .to_string();
                    collector.emit(
                        "xmp",
                        "XMP",
                        provenance_base
                            .checked_add(value_offset)
                            .ok_or("XMP provenance offset overflow")?,
                        text,
                    )?;
                }
                0x83bb => {
                    let value = read_tiff_value(
                        reader,
                        value_offset,
                        byte_len,
                        region_len,
                        collector,
                        "IPTC",
                    )?;
                    parse_iptc(
                        &value,
                        provenance_base
                            .checked_add(value_offset)
                            .ok_or("IPTC provenance offset overflow")?,
                        collector,
                    )?;
                }
                0x8769 | 0xa005 | 0x014a => {
                    let pointers = read_tiff_value(
                        reader,
                        value_offset,
                        byte_len,
                        region_len,
                        collector,
                        "TIFF IFD pointer",
                    )?;
                    let step =
                        usize::try_from(unit).map_err(|_| "TIFF pointer width is too large")?;
                    if step != 4 {
                        return Err(format!("TIFF IFD pointer tag {tag:#06x} is not LONG"));
                    }
                    for bytes in pointers.chunks_exact(step) {
                        pending.push(u64::from(endian.u32(bytes)?));
                    }
                }
                _ => {}
            }
        }
        let next = u64::from(read_u32_at(
            reader,
            table_end,
            region_len,
            endian,
            "TIFF next IFD",
        )?);
        if next != 0 {
            pending.push(next);
        }
    }
    Ok(())
}

fn read_tiff_value<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
    region_len: u64,
    collector: &Collector,
    tag: &str,
) -> Result<Vec<u8>, String> {
    let length = usize::try_from(length).map_err(|_| format!("{tag} value is too large"))?;
    collector.reserve_input(tag, length)?;
    let mut value = vec![0u8; length];
    read_at(reader, offset, &mut value, region_len, tag)?;
    Ok(value)
}

fn decode_user_comment(value: &[u8], endian: Endian) -> Result<(String, usize), String> {
    if value.len() < 8 {
        return Err("EXIF UserComment is shorter than its encoding prefix".to_string());
    }
    let (encoding, body) = value.split_at(8);
    if encoding == b"ASCII\0\0\0" || encoding == [0; 8] {
        return std::str::from_utf8(trim_trailing_nuls(body))
            .map(|text| (text.to_string(), 8))
            .map_err(|_| "EXIF UserComment ASCII payload is invalid".to_string());
    }
    if encoding == b"UNICODE\0" {
        let (mut body, order, text_delta) = if body.starts_with(&[0xff, 0xfe]) {
            (&body[2..], Endian::Little, 10)
        } else if body.starts_with(&[0xfe, 0xff]) {
            (&body[2..], Endian::Big, 10)
        } else {
            (body, endian, 8)
        };
        while body.ends_with(&[0, 0]) {
            body = &body[..body.len() - 2];
        }
        if body.len() % 2 != 0 {
            return Err("EXIF UserComment UTF-16 payload has an odd byte length".to_string());
        }
        let words: Result<Vec<u16>, String> =
            body.chunks_exact(2).map(|bytes| order.u16(bytes)).collect();
        return String::from_utf16(&words?)
            .map(|text| (text, text_delta))
            .map_err(|_| "EXIF UserComment UTF-16 payload is invalid".to_string());
    }
    if encoding.starts_with(b"JIS") {
        return Err("EXIF UserComment JIS encoding is unsupported".to_string());
    }
    Err("EXIF UserComment has an unknown encoding prefix".to_string())
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> Result<u16, String> {
        let bytes: [u8; 2] = bytes
            .try_into()
            .map_err(|_| "truncated 16-bit TIFF field")?;
        Ok(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(self, bytes: &[u8]) -> Result<u32, String> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| "truncated 32-bit TIFF field")?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }
}

fn tiff_type_size(field_type: u16) -> Option<u64> {
    match field_type {
        1 | 2 | 6 | 7 => Some(1),
        3 | 8 => Some(2),
        4 | 9 | 11 | 13 => Some(4),
        5 | 10 | 12 => Some(8),
        _ => None,
    }
}

fn read_u16_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    region_len: u64,
    endian: Endian,
    context: &str,
) -> Result<u16, String> {
    let mut bytes = [0u8; 2];
    read_at(reader, offset, &mut bytes, region_len, context)?;
    endian.u16(&bytes)
}

fn read_u32_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    region_len: u64,
    endian: Endian,
    context: &str,
) -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    read_at(reader, offset, &mut bytes, region_len, context)?;
    endian.u32(&bytes)
}

fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    output: &mut [u8],
    region_len: u64,
    context: &str,
) -> Result<(), String> {
    ensure_region(
        offset,
        u64::try_from(output.len()).map_err(|_| format!("{context} length overflow"))?,
        region_len,
        context,
    )?;
    seek_to(reader, offset, context)?;
    read_exact(reader, output, context)
}

fn ensure_region(offset: u64, length: u64, region_len: u64, context: &str) -> Result<(), String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("{context} offset overflow"))?;
    if end > region_len {
        Err(format!("{context} extends beyond the metadata boundary"))
    } else {
        Ok(())
    }
}

fn read_exact<R: Read>(reader: &mut R, output: &mut [u8], context: &str) -> Result<(), String> {
    reader
        .read_exact(output)
        .map_err(|error| format!("cannot read {context}: {error}"))
}

fn seek_to<S: Seek>(reader: &mut S, offset: u64, context: &str) -> Result<(), String> {
    reader
        .seek(SeekFrom::Start(offset))
        .map(|_| ())
        .map_err(|error| format!("cannot seek to {context}: {error}"))
}

fn position<S: Seek>(reader: &mut S) -> Result<u64, String> {
    reader
        .stream_position()
        .map_err(|error| format!("cannot read image position: {error}"))
}

fn checked_offset(base: u64, delta: usize, context: &str) -> Result<u64, String> {
    base.checked_add(u64::try_from(delta).map_err(|_| format!("{context} offset overflow"))?)
        .ok_or_else(|| format!("{context} offset overflow"))
}

fn find_nul(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|byte| *byte == 0)
}

fn validate_png_keyword(keyword: &[u8]) -> Result<(), String> {
    if keyword.is_empty() || keyword.len() > 79 {
        return Err("PNG text keyword length is outside 1..=79 bytes".to_string());
    }
    if keyword
        .iter()
        .any(|byte| *byte < 32 || (127..=160).contains(byte))
    {
        return Err("PNG text keyword contains a forbidden control byte".to_string());
    }
    Ok(())
}

fn latin1_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn inflate_latin1(input: &[u8], limit: usize, context: &str) -> Result<String, String> {
    inflate_bounded(input, limit, context).map(|bytes| latin1_to_string(&bytes))
}

fn inflate_utf8(input: &[u8], limit: usize, context: &str) -> Result<String, String> {
    let bytes = inflate_bounded(input, limit, context)?;
    String::from_utf8(bytes).map_err(|_| format!("{context} output is not valid UTF-8"))
}

fn inflate_bounded(input: &[u8], limit: usize, context: &str) -> Result<Vec<u8>, String> {
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1); // LAW10: recall-preserving bounded conversion saturates only on wider-than-u64 targets; the reader retains the largest representable stream cap.
    let mut decoder = ZlibDecoder::new(input).take(read_limit);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|error| format!("cannot decompress {context}: {error}"))?;
    if output.len() > limit {
        return Err(format!(
            "{context} output exceeds the {limit}-byte extraction budget"
        ));
    }
    Ok(output)
}

fn trim_trailing_nuls(mut bytes: &[u8]) -> &[u8] {
    while bytes.last() == Some(&0) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn read_be_u16_slice(bytes: &[u8], offset: usize, context: &str) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("{context} offset overflow"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| format!("{context} is truncated"))?
        .try_into()
        .map_err(|_| format!("{context} is truncated"))?;
    Ok(u16::from_be_bytes(raw))
}

fn read_be_u32_slice(bytes: &[u8], offset: usize, context: &str) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("{context} offset overflow"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| format!("{context} is truncated"))?
        .try_into()
        .map_err(|_| format!("{context} is truncated"))?;
    Ok(u32::from_be_bytes(raw))
}

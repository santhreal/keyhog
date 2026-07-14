use flate2::write::ZlibEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;
use std::io::Write;

fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(payload);
    chunk.extend_from_slice(&[0; 4]);
    chunk
}

fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    image.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    for chunk in chunks {
        image.extend_from_slice(chunk);
    }
    image.extend_from_slice(&png_chunk(b"IEND", &[]));
    image
}

fn jpeg_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0xff, marker];
    segment.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn webp_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut chunk = kind.to_vec();
    chunk.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    chunk.extend_from_slice(payload);
    if payload.len() % 2 != 0 {
        chunk.push(0);
    }
    chunk
}

fn webp(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = b"WEBP".to_vec();
    for chunk in chunks {
        body.extend_from_slice(chunk);
    }
    let mut image = b"RIFF".to_vec();
    image.extend_from_slice(&(body.len() as u32).to_le_bytes());
    image.extend_from_slice(&body);
    image
}

fn exif_user_comment(comment: &str) -> Vec<u8> {
    let mut value = b"ASCII\0\0\0".to_vec();
    value.extend_from_slice(comment.as_bytes());
    exif_user_comment_value(&value)
}

fn exif_user_comment_value(value: &[u8]) -> Vec<u8> {
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x8769u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&26u32.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x9286u16.to_le_bytes());
    tiff.extend_from_slice(&7u16.to_le_bytes());
    tiff.extend_from_slice(&(value.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&44u32.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(value);

    let mut payload = b"Exif\0\0".to_vec();
    payload.extend_from_slice(&tiff);
    payload
}

fn photoshop_iptc(value: &str) -> Vec<u8> {
    let mut dataset = vec![0x1c, 2, 120];
    dataset.extend_from_slice(&(value.len() as u16).to_be_bytes());
    dataset.extend_from_slice(value.as_bytes());

    let mut payload = b"Photoshop 3.0\0".to_vec();
    payload.extend_from_slice(b"8BIM");
    payload.extend_from_slice(&0x0404u16.to_be_bytes());
    payload.extend_from_slice(&[0, 0]);
    payload.extend_from_slice(&(dataset.len() as u32).to_be_bytes());
    payload.extend_from_slice(&dataset);
    if dataset.len() % 2 != 0 {
        payload.push(0);
    }
    payload
}

fn jpeg_with_metadata(exif: &str, xmp: &str, iptc: &str) -> Vec<u8> {
    let mut jpeg = vec![0xff, 0xd8];
    jpeg.extend_from_slice(&jpeg_segment(0xe1, &exif_user_comment(exif)));
    let mut xmp_payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    xmp_payload.extend_from_slice(xmp.as_bytes());
    jpeg.extend_from_slice(&jpeg_segment(0xe1, &xmp_payload));
    jpeg.extend_from_slice(&jpeg_segment(0xed, &photoshop_iptc(iptc)));
    jpeg.extend_from_slice(&[0xff, 0xd9]);
    jpeg
}

fn jpeg_with_unicode_exif(comment: &str) -> Vec<u8> {
    let mut value = b"UNICODE\0".to_vec();
    value.extend_from_slice(&[0xff, 0xfe]);
    for word in comment.encode_utf16() {
        value.extend_from_slice(&word.to_le_bytes());
    }
    let mut jpeg = vec![0xff, 0xd8];
    jpeg.extend_from_slice(&jpeg_segment(0xe1, &exif_user_comment_value(&value)));
    jpeg.extend_from_slice(&[0xff, 0xd9]);
    jpeg
}

#[test]
fn jpeg_exif_xmp_iptc_and_png_text_emit_tagged_metadata_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let exif = "EXIF_SECRET=ghp_ExifMetadataToken000000000000001";
    let xmp = "<x:xmpmeta>XMP_SECRET=ghp_XmpMetadataToken0000000000000002</x:xmpmeta>";
    let iptc = "IPTC_SECRET=ghp_IptcMetadataToken000000000000003";
    fs::write(
        dir.path().join("photo.jpg"),
        jpeg_with_metadata(exif, xmp, iptc),
    )
    .unwrap();
    let unicode_exif = "UNICODE_SECRET=ghp_UnicodeExifToken00000000000007";
    fs::write(
        dir.path().join("unicode.jpg"),
        jpeg_with_unicode_exif(unicode_exif),
    )
    .unwrap();

    let text = "PNG_SECRET=ghp_PngTextMetadataToken00000000000004";
    let mut text_payload = b"Comment\0".to_vec();
    text_payload.extend_from_slice(text.as_bytes());
    let png_xmp = "<x:xmpmeta>ghp_PngXmpMetadataToken000000000000005</x:xmpmeta>";
    let mut itxt = b"XML:com.adobe.xmp\0\0\0\0\0".to_vec();
    itxt.extend_from_slice(png_xmp.as_bytes());
    let compressed_text = "ghp_PngCompressedTextToken0000000000000006";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(compressed_text.as_bytes()).unwrap();
    let mut ztxt = b"Comment\0\0".to_vec();
    ztxt.extend_from_slice(&encoder.finish().unwrap());
    let png_exif = "ghp_PngExifMetadataToken00000000000000008";
    let png_exif_payload = exif_user_comment(png_exif);
    fs::write(
        dir.path().join("graphic.png"),
        png(&[
            png_chunk(b"tEXt", &text_payload),
            png_chunk(b"iTXt", &itxt),
            png_chunk(b"zTXt", &ztxt),
            png_chunk(b"eXIf", &png_exif_payload[6..]),
        ]),
    )
    .unwrap();
    let webp_xmp = "<x:xmpmeta>ghp_WebpXmpMetadataToken000000000000009</x:xmpmeta>";
    fs::write(
        dir.path().join("photo.webp"),
        webp(&[webp_chunk(b"XMP ", webp_xmp.as_bytes())]),
    )
    .unwrap();

    let chunks = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for expected in [
        exif,
        xmp,
        iptc,
        unicode_exif,
        text,
        png_xmp,
        compressed_text,
        png_exif,
        webp_xmp,
    ] {
        assert!(
            chunks.iter().any(|chunk| chunk.data.contains(expected)),
            "metadata value was not recovered: {expected}"
        );
    }
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "filesystem/image-metadata/exif"
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("EXIF:UserComment@64"))
            && chunk.metadata.base_offset == 64
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.data.contains(unicode_exif)
            && chunk.metadata.base_offset == 66
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("EXIF:UserComment@66"))
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "filesystem/image-metadata/iptc"
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("IPTC:2:120@"))
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "filesystem/image-metadata/png"
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("PNG:tEXt@"))
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.data.contains(webp_xmp)
            && chunk.metadata.source_type.as_ref() == "filesystem/image-metadata/xmp"
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.contains("XMP@"))
    }));
}

#[test]
fn image_pixel_bytes_are_never_scanned_as_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let pixel_secret = "ghp_PixelOnlyTokenMustNeverBeMetadata0000001";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&[0]).unwrap();
    encoder.write_all(pixel_secret.as_bytes()).unwrap();
    let idat = encoder.finish().unwrap();
    fs::write(
        dir.path().join("pixels.png"),
        png(&[png_chunk(b"IDAT", &idat)]),
    )
    .unwrap();
    let jpeg_pixel_secret = "ghp_JpegPixelOnlyTokenMustNeverBeMetadata00002";
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xda, 0, 2];
    jpeg.extend_from_slice(jpeg_pixel_secret.as_bytes());
    jpeg.extend_from_slice(&[0xff, 0xd9]);
    fs::write(dir.path().join("pixels.jpg"), jpeg).unwrap();
    let webp_pixel_secret = "ghp_WebpPixelOnlyTokenMustNeverBeMetadata0003";
    fs::write(
        dir.path().join("pixels.webp"),
        webp(&[webp_chunk(b"VP8 ", webp_pixel_secret.as_bytes())]),
    )
    .unwrap();
    let tiff_pixel_secret = "ghp_TiffPixelOnlyTokenMustNeverBeMetadata0004";
    let mut tiff = b"II".to_vec();
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x0111u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&26u32.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(tiff_pixel_secret.as_bytes());
    fs::write(dir.path().join("pixels.tiff"), tiff).unwrap();

    let chunks = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(chunks.is_empty(), "pixel payload emitted scan chunks");
    assert!(!chunks.iter().any(|chunk| chunk.data.contains(pixel_secret)));
    assert!(!chunks
        .iter()
        .any(|chunk| chunk.data.contains(jpeg_pixel_secret)));
    assert!(!chunks
        .iter()
        .any(|chunk| chunk.data.contains(webp_pixel_secret)));
    assert!(!chunks
        .iter()
        .any(|chunk| chunk.data.contains(tiff_pixel_secret)));
}

#[test]
fn cyclic_tiff_ifd_fails_visibly_without_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let mut tiff = b"II".to_vec();
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&0u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());
    fs::write(dir.path().join("cycle.tiff"), tiff).unwrap();

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    assert_eq!(rows.len(), 1);
    let error = rows[0].as_ref().unwrap_err().to_string();
    assert!(
        error.contains("IFD cycle detected"),
        "unexpected error: {error}"
    );
    assert!(error.contains("coverage is incomplete"));
}

#[test]
fn malformed_and_oversized_png_metadata_fail_visibly_without_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let mut oversized = b"\x89PNG\r\n\x1a\n".to_vec();
    oversized.extend_from_slice(&u32::MAX.to_be_bytes());
    oversized.extend_from_slice(b"tEXt");
    fs::write(dir.path().join("oversized.png"), oversized).unwrap();

    let mut malformed = b"\x89PNG\r\n\x1a\n".to_vec();
    malformed.extend_from_slice(&3u32.to_be_bytes());
    malformed.extend_from_slice(b"tEXt");
    malformed.extend_from_slice(b"bad");
    fs::write(dir.path().join("malformed.png"), malformed).unwrap();

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&vec![b'a'; 64 * 1024]).unwrap();
    let mut bomb = b"Comment\0\0".to_vec();
    bomb.extend_from_slice(&encoder.finish().unwrap());
    fs::write(
        dir.path().join("compressed-bomb.png"),
        png(&[png_chunk(b"zTXt", &bomb)]),
    )
    .unwrap();

    let partial_secret = "ghp_ValidMetadataBeforeMalformedTag00000000010";
    let mut partial_payload = b"Comment\0".to_vec();
    partial_payload.extend_from_slice(partial_secret.as_bytes());
    let mut partial = png(&[png_chunk(b"tEXt", &partial_payload)]);
    partial.truncate(partial.len() - png_chunk(b"IEND", &[]).len());
    partial.extend_from_slice(&u32::MAX.to_be_bytes());
    partial.extend_from_slice(b"tEXt");
    fs::write(dir.path().join("partial.png"), partial).unwrap();

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().any(|row| {
        row.as_ref()
            .is_ok_and(|chunk| chunk.data.contains(partial_secret))
    }));
    let errors: Vec<_> = rows
        .into_iter()
        .filter_map(|row| row.err().map(|error| error.to_string()))
        .collect();
    assert_eq!(errors.len(), 4);
    assert!(errors
        .iter()
        .all(|error| error.contains("coverage is incomplete")));
    assert!(errors.iter().any(|error| error.contains("4294967295")));
    assert!(errors.iter().any(|error| error.contains("boundary")));
    assert!(errors
        .iter()
        .any(|error| error.contains("output exceeds") && error.contains("extraction budget")));
}

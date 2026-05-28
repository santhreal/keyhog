//! Zip archives whose cumulative uncompressed size exceeds 4× max_file_size
//! must abort extraction before later entries are read (zip-bomb budget).

use std::io::Write;

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_bomb_4x_budget_aborts_before_late_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("bomb.zip");
    let file = File::create(&zip_path).expect("create zip");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for i in 0..3 {
        let name = format!("part{i}.txt");
        zip.start_file(name, opts).expect("start");
        let body = vec![b'Z'; 400];
        zip.write_all(&body).expect("write");
    }
    zip.start_file("secret.env", opts).expect("start secret");
    zip.write_all(b"LEAK=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("write secret");
    zip.finish().expect("finish");

    std::fs::write(dir.path().join("outside.txt"), "OUTSIDE=ok\n").expect("outside");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(256);
    let bodies: Vec<String> = source
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    assert!(
        bodies.iter().any(|b| b.contains("OUTSIDE=ok")),
        "walk must continue after zip-bomb abort"
    );
    assert!(
        !bodies.iter().any(|b| b.contains("LEAK=AKIAQYLPMN5HFIQR7XYA")),
        "entry past 4× budget must never be extracted; got {bodies:?}"
    );
}

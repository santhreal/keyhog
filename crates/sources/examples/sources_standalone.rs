use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::path::PathBuf;

fn main() {
    let source = FilesystemSource::new(PathBuf::from(".")).with_max_file_size(1024 * 1024);
    let chunk_count = source.chunks().take(5).filter_map(Result::ok).count();

    println!("source={}", source.name());
    println!("sampled_chunks={chunk_count}");
}

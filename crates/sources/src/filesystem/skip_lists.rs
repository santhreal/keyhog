/// File extensions to skip (binary, images, etc.).
pub(super) const SKIP_EXTENSIONS: &[&str] = &[
    // Images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "ico",
    "cur",
    "icns",
    "webp",
    "svg",
    // Audio/Video
    "mp3",
    "mp4",
    "avi",
    "mov",
    "mkv",
    "flac",
    "wav",
    "ogg",
    "webm",
    // Archives (binary — `.zip` is handled by the archive-unpack branch
    // with symlink guard + 4× zip-bomb budget; see `archive.rs`.)
    "tar",
    // gz / zst / lz4 / sz are handled by `extract_compressed_chunks`
    // below, NOT skipped — earlier versions had them in this list,
    // which silently bypassed the streaming-decompression path.
    "tgz",
    "bz2",
    "xz",
    "rar",
    "7z",
    // Native binaries
    "exe",
    "dll",
    "so",
    "dylib",
    "o",
    "a",
    "lib",
    "obj",
    // Compiled/bytecode
    "class",
    "wasm",
    "pyc",
    "pyo",
    "elc",
    "beam",
    // Documents (binary formats)
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    // Fonts
    "ttf",
    "otf",
    "woff",
    "woff2",
    "eot",
    // Database files
    "db",
    "sqlite",
    "sqlite3",
    // Disk images / firmware
    "iso",
    "img",
    "bin",
    "rom",
    // Serialized data (not human-authored)
    "pickle",
    "npy",
    "npz",
    "onnx",
    "pb",
    "tflite",
    "pt",
    "safetensors",
];

/// Directories to skip entirely.
pub(super) const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    "swagger-ui",
    "swagger",
];

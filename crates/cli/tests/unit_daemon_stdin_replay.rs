//! The automatic daemon route owns stdin before IPC. Its in-process retry must
//! use the same bounded payload, not attempt to read the consumed pipe again.
//! This drives the real CLI source factory with the replay field and checks the
//! exact source bytes, metadata, and lossy UTF-8 contract.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi, API};

#[test]
fn buffered_stdin_replay_uses_one_source_with_exact_lossy_decoding() {
    let mut args =
        ScanArgs::try_parse_from(["scan", "--stdin"]).expect("stdin scan arguments must parse");
    let bytes = b"prefix=ok\xff\nsecret=AKIAQYLPM5HFIQR7XYA\n".to_vec();
    API.set_buffered_stdin(&mut args, bytes);

    let sources = API
        .build_sources(&args, Vec::new(), None)
        .expect("buffered stdin source must build");
    assert_eq!(
        sources.len(),
        1,
        "stdin replay must not add a filesystem source"
    );
    let chunks = sources[0]
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("buffered stdin must decode within the default limit");
    assert_eq!(chunks.len(), 1, "stdin is one logical source chunk");
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "stdin");
    assert_eq!(chunks[0].metadata.path, None);
    assert_eq!(
        chunks[0].data.as_ref(),
        "prefix=ok\u{fffd}\nsecret=AKIAQYLPM5HFIQR7XYA\n",
        "replay must match the normal lossy UTF-8 stdin decoder exactly"
    );
}

/// WHY: a failed daemon request can replay the full bounded stdin body in
/// process; retaining one whole decoded copy would make peak memory scale at
/// twice the input size instead of one shared body plus one scan window.
#[test]
fn buffered_stdin_replay_emits_bounded_overlapping_windows() {
    const WINDOW: usize = keyhog_core::DEFAULT_WINDOW_SIZE_BYTES;
    const OVERLAP: usize = keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES;
    let mut args =
        ScanArgs::try_parse_from(["scan", "--stdin"]).expect("stdin scan arguments must parse");
    let mut bytes = vec![b'a'; WINDOW + 16];
    bytes[100] = b'\n';
    bytes[200] = b'\n';
    bytes[WINDOW - 10] = b'\n';
    API.set_buffered_stdin(&mut args, bytes.clone());

    let sources = API
        .build_sources(&args, Vec::new(), None)
        .expect("buffered stdin source must build");
    let chunks = sources[0]
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("bounded buffered stdin must decode");

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].data.len(), WINDOW);
    assert_eq!(chunks[0].metadata.base_offset, 0);
    assert_eq!(chunks[0].metadata.base_line, 0);
    assert_eq!(chunks[1].metadata.base_offset, WINDOW - OVERLAP);
    assert_eq!(chunks[1].metadata.base_line, 2);
    assert_eq!(
        chunks[1].data.as_bytes(),
        &bytes[WINDOW - OVERLAP..],
        "the retry window must preserve the exact overlap and trailing bytes"
    );
}

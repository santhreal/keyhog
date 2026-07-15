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

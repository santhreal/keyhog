//! Single encoded blob in one assignment yields one spliced decode output.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn single_assignment_yields_one_spliced_decode() {
    let blob = "c2stcHJvai1hYmMxMjM=";
    let text = format!("token={blob}");
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let sk_count = decoded
        .iter()
        .filter(|c| c.data.contains("sk-proj-abc123"))
        .count();
    assert_eq!(
        sk_count, 1,
        "single encoded blob must produce exactly one spliced decode chunk"
    );
}

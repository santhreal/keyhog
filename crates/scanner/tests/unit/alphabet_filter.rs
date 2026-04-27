use keyhog_scanner::alphabet_filter::{AlphabetMask, AlphabetScreen};
use proptest::prelude::*;

proptest! {
    #[test]
    fn proptest_mask_correctness(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let scalar_mask = AlphabetMask::from_bytes_scalar(&bytes);
        let simd_mask = AlphabetMask::from_bytes(&bytes);
        assert_eq!(scalar_mask, simd_mask, "SIMD mask must match scalar mask exactly");
    }
}

#[test]
fn test_mask_intersection() {
    let m1 = AlphabetMask::from_text("abc");
    let m2 = AlphabetMask::from_text("def");
    let m3 = AlphabetMask::from_text("cde");

    assert!(!m1.intersects(&m2));
    assert!(m1.intersects(&m3)); // 'c'
    assert!(m2.intersects(&m3)); // 'd', 'e'
}

#[test]
fn test_alphabet_screen() {
    let screen = AlphabetScreen::new(&["AKIA".to_string(), "ghp_".to_string()]);

    // Positive cases
    assert!(screen.screen(b"some AKIA key"));
    assert!(screen.screen(b"ghp_token"));

    // Negative cases
    assert!(!screen.screen(b"1234567890!@#$%^&*()"));
    assert!(!screen.screen(b"qrzvujmwx")); // none of a,k,i,g,h,p,_
}

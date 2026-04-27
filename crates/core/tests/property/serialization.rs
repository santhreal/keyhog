use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use proptest::prelude::*;
use std::borrow::Cow;
use std::collections::HashMap;

proptest! {
    #[test]
    fn prop_verified_finding_roundtrip_json(
        id in "\\PC*",
        name in "\\PC*",
        serv in "\\PC*",
        cred in "\\PC*",
    ) {
        let finding = VerifiedFinding {
            detector_id: id.clone().into(),
            detector_name: name.clone().into(),
            service: serv.clone().into(),
            severity: Severity::High,
            credential_redacted: Cow::Owned(cred.clone()),
            credential_hash: "hash".to_string(),
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.txt".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: VerificationResult::Live,
            metadata: HashMap::new(),
            additional_locations: Vec::new(),
            confidence: Some(0.9),
        };

        let json = serde_json::to_string(&finding).unwrap();
        let decompiled: VerifiedFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(finding.detector_id, decompiled.detector_id);
        assert_eq!(finding.credential_redacted, decompiled.credential_redacted);
    }
}

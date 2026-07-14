use super::{reset_resident_presence_slot, GpuResidentPresenceSlot};

#[test]
fn calibration_reset_preserves_an_unhealthy_resident_slot() {
    let slot = std::sync::Mutex::new(GpuResidentPresenceSlot::Failed(
        "driver cleanup fault".to_string(),
    ));

    let error = reset_resident_presence_slot(&slot)
        .expect_err("an unhealthy resident slot must remain a visible calibration failure");
    assert!(error.contains("driver cleanup fault"));
    assert!(matches!(
        slot.into_inner().expect("unpoisoned slot"),
        GpuResidentPresenceSlot::Failed(reason) if reason == "driver cleanup fault"
    ));
}

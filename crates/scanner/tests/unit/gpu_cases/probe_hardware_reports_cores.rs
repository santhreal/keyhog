use keyhog_scanner::hw_probe::testing::probe_hardware;
#[test]
fn probe_hardware_reports_cores() {
    let caps = probe_hardware();
    assert!(caps.physical_cores >= 1);
    assert!(caps.logical_cores >= 1);
}

use auditd_ebpf_common::permission::PermissionMask;

#[test]
fn linux_audit_bits_and_display_order_are_stable() {
    assert_eq!(PermissionMask::EXEC.bits(), 1);
    assert_eq!(PermissionMask::WRITE.bits(), 2);
    assert_eq!(PermissionMask::READ.bits(), 4);
    assert_eq!(PermissionMask::ATTR.bits(), 8);

    let mask = PermissionMask::from_bits(0b1111).unwrap();
    assert_eq!(mask.to_string(), "rwxa");
}

#[test]
fn intersections_and_unknown_bits_are_explicit() {
    let rw = PermissionMask::READ | PermissionMask::WRITE;
    assert!(rw.intersects(PermissionMask::READ));
    assert!(!rw.intersects(PermissionMask::EXEC));
    assert_eq!(rw & PermissionMask::WRITE, PermissionMask::WRITE);
    assert!(PermissionMask::from_bits(0x10).is_none());
    assert!(PermissionMask::EMPTY.is_empty());
}

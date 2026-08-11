use super::ProcessCache;

pub fn on_mount_boundary_change(cache: &mut ProcessCache, syscall: &str, success: bool) {
    if success
        && matches!(
            syscall,
            "mount"
                | "umount2"
                | "move_mount"
                | "mount_setattr"
                | "chroot"
                | "pivot_root"
                | "setns"
                | "unshare"
        )
    {
        cache.invalidate_mounts();
    }
}

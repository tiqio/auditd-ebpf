use super::ProcessCache;

pub fn on_mount_boundary_change(cache: &mut ProcessCache, tid: u32, syscall: &str, success: bool) {
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
        let _ = cache.invalidate_process_mounts(tid);
    }
}

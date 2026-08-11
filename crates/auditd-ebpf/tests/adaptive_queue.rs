use std::time::Duration;

use auditd_ebpf::output::adaptive_queue::{
    AdaptiveQueue, DEFAULT_INITIAL_BYTES, DEFAULT_MAX_BYTES, QueueError, QueueState,
};

#[test]
fn 默认容量符合生产契约() {
    let queue = AdaptiveQueue::with_defaults();

    assert_eq!(queue.limit_bytes(), DEFAULT_INITIAL_BYTES);
    assert_eq!(queue.max_bytes(), DEFAULT_MAX_BYTES);
    assert_eq!(queue.used_bytes(), 0);
    assert_eq!(queue.state(), QueueState::Normal);
}

#[test]
fn 连续三个高水位窗口后容量倍增() {
    let mut queue = AdaptiveQueue::new(100, 400).unwrap();
    queue.try_push(vec![0; 80]).unwrap();

    queue.observe_window(Duration::from_secs(1));
    queue.observe_window(Duration::from_secs(1));
    assert_eq!(queue.limit_bytes(), 100);

    queue.observe_window(Duration::from_secs(1));
    assert_eq!(queue.limit_bytes(), 200);
    assert_eq!(queue.state(), QueueState::Growing);
}

#[test]
fn 低水位持续十分钟后逐级缩容但不低于初始值() {
    let mut queue = AdaptiveQueue::new(100, 400).unwrap();
    queue.try_push(vec![0; 81]).unwrap();
    for _ in 0..3 {
        queue.observe_window(Duration::from_secs(1));
    }
    assert_eq!(queue.limit_bytes(), 200);
    while queue.pop().is_some() {}

    queue.observe_window(Duration::from_secs(599));
    assert_eq!(queue.limit_bytes(), 200);
    queue.observe_window(Duration::from_secs(1));
    assert_eq!(queue.limit_bytes(), 100);

    queue.observe_window(Duration::from_secs(600));
    assert_eq!(queue.limit_bytes(), 100);
}

#[test]
fn 达到硬上限时丢弃新记录且不破坏已有队列() {
    let mut queue = AdaptiveQueue::new(16, 32).unwrap();
    queue.try_push(vec![1; 24]).unwrap();
    let before = queue.used_bytes();

    assert_eq!(queue.try_push(vec![2; 9]), Err(QueueError::AtHardLimit));
    assert_eq!(queue.used_bytes(), before);
    assert_eq!(queue.dropped_total(), 1);
    assert_eq!(queue.state(), QueueState::Dropping);
    assert_eq!(queue.pop(), Some(vec![1; 24]));
}

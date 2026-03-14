use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::threat::ThreatEvent;

/// A simple publish-subscribe event bus for distributing ThreatEvents
/// to multiple consumers (alerting, response engine, storage, etc.).
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ThreatEvent>,
}

impl EventBus {
    /// Create a new EventBus with the given channel capacity.
    /// If the channel fills up, the oldest events are dropped for slow receivers.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Create a new subscriber that will receive events published after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<ThreatEvent> {
        self.sender.subscribe()
    }

    /// Publish a threat event to all current subscribers.
    /// Returns Ok with the number of receivers that received the event.
    /// Returns Err if there are no active subscribers.
    pub fn publish(&self, event: ThreatEvent) -> Result<usize> {
        debug!(
            event_id = %event.id,
            threat_type = %event.threat_type,
            severity = %event.severity,
            "Publishing threat event to event bus"
        );
        self.sender
            .send(event)
            .context("Failed to publish event: no active subscribers")
    }

    /// Publish a threat event, ignoring the error if there are no subscribers.
    /// This is useful during startup when subscribers may not be registered yet.
    pub fn try_publish(&self, event: ThreatEvent) {
        match self.sender.send(event) {
            Ok(count) => {
                debug!(receiver_count = count, "Event published successfully");
            }
            Err(_) => {
                warn!("No active subscribers on event bus; event was dropped");
            }
        }
    }

    /// Return the current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::threat::ThreatType;

    #[tokio::test]
    async fn test_publish_subscribe() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        let event = ThreatEvent::new(ThreatType::PortScan, "test", "Test event");
        let expected_id = event.id.clone();

        bus.publish(event).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, expected_id);
        assert_eq!(received.threat_type, ThreatType::PortScan);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = ThreatEvent::new(ThreatType::SynFlood, "test", "Flood detected");
        let count = bus.publish(event).unwrap();
        assert_eq!(count, 2);

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.id, e2.id);
    }

    #[test]
    fn test_no_subscribers() {
        let bus = EventBus::new(16);
        let event = ThreatEvent::new(ThreatType::BruteForce, "test", "No listeners");
        assert!(bus.publish(event).is_err());
    }

    #[test]
    fn test_try_publish_no_subscribers() {
        let bus = EventBus::new(16);
        let event = ThreatEvent::new(ThreatType::BruteForce, "test", "No listeners");
        // Should not panic
        bus.try_publish(event);
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new(16);
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        drop(_rx1);
        assert_eq!(bus.subscriber_count(), 1);
    }
}

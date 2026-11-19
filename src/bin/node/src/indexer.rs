//! Indexed event and state views over applied chain data (issue #86).
//!
//! The indexer appends every event emitted by an applied block to an
//! append-only log and retains the state root observed at each block, so
//! API-facing queries can be served without re-deriving chain history.

use std::collections::HashMap;

use workstream_core::types::{BlockNumber, Event, StateRoot};

/// Append-only event log with per-block state snapshots, exposed as API-friendly
/// views over chain data (issue #86).
#[derive(Debug, Default)]
pub struct EventIndexer {
    events: Vec<Event>,
    state_roots: HashMap<BlockNumber, StateRoot>,
}

impl EventIndexer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an applied block: its observed state root and emitted events.
    ///
    /// Events are appended in block order; the state root snapshot is keyed
    /// by block height for historical state queries.
    pub fn record(&mut self, block_number: BlockNumber, state_root: StateRoot, events: Vec<Event>) {
        for event in events {
            self.events.push(event);
        }
        self.state_roots.insert(block_number, state_root);
    }

    /// Events emitted by a block, in emission order.
    pub fn events(&self, block_number: BlockNumber) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| e.block_number == block_number)
            .collect()
    }

    /// All recorded events, in block order.
    pub fn all_events(&self) -> &[Event] {
        &self.events
    }

    /// Events of a given type across the indexed chain.
    pub fn events_by_type(&self, event_type: &str) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// State root observed after applying a block, if indexed.
    pub fn state_root_at(&self, block_number: BlockNumber) -> Option<StateRoot> {
        self.state_roots.get(&block_number).cloned()
    }

    /// Number of indexed events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether any block has been indexed yet.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_core::hash::H256;

    fn event(block: u64, tx_index: u32, event_type: &str) -> Event {
        Event {
            event_type: event_type.to_string(),
            data: vec![1, 2, 3],
            block_number: block,
            tx_index,
        }
    }

    fn state_root() -> StateRoot {
        StateRoot::new(H256::ZERO, H256::ZERO)
    }

    #[test]
    fn indexer_appends_events_per_block() {
        let mut indexer = EventIndexer::new();
        assert!(indexer.is_empty());
        assert_eq!(indexer.len(), 0);

        indexer.record(1, state_root(), vec![event(1, 0, "actor.registered")]);
        indexer.record(2, state_root(), vec![event(2, 0, "project.created")]);

        assert_eq!(indexer.len(), 2);
        assert_eq!(indexer.events(1).len(), 1);
        assert_eq!(indexer.events(2).len(), 1);
        assert_eq!(indexer.all_events().len(), 2);
        assert_eq!(indexer.events(99).len(), 0);
    }

    #[test]
    fn indexer_filters_events_by_type() {
        let mut indexer = EventIndexer::new();
        indexer.record(1, state_root(), vec![event(1, 0, "actor.registered")]);
        indexer.record(
            2,
            state_root(),
            vec![event(2, 0, "actor.registered"), event(2, 1, "task.created")],
        );

        let registered = indexer.events_by_type("actor.registered");
        assert_eq!(registered.len(), 2);
        assert!(registered
            .iter()
            .all(|e| e.event_type == "actor.registered"));
        assert!(indexer.events_by_type("missing.type").is_empty());
    }

    #[test]
    fn indexer_tracks_state_roots_per_block() {
        let mut indexer = EventIndexer::new();
        assert!(indexer.state_root_at(1).is_none());
        indexer.record(
            1,
            StateRoot::new(H256::from_bytes([9u8; 32]), H256::ZERO),
            vec![],
        );
        assert!(indexer.state_root_at(1).is_some());
        assert!(indexer.state_root_at(2).is_none());
    }
}

use crate::chatwidget::ChatWidget;
use crate::chatwidget::ThreadInputState;
use codex_protocol::ThreadId;
use codex_protocol::items::TurnItem;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

#[path = "app/pending_interactive_replay.rs"]
mod pending_interactive_replay;

use pending_interactive_replay::PendingInteractiveReplayState;

#[derive(Debug, Clone)]
pub(crate) struct ThreadEventSnapshot {
    pub(crate) session_configured: Option<Event>,
    pub(crate) events: Vec<Event>,
    pub(crate) input_state: Option<ThreadInputState>,
}

#[derive(Debug)]
pub(crate) struct ThreadEventStore {
    pub(crate) session_configured: Option<Event>,
    buffer: VecDeque<Event>,
    user_message_ids: HashSet<String>,
    pending_interactive_replay: PendingInteractiveReplayState,
    pub(crate) input_state: Option<ThreadInputState>,
    capacity: usize,
    pub(crate) active: bool,
}

impl ThreadEventStore {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            session_configured: None,
            buffer: VecDeque::new(),
            user_message_ids: HashSet::new(),
            pending_interactive_replay: PendingInteractiveReplayState::default(),
            input_state: None,
            capacity,
            active: false,
        }
    }

    pub(crate) fn new_with_session_configured(capacity: usize, event: Event) -> Self {
        let mut store = Self::new(capacity);
        store.session_configured = Some(event);
        store
    }

    pub(crate) fn push_event(&mut self, event: Event) {
        self.pending_interactive_replay.note_event(&event);
        match &event.msg {
            EventMsg::SessionConfigured(_) => {
                self.session_configured = Some(event);
                return;
            }
            EventMsg::ItemCompleted(completed) => {
                if let TurnItem::UserMessage(item) = &completed.item {
                    if !event.id.is_empty() && self.user_message_ids.contains(&event.id) {
                        return;
                    }
                    let legacy = Event {
                        id: event.id,
                        msg: item.as_legacy_event(),
                    };
                    self.push_legacy_event(legacy);
                    return;
                }
            }
            _ => {}
        }

        self.push_legacy_event(event);
    }

    fn push_legacy_event(&mut self, event: Event) {
        if let EventMsg::UserMessage(_) = &event.msg
            && !event.id.is_empty()
            && !self.user_message_ids.insert(event.id.clone())
        {
            return;
        }
        self.buffer.push_back(event);
        if self.buffer.len() > self.capacity
            && let Some(removed) = self.buffer.pop_front()
        {
            self.pending_interactive_replay.note_evicted_event(&removed);
            if matches!(removed.msg, EventMsg::UserMessage(_)) && !removed.id.is_empty() {
                self.user_message_ids.remove(&removed.id);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> ThreadEventSnapshot {
        let mut pending_interactive_replay = self.pending_interactive_replay.clone();
        ThreadEventSnapshot {
            session_configured: self.session_configured.clone(),
            events: self
                .buffer
                .iter()
                .filter(|event| pending_interactive_replay.should_replay_snapshot_event(event))
                .cloned()
                .collect(),
            input_state: self.input_state.clone(),
        }
    }

    pub(crate) fn note_outbound_op(&mut self, op: &Op) {
        self.pending_interactive_replay.note_outbound_op(op);
    }

    pub(crate) fn op_can_change_pending_replay_state(op: &Op) -> bool {
        PendingInteractiveReplayState::op_can_change_state(op)
    }

    pub(crate) fn event_can_change_pending_thread_approvals(event: &Event) -> bool {
        PendingInteractiveReplayState::event_can_change_pending_thread_approvals(event)
    }

    pub(crate) fn has_pending_thread_approvals(&self) -> bool {
        self.pending_interactive_replay
            .has_pending_thread_approvals()
    }
}

#[derive(Debug)]
pub(crate) struct ThreadEventChannel {
    pub(crate) sender: mpsc::Sender<Event>,
    pub(crate) receiver: Option<mpsc::Receiver<Event>>,
    pub(crate) store: Arc<Mutex<ThreadEventStore>>,
}

impl ThreadEventChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self {
            sender,
            receiver: Some(receiver),
            store: Arc::new(Mutex::new(ThreadEventStore::new(capacity))),
        }
    }

    pub(crate) fn new_with_session_configured(capacity: usize, event: Event) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self {
            sender,
            receiver: Some(receiver),
            store: Arc::new(Mutex::new(ThreadEventStore::new_with_session_configured(
                capacity, event,
            ))),
        }
    }
}

pub(crate) async fn set_thread_active(
    thread_event_channels: &mut HashMap<ThreadId, ThreadEventChannel>,
    thread_id: ThreadId,
    active: bool,
) {
    if let Some(channel) = thread_event_channels.get_mut(&thread_id) {
        let mut store = channel.store.lock().await;
        store.active = active;
    }
}

pub(crate) async fn activate_thread_channel(
    thread_event_channels: &mut HashMap<ThreadId, ThreadEventChannel>,
    active_thread_id: &mut Option<ThreadId>,
    active_thread_rx: &mut Option<mpsc::Receiver<Event>>,
    thread_id: ThreadId,
) {
    if active_thread_id.is_some() {
        return;
    }
    set_thread_active(thread_event_channels, thread_id, true).await;
    let receiver = if let Some(channel) = thread_event_channels.get_mut(&thread_id) {
        channel.receiver.take()
    } else {
        None
    };
    *active_thread_id = Some(thread_id);
    *active_thread_rx = receiver;
}

pub(crate) async fn store_active_thread_receiver(
    thread_event_channels: &mut HashMap<ThreadId, ThreadEventChannel>,
    active_thread_id: Option<ThreadId>,
    active_thread_rx: &mut Option<mpsc::Receiver<Event>>,
    chat_widget: &ChatWidget,
) {
    let Some(active_id) = active_thread_id else {
        return;
    };
    let input_state = chat_widget.capture_thread_input_state();
    if let Some(channel) = thread_event_channels.get_mut(&active_id) {
        let receiver = active_thread_rx.take();
        let mut store = channel.store.lock().await;
        store.active = false;
        store.input_state = input_state;
        if let Some(receiver) = receiver {
            channel.receiver = Some(receiver);
        }
    }
}

pub(crate) async fn activate_thread_for_replay(
    thread_event_channels: &mut HashMap<ThreadId, ThreadEventChannel>,
    thread_id: ThreadId,
) -> Option<(mpsc::Receiver<Event>, ThreadEventSnapshot)> {
    let channel = thread_event_channels.get_mut(&thread_id)?;
    let receiver = channel.receiver.take()?;
    let mut store = channel.store.lock().await;
    store.active = true;
    let snapshot = store.snapshot();
    Some((receiver, snapshot))
}

pub(crate) async fn clear_active_thread(
    thread_event_channels: &mut HashMap<ThreadId, ThreadEventChannel>,
    active_thread_id: &mut Option<ThreadId>,
    active_thread_rx: &mut Option<mpsc::Receiver<Event>>,
) {
    if let Some(active_id) = active_thread_id.take() {
        set_thread_active(thread_event_channels, active_id, false).await;
    }
    *active_thread_rx = None;
}

pub(crate) fn drain_active_thread_events(
    active_thread_rx: &mut Option<mpsc::Receiver<Event>>,
    mut handle_event_now: impl FnMut(Event),
) -> bool {
    let Some(mut rx) = active_thread_rx.take() else {
        return false;
    };

    let mut disconnected = false;
    loop {
        match rx.try_recv() {
            Ok(event) => handle_event_now(event),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }

    if !disconnected {
        *active_thread_rx = Some(rx);
    }

    disconnected
}

pub(crate) fn prepare_thread_snapshot_replay(
    chat_widget: &mut ChatWidget,
    snapshot: ThreadEventSnapshot,
) -> Vec<Event> {
    let mut events = Vec::with_capacity(
        snapshot.events.len() + usize::from(snapshot.session_configured.is_some()),
    );
    if let Some(event) = snapshot.session_configured {
        events.push(event);
    }
    chat_widget.set_queue_autosend_suppressed(true);
    chat_widget.restore_thread_input_state(snapshot.input_state);
    events.extend(snapshot.events);
    events
}

pub(crate) fn finish_thread_snapshot_replay(
    chat_widget: &mut ChatWidget,
    resume_restored_queue: bool,
) {
    chat_widget.set_queue_autosend_suppressed(false);
    if resume_restored_queue {
        chat_widget.maybe_send_next_queued_input();
    }
}

// Sample Rust for knowledge graph extraction
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Idle,
    Authenticating,
    Active,
    Terminated,
}

pub struct Config {
    pub max_sessions: usize,
    pub timeout_secs: u64,
}

pub struct SessionManager {
    sessions: HashMap<String, Session>,
    config: Config,
    state: SessionState,
    counter: Arc<Mutex<u64>>,
}

pub struct Session {
    pub id: String,
    pub user: String,
    pub state: SessionState,
}

pub trait Authenticator {
    fn verify(&self, token: &str) -> bool;
    fn revoke(&mut self, session_id: &str);
}

impl SessionManager {
    pub fn new(config: Config) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            config,
            state: SessionState::Idle,
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub fn create_session(&mut self, user: &str, token: &str) -> Option<String> {
        if self.sessions.len() >= self.config.max_sessions {
            return None;
        }
        let id = self.generate_id();
        let session = Session {
            id: id.clone(),
            user: user.to_string(),
            state: SessionState::Active,
        };
        self.sessions.insert(id.clone(), session);
        self.state = SessionState::Active;
        Some(id)
    }

    pub fn terminate_session(&mut self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.state = SessionState::Terminated;
            self.cleanup_session(session_id);
            true
        } else {
            false
        }
    }

    fn generate_id(&self) -> String {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        format!("session_{}", counter)
    }

    fn cleanup_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        if self.sessions.is_empty() {
            self.state = SessionState::Idle;
        }
    }

    pub fn get_active_count(&self) -> usize {
        self.sessions.values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }
}

impl Authenticator for SessionManager {
    fn verify(&self, token: &str) -> bool {
        !token.is_empty() && self.state == SessionState::Active
    }

    fn revoke(&mut self, session_id: &str) {
        self.terminate_session(session_id);
    }
}

// Free function with unsafe
pub unsafe fn raw_copy(dst: *mut u8, src: *const u8, len: usize) {
    std::ptr::copy_nonoverlapping(src, dst, len);
}

// Inline module with struct and function inside
mod helpers {
    pub struct Helper {
        pub name: String,
    }

    pub fn helper_init() -> Helper {
        Helper { name: String::new() }
    }
}

// Async function
pub async fn fetch_data(url: &str) -> String {
    url.to_string()
}

// Macro definition
macro_rules! log_event {
    ($msg:expr) => {
        println!("{}", $msg);
    };
}

// Function with explicit lifetime parameters
pub fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// Generic struct
pub struct Cache<T: Clone + Send> {
    pub items: Vec<T>,
}

// Generic function with where clause
pub fn process<T, U>(input: T) -> U where T: Into<U>, U: Default {
    input.into()
}

// Write-only field test (for H6 reads_state fix)
pub struct Counter {
    value: u64,
    read_field: u64,
}

impl Counter {
    pub fn reset(&mut self) {
        self.value = 0;
    }

    pub fn get_read(&self) -> u64 {
        self.read_field
    }
}

//! DFA lexer table compilation.
//!
//! Converts a list of token regexes into a deterministic finite
//! automaton with one transition row per state and per character class.
//! Emission format matches what `vyre-libs::parsing::lexer` expects:
//!
//! ```text
//! dfa_transitions[state * NUM_CLASSES + class] =
//!   (next_state << 16) | action
//!
//! dfa_token_ids[state] = token_kind_emitted_on_enter   // 0 if non-accepting
//! ```
//!
//! `action` values:
//!  - 0 = CONTINUE (advance to next_state, consume the byte)
//!  - 1 = EMIT_TOKEN (emit token of kind `dfa_token_ids[state]`, reset to state 0)
//!  - 2 = PUSH_BACK (emit previous accepting state's token, don't consume this byte)
//!  - 3 = ERROR

use regex_automata::MatchKind;
use serde::{Deserialize, Serialize};

/// DFA action on a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Action {
    /// Advance to next_state, consume byte.
    Continue = 0,
    /// Emit a token of `dfa_token_ids[state]`, reset to initial state.
    EmitToken = 1,
    /// Emit previous accepting token, keep the current byte for re-lex.
    PushBack = 2,
    /// Hard error — unrecognized input.
    Error = 3,
}

/// Packed 32-bit transition: `(next_state << 16) | action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// State to advance to on this (state, class) pair.
    pub next_state: u16,
    /// What to do with the byte.
    pub action: Action,
}

impl Transition {
    /// Pack into a single u32 ready for the GPU.
    #[must_use]
    pub fn pack(self) -> u32 {
        (u32::from(self.next_state) << 16) | (self.action as u32)
    }

    /// Unpack a u32 back to the structured form.
    #[must_use]
    pub fn unpack(word: u32) -> Self {
        let next_state = (word >> 16) as u16;
        let action = match word & 0xFFFF {
            0 => Action::Continue,
            1 => Action::EmitToken,
            2 => Action::PushBack,
            _ => Action::Error,
        };
        Self { next_state, action }
    }
}

/// The compiled DFA: dense row-major transition table + per-state
/// accepting-token id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DfaTable {
    /// Number of states.
    pub num_states: u32,
    /// Number of input character classes.
    pub num_classes: u32,
    /// Flat transitions, row-major: `[state][class] =
    /// transitions[state * num_classes + class]`.
    pub transitions: Vec<u32>,
    /// One u32 per state. `token_ids[state] = 0` means non-accepting.
    pub token_ids: Vec<u32>,
}

impl DfaTable {
    /// Get the transition for `(state, class)`.
    #[must_use]
    pub fn transition(&self, state: u32, class: u32) -> Transition {
        let idx = (state * self.num_classes + class) as usize;
        Transition::unpack(self.transitions[idx])
    }

    /// Set the transition for `(state, class)`.
    pub fn set_transition(&mut self, state: u32, class: u32, t: Transition) {
        let idx = (state * self.num_classes + class) as usize;
        self.transitions[idx] = t.pack();
    }
}

/// Builder-side API for populating a DFA table without the index math.
#[derive(Debug, Clone)]
pub struct DfaBuilder {
    table: DfaTable,
    patterns: Vec<(u32, String)>,
}

impl DfaBuilder {
    /// Allocate a zero-initialized DFA with `num_states × num_classes`
    /// transitions all set to `Action::Error` and every state
    /// non-accepting.
    #[must_use]
    pub fn new(num_states: u32, num_classes: u32) -> Self {
        let size = (num_states * num_classes) as usize;
        let error_word = Transition {
            next_state: 0,
            action: Action::Error,
        }
        .pack();
        Self {
            table: DfaTable {
                num_states,
                num_classes,
                transitions: vec![error_word; size],
                token_ids: vec![0; num_states as usize],
            },
            patterns: Vec::new(),
        }
    }

    /// Add a regex pattern to the builder for the given token_id.
    pub fn add_pattern(&mut self, token_id: u32, pattern: &str) {
        self.patterns.push((token_id, pattern.to_string()));
    }

    /// Record `(state, class) -> next_state` with `Action::Continue`.
    pub fn continue_to(&mut self, state: u32, class: u32, next_state: u32) {
        self.table.set_transition(
            state,
            class,
            Transition {
                next_state: u16::try_from(next_state).expect("next_state fits in u16"),
                action: Action::Continue,
            },
        );
    }

    /// Mark `state` as accepting with token id `token_id`.
    pub fn accept(&mut self, state: u32, token_id: u32) {
        self.table.token_ids[state as usize] = token_id;
    }

    /// Finalize. Uses [`MatchKind::All`] for historical GPU / `SGGC` blob parity.
    #[must_use]
    pub fn build(self) -> DfaTable {
        self.build_with_match_kind(MatchKind::All)
    }

    /// Finalize with a given [`MatchKind`]. Use [`MatchKind::LeftmostFirst`] for
    /// host max-munch lexing; the default [`build`](Self::build) keeps `All`.
    #[must_use]
    pub fn build_with_match_kind(self, kind: MatchKind) -> DfaTable {
        if self.patterns.is_empty() {
            return self.table;
        }

        use regex_automata::dfa::{dense, Automaton};
        use regex_automata::Input;

        let anchored_regexes: Vec<String> = self
            .patterns
            .iter()
            .map(|(_, p)| format!("^(?:{p})"))
            .collect();
        let regexes: Vec<&str> = anchored_regexes.iter().map(String::as_str).collect();
        let dfa = dense::Builder::new()
            .configure(dense::Config::new().match_kind(kind))
            .build_many(&regexes)
            .expect("failed to compile regex patterns to DFA");

        let input = Input::new("");
        let start_id = dfa
            .start_state_forward(&input)
            .expect("must have start state");

        let mut state_queue = vec![start_id];
        let mut id_to_idx = std::collections::HashMap::new();
        id_to_idx.insert(start_id, 0u32);

        let mut i = 0;
        while i < state_queue.len() {
            let id = state_queue[i];
            i += 1;
            for byte in 0..=255u8 {
                let next_id = dfa.next_state(id, byte);
                if let std::collections::hash_map::Entry::Vacant(e) = id_to_idx.entry(next_id) {
                    e.insert(state_queue.len() as u32);
                    state_queue.push(next_id);
                }
            }
        }

        let num_states = state_queue.len();
        let num_classes = 256;
        let size = num_states * num_classes;
        let error_word = Transition {
            next_state: 0,
            action: Action::Error,
        }
        .pack();

        let mut table = DfaTable {
            num_states: num_states as u32,
            num_classes: num_classes as u32,
            transitions: vec![error_word; size],
            token_ids: vec![0; num_states],
        };

        for (state_idx, &id) in state_queue.iter().enumerate() {
            let is_match = dfa.is_match_state(id);
            if is_match {
                let match_count = dfa.match_len(id);
                if match_count > 0 {
                    let pat_idx = dfa.match_pattern(id, 0).as_usize();
                    table.token_ids[state_idx] = self.patterns[pat_idx].0;
                }
            }

            for byte in 0..=255u8 {
                let next_id = dfa.next_state(id, byte);
                let next_idx = id_to_idx[&next_id];

                let action = if dfa.is_dead_state(next_id) || dfa.is_quit_state(next_id) {
                    Action::Error
                } else {
                    Action::Continue
                };

                table.set_transition(
                    state_idx as u32,
                    byte as u32,
                    Transition {
                        next_state: next_idx as u16,
                        action,
                    },
                );
            }
        }

        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_pack_unpack_preserves_fields() {
        for action in [
            Action::Continue,
            Action::EmitToken,
            Action::PushBack,
            Action::Error,
        ] {
            for &next in &[0u16, 1, 42, 1000, u16::MAX] {
                let t = Transition {
                    next_state: next,
                    action,
                };
                let got = Transition::unpack(t.pack());
                assert_eq!(got.next_state, next);
                assert_eq!(got.action, action);
            }
        }
    }

    #[test]
    fn builder_default_row_is_error() {
        let b = DfaBuilder::new(4, 8);
        let table = b.build();
        assert_eq!(table.num_states, 4);
        assert_eq!(table.num_classes, 8);
        for &t in &table.transitions {
            assert_eq!(Transition::unpack(t).action, Action::Error);
        }
    }

    #[test]
    fn builder_continue_populates_cell() {
        let mut b = DfaBuilder::new(4, 8);
        b.continue_to(1, 3, 2);
        let table = b.build();
        let got = table.transition(1, 3);
        assert_eq!(got.next_state, 2);
        assert_eq!(got.action, Action::Continue);
    }

    #[test]
    fn builder_accept_sets_token_id() {
        let mut b = DfaBuilder::new(4, 8);
        b.accept(2, 42);
        let table = b.build();
        assert_eq!(table.token_ids[2], 42);
    }
}

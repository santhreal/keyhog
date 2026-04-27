//! LR(1) action + goto table compilation.
//!
//! 0.6 scaffolding: data types + emitter + a trivial two-token smoke
//! grammar that lets downstream `vyre-libs::parsing::lr_table` unit
//! tests run end-to-end against a non-trivial table before the full
//! C11 grammar generator lands (Phase L4).

use serde::{Deserialize, Serialize};

/// Encoded LR action. Packed as `(tag << 28) | payload` in a u32:
///
/// - `0 << 28 | payload` = SHIFT to state `payload`
/// - `1 << 28 | payload` = REDUCE by production `payload`
/// - `2 << 28 | 0`       = ACCEPT
/// - `3 << 28 | 0`       = ERROR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Action {
    /// Shift to next state.
    Shift(u32),
    /// Reduce by production id.
    Reduce(u32),
    /// Accept.
    Accept,
    /// Error — unrecognized token in current state.
    Error,
}

impl Action {
    /// Pack into a u32.
    #[must_use]
    pub fn pack(self) -> u32 {
        match self {
            Action::Shift(state) => state & 0x0FFF_FFFF,
            Action::Reduce(prod) => (1u32 << 28) | (prod & 0x0FFF_FFFF),
            Action::Accept => 2u32 << 28,
            Action::Error => 3u32 << 28,
        }
    }

    /// Unpack a u32 back.
    #[must_use]
    pub fn unpack(word: u32) -> Self {
        let tag = word >> 28;
        let payload = word & 0x0FFF_FFFF;
        match tag {
            0 => Action::Shift(payload),
            1 => Action::Reduce(payload),
            2 => Action::Accept,
            _ => Action::Error,
        }
    }
}

/// Production rule — LHS nonterminal + number of symbols on the RHS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Production {
    /// Nonterminal symbol produced.
    pub lhs: u32,
    /// Number of symbols popped on reduce.
    pub rhs_len: u32,
}

/// The compiled LR(1) tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LrTable {
    /// Number of parser states.
    pub num_states: u32,
    /// Number of terminals (token kinds).
    pub num_tokens: u32,
    /// Number of nonterminals.
    pub num_nonterminals: u32,
    /// `action[state * num_tokens + token] = Action::pack(..)`.
    pub action: Vec<u32>,
    /// `goto[state * num_nonterminals + nt] = next_state (or u32::MAX)`.
    pub goto: Vec<u32>,
    /// Production rules indexed by production id.
    pub productions: Vec<Production>,
}

impl LrTable {
    /// Look up the action for `(state, token)`.
    #[must_use]
    pub fn action_at(&self, state: u32, token: u32) -> Action {
        let idx = (state * self.num_tokens + token) as usize;
        Action::unpack(self.action[idx])
    }

    /// Look up the goto for `(state, nonterminal)`. `u32::MAX` = no goto.
    #[must_use]
    pub fn goto_at(&self, state: u32, nt: u32) -> u32 {
        let idx = (state * self.num_nonterminals + nt) as usize;
        self.goto[idx]
    }
}

/// Builder — 0.6 scaffolding. Populates a trivial smoke grammar that
/// recognizes `(A B)*` over two terminals.
pub struct LrBuilder {
    table: LrTable,
}

impl LrBuilder {
    /// Allocate an empty table with all actions = ERROR and all gotos
    /// = u32::MAX.
    #[must_use]
    pub fn new(num_states: u32, num_tokens: u32, num_nonterminals: u32) -> Self {
        let action_size = (num_states * num_tokens) as usize;
        let goto_size = (num_states * num_nonterminals) as usize;
        Self {
            table: LrTable {
                num_states,
                num_tokens,
                num_nonterminals,
                action: vec![Action::Error.pack(); action_size],
                goto: vec![u32::MAX; goto_size],
                productions: Vec::new(),
            },
        }
    }

    /// Set `action[state][token]`.
    pub fn set_action(&mut self, state: u32, token: u32, action: Action) {
        let idx = (state * self.table.num_tokens + token) as usize;
        self.table.action[idx] = action.pack();
    }

    /// Set `goto[state][nt] = next_state`.
    pub fn set_goto(&mut self, state: u32, nt: u32, next_state: u32) {
        let idx = (state * self.table.num_nonterminals + nt) as usize;
        self.table.goto[idx] = next_state;
    }

    /// Add a production rule and return its id.
    pub fn add_production(&mut self, lhs: u32, rhs_len: u32) -> u32 {
        let id = u32::try_from(self.table.productions.len()).expect("production count fits u32");
        self.table.productions.push(Production { lhs, rhs_len });
        id
    }

    /// Finalize.
    #[must_use]
    pub fn build(self) -> LrTable {
        self.table
    }
}

/// Build the smoke grammar: `S -> (A B)*` over two
/// terminals `T_A = 0`, `T_B = 1`, EOF = `2`. Recognizes any
/// non-empty alternating sequence starting with `A`.
#[must_use]
pub fn smoke_grammar() -> LrTable {
    // 4 states, 3 tokens (A, B, EOF), 1 nonterminal (S).
    let mut b = LrBuilder::new(4, 3, 1);
    let prod_unit = b.add_production(0, 2); // S -> A B

    // state 0: initial. On A shift to 1, on EOF accept.
    b.set_action(0, 0, Action::Shift(1));
    b.set_action(0, 2, Action::Accept);
    // state 1: just shifted A. On B shift to 2.
    b.set_action(1, 1, Action::Shift(2));
    // state 2: A B seen. Reduce S -> A B.
    b.set_action(2, 0, Action::Reduce(prod_unit));
    b.set_action(2, 2, Action::Reduce(prod_unit));
    // state 3: after reduce — GOTO logic would return us to state 0.

    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_pack_roundtrip() {
        for a in [
            Action::Shift(0),
            Action::Shift(42),
            Action::Reduce(0),
            Action::Reduce(99),
            Action::Accept,
            Action::Error,
        ] {
            assert_eq!(Action::unpack(a.pack()), a);
        }
    }

    #[test]
    fn builder_empty_table_is_all_errors() {
        let t = LrBuilder::new(2, 3, 1).build();
        for &word in &t.action {
            assert_eq!(Action::unpack(word), Action::Error);
        }
        for &word in &t.goto {
            assert_eq!(word, u32::MAX);
        }
    }

    #[test]
    fn smoke_grammar_shifts_on_a() {
        let t = smoke_grammar();
        assert_eq!(t.action_at(0, 0), Action::Shift(1));
        assert_eq!(t.action_at(0, 2), Action::Accept);
        assert_eq!(t.action_at(1, 1), Action::Shift(2));
    }
}

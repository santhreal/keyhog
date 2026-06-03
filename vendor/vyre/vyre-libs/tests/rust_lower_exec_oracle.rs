//! End-to-end execution oracle for the Rust nano-subset: lower the AST to a
//! Vyre `Program`, run it on the pure-Rust reference interpreter, and check the
//! result against two independent oracles:
//!   1. a direct AST tree-walk interpreter (independent of lowering), and
//!   2. real rustc: compile the module + a `main` that prints `entry(args)`,
//!      run it, and compare stdout.
//!
//! Programs are generated overflow-free and division-free so i32 semantics are
//! unambiguous across all three (no Rust debug-overflow panic, no div-by-zero).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use vyre_libs::parsing::rust::lex::lexer::core::lex;
use vyre_libs::parsing::rust::lower::{lower, lower_batched};
use vyre_libs::parsing::rust::parse::{parse, Expr, Module, Stmt};
use vyre_libs::parsing::rust::sema::{resolve, typeck, BindingId, Resolution};
use vyre_reference::value::Value;

use vyre_libs::parsing::rust::lex::tokens::{
    ANDAND, EQ, GE, GT, LE, LT, MINUS, NE, OROR, PERCENT, PLUS, SLASH, STAR,
};

// ---------------------------------------------------------------------------
// Pipeline helpers
// ---------------------------------------------------------------------------

fn frontend(src: &str) -> (Module, Resolution) {
    let bytes = src.as_bytes();
    let tokens = lex(bytes).expect("lex");
    let module = parse(bytes, &tokens).expect("parse");
    let resolution = resolve(&module, bytes).expect("resolve");
    typeck(&module, bytes, &resolution).expect("typeck");
    (module, resolution)
}

fn value_to_i32(v: &Value) -> i32 {
    match v {
        Value::I32(x) => *x,
        Value::U32(x) => *x as i32,
        Value::Bool(b) => i32::from(*b),
        Value::Bytes(bytes) => i32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")),
        other => panic!("unexpected output value {other:?}"),
    }
}

/// Lower `src`'s entry function and run it on the reference interpreter.
fn ir_exec(src: &str, inputs: &[i32]) -> i32 {
    let (module, resolution) = frontend(src);
    let program = lower(&module, &resolution).expect("lower");
    let values: Vec<Value> = inputs.iter().map(|&x| Value::I32(x)).collect();
    let out = vyre_reference::reference_eval(&program, &values).expect("reference_eval");
    assert_eq!(out.len(), 1, "entry must produce exactly one output");
    value_to_i32(&out[0])
}

fn i32_vec_to_bytes(values: &[i32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn bytes_to_i32_vec(bytes: &[u8]) -> Vec<i32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| i32::from_le_bytes(chunk.try_into().expect("i32 chunk")))
        .collect()
}

/// Lower `src`'s entry function as a data-parallel batch kernel and run it on
/// the reference interpreter. Each inner vector is one parameter buffer.
fn ir_exec_batched(src: &str, columns: &[Vec<i32>]) -> Vec<i32> {
    let lane_count = columns.first().map_or(0, Vec::len);
    assert!(lane_count > 0, "batched execution needs at least one lane");
    assert!(
        columns.iter().all(|column| column.len() == lane_count),
        "batched parameter columns must have equal lengths"
    );
    let (module, resolution) = frontend(src);
    let program = lower_batched(&module, &resolution, lane_count as u32).expect("lower_batched");
    let values: Vec<Value> = columns
        .iter()
        .map(|column| Value::from(i32_vec_to_bytes(column)))
        .collect();
    let out = vyre_reference::reference_eval(&program, &values).expect("reference_eval");
    assert_eq!(out.len(), 1, "entry must produce exactly one output");
    match &out[0] {
        Value::Bytes(bytes) => bytes_to_i32_vec(bytes),
        other => vec![value_to_i32(other)],
    }
}

// ---------------------------------------------------------------------------
// Independent AST tree-walk interpreter (oracle #1)
// ---------------------------------------------------------------------------

fn global_def_to_id(resolution: &Resolution) -> HashMap<u32, BindingId> {
    resolution
        .bindings
        .iter()
        .enumerate()
        .map(|(id, b)| (b.def_offset, id))
        .collect()
}

enum Flow {
    Return(i32),
    Fall,
}

struct Ev<'a> {
    module: &'a Module,
    resolution: &'a Resolution,
    def_to_id: &'a HashMap<u32, BindingId>,
}

impl Ev<'_> {
    fn run_fn(&self, idx: usize, args: &[i32]) -> i32 {
        let func = &self.module.functions[idx];
        let mut env: HashMap<BindingId, i32> = HashMap::new();
        for (i, (offset, _)) in func.params.iter().enumerate() {
            env.insert(self.def_to_id[offset], args[i]);
        }
        match self.exec(&func.body, &mut env) {
            Flow::Return(v) => v,
            Flow::Fall => 0,
        }
    }

    fn exec(&self, stmts: &[Stmt], env: &mut HashMap<BindingId, i32>) -> Flow {
        for stmt in stmts {
            match stmt {
                Stmt::Let { name, init, .. } => {
                    let v = self.eval_int(init, env);
                    env.insert(self.def_to_id[name], v);
                }
                Stmt::Return(Some(e)) => return Flow::Return(self.eval_int(e, env)),
                Stmt::Return(None) => return Flow::Return(0),
                Stmt::Assign { name, value } => {
                    let v = self.eval_int(value, env);
                    env.insert(self.resolution.uses[name], v);
                }
                Stmt::While { cond, body } => {
                    let mut guard = 0u32;
                    while self.eval_bool(cond, env) {
                        if let Flow::Return(v) = self.exec(body, env) {
                            return Flow::Return(v);
                        }
                        guard += 1;
                        assert!(guard < 1_000_000, "oracle while loop did not terminate");
                    }
                }
                Stmt::For {
                    name,
                    start,
                    end,
                    body,
                } => {
                    let binding = self.def_to_id[name];
                    let start = self.eval_int(start, env);
                    let end = self.eval_int(end, env);
                    for value in start..end {
                        env.insert(binding, value);
                        if let Flow::Return(v) = self.exec(body, env) {
                            return Flow::Return(v);
                        }
                    }
                }
                Stmt::Expr(Expr::If {
                    cond,
                    then_block,
                    else_block,
                }) => {
                    let taken = if self.eval_bool(cond, env) {
                        Some(then_block.as_ref())
                    } else {
                        else_block.as_deref()
                    };
                    if let Some(Expr::Block(body)) = taken {
                        if let Flow::Return(v) = self.exec(body, env) {
                            return Flow::Return(v);
                        }
                    }
                }
                Stmt::Expr(_) => {}
            }
        }
        Flow::Fall
    }

    fn eval_int(&self, e: &Expr, env: &HashMap<BindingId, i32>) -> i32 {
        match e {
            Expr::LiteralInt(_, v) => *v as i32,
            Expr::Var(off) => env[&self.resolution.uses[off]],
            Expr::Binary { op, lhs, rhs } => {
                let (l, r) = (self.eval_int(lhs, env), self.eval_int(rhs, env));
                match *op {
                    PLUS => l.wrapping_add(r),
                    MINUS => l.wrapping_sub(r),
                    STAR => l.wrapping_mul(r),
                    SLASH => l / r, // generator guarantees a nonzero literal divisor
                    PERCENT => l % r, // generator guarantees a nonzero literal divisor
                    other => panic!("non-arithmetic op {other} in integer position"),
                }
            }
            Expr::Call { name, args } => {
                let idx = self.resolution.calls[name];
                let a: Vec<i32> = args.iter().map(|x| self.eval_int(x, env)).collect();
                self.run_fn(idx, &a)
            }
            Expr::Borrow { expr, .. } => self.eval_int(expr, env),
            Expr::Deref(inner) => self.eval_int(inner, env),
            Expr::Neg(inner) => self.eval_int(inner, env).wrapping_neg(),
            other => panic!("unexpected integer expr {other:?}"),
        }
    }

    fn eval_bool(&self, e: &Expr, env: &HashMap<BindingId, i32>) -> bool {
        match e {
            Expr::LiteralBool(_, b) => *b,
            Expr::Not(inner) => !self.eval_bool(inner, env),
            Expr::Binary { op, lhs, rhs } => {
                if *op == ANDAND {
                    return self.eval_bool(lhs, env) && self.eval_bool(rhs, env);
                }
                if *op == OROR {
                    return self.eval_bool(lhs, env) || self.eval_bool(rhs, env);
                }
                let (l, r) = (self.eval_int(lhs, env), self.eval_int(rhs, env));
                match *op {
                    LT => l < r,
                    GT => l > r,
                    LE => l <= r,
                    GE => l >= r,
                    EQ => l == r,
                    NE => l != r,
                    other => panic!("non-comparison op {other} in bool position"),
                }
            }
            other => panic!("unexpected bool expr {other:?}"),
        }
    }
}

fn ast_interp(src: &str, inputs: &[i32]) -> i32 {
    let (module, resolution) = frontend(src);
    let def_to_id = global_def_to_id(&resolution);
    let ev = Ev {
        module: &module,
        resolution: &resolution,
        def_to_id: &def_to_id,
    };
    ev.run_fn(module.functions.len() - 1, inputs)
}

// ---------------------------------------------------------------------------
// Program generator (overflow-free, division-free i32 nano programs)
// ---------------------------------------------------------------------------

struct Gen {
    state: u64,
}
impl Gen {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x517C_C1B7_2722_0A95,
        }
    }
    fn next(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 33) as u32
    }
    /// Small arithmetic expression over `nvars` in-scope `vN` variables. When
    /// `calls`, may emit `h(e, e)`; when `refs`, may emit `*(&e)` or `d(&e)`.
    fn expr(&mut self, nvars: usize, depth: u32, calls: bool, refs: bool) -> String {
        if depth > 0 {
            if calls && self.next() % 5 == 0 {
                return format!(
                    "h({}, {})",
                    self.expr(nvars, depth - 1, calls, refs),
                    self.expr(nvars, depth - 1, calls, refs)
                );
            }
            if refs && self.next() % 5 == 0 {
                let inner = self.expr(nvars, depth - 1, calls, refs);
                return if self.next() % 2 == 0 {
                    format!("*(&({inner}))")
                } else {
                    format!("d(&({inner}))")
                };
            }
            if self.next() % 6 == 0 {
                // Division or remainder by a nonzero literal divisor (1..=5): no
                // div-by-zero; dividend may be negative (signed truncation).
                let op = if self.next() % 2 == 0 { "/" } else { "%" };
                return format!(
                    "({} {} {})",
                    self.expr(nvars, depth - 1, calls, refs),
                    op,
                    self.next() % 5 + 1
                );
            }
        }
        if depth == 0 || self.next() % 3 == 0 {
            if self.next() % 2 == 0 {
                format!("v{}", (self.next() as usize) % nvars)
            } else {
                format!("{}", self.next() % 6) // literal 0..=5
            }
        } else {
            let op = ["+", "-", "*"][(self.next() % 3) as usize];
            format!(
                "({} {} {})",
                self.expr(nvars, depth - 1, calls, refs),
                op,
                self.expr(nvars, depth - 1, calls, refs)
            )
        }
    }
    fn cond(&mut self, nvars: usize) -> String {
        self.cond_depth(nvars, 1)
    }
    fn cond_depth(&mut self, nvars: usize, depth: u32) -> String {
        if depth > 0 && self.next() % 4 == 0 {
            return format!("!({})", self.cond_depth(nvars, depth - 1));
        }
        if depth > 0 && self.next() % 3 == 0 {
            let op = if self.next() % 2 == 0 { "&&" } else { "||" };
            return format!(
                "({}) {} ({})",
                self.cond_depth(nvars, depth - 1),
                op,
                self.cond_depth(nvars, depth - 1)
            );
        }
        let op = ["<", ">", "<=", ">=", "==", "!="][(self.next() % 6) as usize];
        format!(
            "{} {} {}",
            self.expr(nvars, 1, false, false),
            op,
            self.expr(nvars, 1, false, false)
        )
    }
}

/// Generate `(source, param_count)`. Programs may include a leaf helper `h(a,b)`
/// and a ref-deref helper `d(p: &i32)` that the entry inlines, plus internal
/// `*(&e)` borrows. Params are i32; magnitudes stay small so no i32 overflow
/// occurs and the verdict is unambiguous.
fn gen_program(seed: u64) -> (String, usize) {
    let mut g = Gen::new(seed);
    let calls = g.next() % 2 == 0;
    let refs = g.next() % 2 == 0;
    let mut module = String::new();
    if calls {
        module.push_str(&format!(
            "fn h(v0: i32, v1: i32) -> i32 {{ return {}; }}\n",
            g.expr(2, 2, false, false)
        ));
    }
    if refs {
        module.push_str("fn d(v0: &i32) -> i32 { return *v0; }\n");
    }
    let nparams = 1 + (g.next() % 3) as usize; // 1..=3
    let mut nvars = nparams;
    let params: Vec<String> = (0..nparams).map(|i| format!("v{i}: i32")).collect();
    module.push_str(&format!("fn f({}) -> i32 {{", params.join(", ")));
    let nlets = (g.next() % 3) as usize;
    for _ in 0..nlets {
        module.push_str(&format!(
            " let mut v{}: i32 = {};",
            nvars,
            g.expr(nvars, 2, calls, refs)
        ));
        nvars += 1;
    }
    // Reassign existing mut locals (params stay immutable).
    if nvars > nparams {
        for _ in 0..(g.next() % 3) {
            let k = nparams + (g.next() as usize) % (nvars - nparams);
            module.push_str(&format!(" v{k} = {};", g.expr(nvars, 2, calls, refs)));
        }
    }
    if g.next() % 2 == 0 {
        module.push_str(&format!(" return {}; }}", g.expr(nvars, 2, calls, refs)));
    } else {
        module.push_str(&format!(
            " if {} {{ return {}; }} else {{ return {}; }} }}",
            g.cond(nvars),
            g.expr(nvars, 2, calls, refs),
            g.expr(nvars, 2, calls, refs)
        ));
    }
    (module, nparams)
}

fn gen_inputs(seed: u64, n: usize) -> Vec<i32> {
    let mut g = Gen::new(seed ^ 0xABCD_1234);
    (0..n).map(|_| (g.next() % 19) as i32 - 9).collect() // -9..=9
}

/// Canonical counting-loop program: `let mut i = 0; let mut acc = <params>;
/// while i < BOUND { acc = acc + <params,i>; i = i + 1; } return acc;`.
/// The accumulator grows linearly (the body never reads `acc`), so no i32
/// overflow, and the form is exactly what the lowering recognizes.
fn gen_while_program(seed: u64) -> (String, usize) {
    let mut g = Gen::new(seed ^ 0x5DEE_CE66_1357_9BDF);
    let nparams = 1 + (g.next() % 2) as usize; // 1..=2
    let i = nparams; // loop variable index
    let acc = nparams + 1; // accumulator index
    let bound = g.next() % 6 + 1; // 1..=6
    let params: Vec<String> = (0..nparams).map(|p| format!("v{p}: i32")).collect();
    let acc_init = g.expr(nparams, 1, false, false); // over params only
    let body = g.expr(nparams + 1, 1, false, false); // over params + i (not acc)
    (
        format!(
            "fn f({}) -> i32 {{ let mut v{i}: i32 = 0; let mut v{acc}: i32 = {acc_init}; \
             while v{i} < {bound} {{ v{acc} = v{acc} + {body}; v{i} = v{i} + 1; }} return v{acc}; }}",
            params.join(", ")
        ),
        nparams,
    )
}

#[test]
fn lowered_while_matches_ast_and_rustc() {
    let mut checked = 0;
    for seed in 0..400u64 {
        let (src, nparams) = gen_while_program(seed);
        let inputs = gen_inputs(seed.wrapping_mul(11).wrapping_add(2), nparams);
        let ast = ast_interp(&src, &inputs);
        let ir = ir_exec(&src, &inputs);
        assert_eq!(
            ir, ast,
            "while: lowered IR diverged from AST interp:\n  {src}\n  inputs {inputs:?}"
        );
        if seed < 60 {
            if let Some(rustc) = rustc_run(&src, &inputs) {
                assert_eq!(
                    ir, rustc,
                    "while: lowered IR diverged from rustc:\n  {src}\n  inputs {inputs:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 30,
        "expected most while programs to compile+run under rustc, got {checked}"
    );
}

/// Canonical range-loop program: `for i in START..BOUND { acc += <params,i>; }`.
/// Bounds are small and signed so the test exercises non-zero, negative, and
/// zero-trip ranges without risking a huge lowered loop.
fn gen_for_program(seed: u64) -> (String, usize) {
    let mut g = Gen::new(seed ^ 0xA11C_E5F0_2BCD_8891);
    let nparams = 1 + (g.next() % 2) as usize; // 1..=2
    let acc = nparams;
    let start = (g.next() % 7) as i32 - 3; // -3..=3
    let span = g.next() % 7; // 0..=6
    let end = start + span as i32;
    let params: Vec<String> = (0..nparams).map(|p| format!("v{p}: i32")).collect();
    let acc_init = g.expr(nparams, 1, false, false);
    let body = g.expr(nparams + 2, 1, false, false); // params + acc + loop variable
    (
        format!(
            "fn f({}) -> i32 {{ let mut v{acc}: i32 = {acc_init}; \
             for v{} in {start}..{end} {{ v{acc} += {body}; }} return v{acc}; }}",
            params.join(", "),
            acc + 1
        ),
        nparams,
    )
}

#[test]
fn lowered_for_range_matches_ast_and_rustc() {
    let mut checked = 0;
    for seed in 0..400u64 {
        let (src, nparams) = gen_for_program(seed);
        let inputs = gen_inputs(seed.wrapping_mul(17).wrapping_add(5), nparams);
        let ast = ast_interp(&src, &inputs);
        let ir = ir_exec(&src, &inputs);
        assert_eq!(
            ir, ast,
            "for-range: lowered IR diverged from AST interp:\n  {src}\n  inputs {inputs:?}"
        );
        if seed < 80 {
            if let Some(rustc) = rustc_run(&src, &inputs) {
                assert_eq!(
                    ir, rustc,
                    "for-range: lowered IR diverged from rustc:\n  {src}\n  inputs {inputs:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 50,
        "expected most for-range programs to compile+run under rustc, got {checked}"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn lowered_ir_matches_ast_interpreter() {
    for seed in 0..2000u64 {
        let (src, nparams) = gen_program(seed);
        for input_seed in 0..3u64 {
            let inputs = gen_inputs(seed.wrapping_mul(7).wrapping_add(input_seed), nparams);
            let expected = ast_interp(&src, &inputs);
            let got = ir_exec(&src, &inputs);
            assert_eq!(
                got, expected,
                "lowered IR diverged from AST interpreter at seed {seed} inputs {inputs:?}:\n  {src}"
            );
        }
    }
}

#[test]
fn curated_programs_execute_correctly() {
    let cases: &[(&str, &[i32], i32)] = &[
        ("fn f(a: i32, b: i32) -> i32 { return a + b; }", &[3, 4], 7),
        ("fn f(a: i32, b: i32) -> i32 { return a - b; }", &[10, 3], 7),
        ("fn f(a: i32) -> i32 { let b: i32 = a * 2; return b + 1; }", &[5], 11),
        ("fn f(a: i32, b: i32) -> i32 { if a < b { return b; } else { return a; } }", &[3, 9], 9),
        ("fn f(a: i32, b: i32) -> i32 { if a < b { return b; } else { return a; } }", &[9, 3], 9),
        ("fn f(a: i32) -> i32 { if a == 0 { return 100; } else { return a; } }", &[0], 100),
        ("fn g(a: i32, b: i32) -> i32 { return a + b; } fn f(a: i32) -> i32 { return g(a, 10); }", &[5], 15),
        ("fn g(a: i32) -> i32 { let d: i32 = a * a; return d - 1; } fn f(a: i32, b: i32) -> i32 { return g(a) + b; }", &[4, 2], 17),
        ("fn f(a: i32) -> i32 { let r: &i32 = &a; return *r + 1; }", &[6], 7),
        ("fn f(a: i32) -> i32 { return *(&a) * 2; }", &[5], 10),
        ("fn d(p: &i32) -> i32 { return *p + 1; } fn f(a: i32) -> i32 { return d(&a); }", &[8], 9),
        ("fn f(a: i32) -> i32 { return a / 3; }", &[7], 2),
        ("fn f(a: i32) -> i32 { return a / 3; }", &[-7], -2), // truncates toward zero
        ("fn f(a: i32) -> i32 { return a % 3; }", &[7], 1),
        ("fn f(a: i32) -> i32 { return a % 3; }", &[-7], -1), // remainder sign follows dividend
        ("fn f(a: i32, b: i32) -> i32 { if a > b { return 1; } else { return 0; } }", &[5, 2], 1),
        ("fn f(a: i32, b: i32) -> i32 { if a <= b { return 1; } else { return 0; } }", &[2, 2], 1),
        ("fn f(a: i32, b: i32) -> i32 { if a >= b { return 1; } else { return 0; } }", &[1, 2], 0),
        ("fn f(a: i32, b: i32) -> i32 { if a != b { return 1; } else { return 0; } }", &[3, 3], 0),
        ("fn f(a: i32, b: i32) -> i32 { if a < b && b < 10 { return 1; } else { return 0; } }", &[3, 5], 1),
        ("fn f(a: i32, b: i32) -> i32 { if a < b && b < 10 { return 1; } else { return 0; } }", &[3, 50], 0),
        ("fn f(a: i32, b: i32) -> i32 { if a == 0 || b == 0 { return 1; } else { return 0; } }", &[0, 7], 1),
        ("fn f(a: i32, b: i32) -> i32 { if !(a < b) { return 1; } else { return 0; } }", &[5, 2], 1),
        ("fn f(a: i32) -> i32 { let mut x: i32 = a; x = x + 1; x = x * 2; return x; }", &[3], 8),
        ("fn f(n: i32) -> i32 { let mut i: i32 = 0; let mut acc: i32 = 0; while i < n { acc = acc + i; i = i + 1; } return acc; }", &[5], 10),
        ("fn f(n: i32) -> i32 { let mut i: i32 = 0; let mut acc: i32 = 0; while i < n { acc = acc + i; i = i + 1; } return acc; }", &[0], 0),
        // Negative bound: rustc runs the loop zero times. The old lowering cast
        // `n` to u32 (-> ~4.29e9 iterations); the clamped trip count must give 0.
        ("fn f(n: i32) -> i32 { let mut i: i32 = 0; let mut acc: i32 = 0; while i < n { acc = acc + i; i = i + 1; } return acc; }", &[-3], 0),
        // Non-zero (and negative) start: `i` must reconstruct as `i0 + lv`, not as
        // the raw u32 loop counter. 2+3+4 = 9.
        ("fn f() -> i32 { let mut i: i32 = 2; let mut acc: i32 = 0; while i < 5 { acc = acc + i; i = i + 1; } return acc; }", &[], 9),
        ("fn f() -> i32 { let mut i: i32 = -2; let mut acc: i32 = 0; while i < 1 { acc = acc + i; i = i + 1; } return acc; }", &[], -3), // (-2)+(-1)+0 = -3
        // Post-loop induction value. After a loop that ran, `i == n`; for a
        // zero-trip loop `i` is left unchanged (the old `i := n` was wrong).
        ("fn f(n: i32) -> i32 { let mut i: i32 = 0; while i < n { i = i + 1; } return i; }", &[4], 4),
        ("fn f() -> i32 { let mut i: i32 = 5; while i < 3 { i = i + 1; } return i; }", &[], 5),
        // Compound assignment value semantics: the differential only checks
        // accept/reject, so a broken `x += e -> x = e` desugar would ship green.
        // Hardcoded expected values pin the read-modify-write (a broken desugar
        // fools the ir-vs-ast cross-check but not the literal oracle below).
        ("fn f(a: i32) -> i32 { let mut x: i32 = a; x += 2; return x; }", &[3], 5),
        ("fn f(a: i32) -> i32 { let mut x: i32 = a; x -= 2; return x; }", &[10], 8),
        ("fn f(a: i32, b: i32) -> i32 { let mut x: i32 = a; x += b * 2; return x; }", &[10, 4], 18),
        // Unary minus value + precedence: `-a + b` must parse as `(-a) + b`, not
        // `-(a + b)`; `-(-a)` is identity. Accept-only differential cannot see this.
        ("fn f(a: i32, b: i32) -> i32 { return -a + b; }", &[5, 3], -2),
        ("fn f(a: i32) -> i32 { return -(-a); }", &[7], 7),
        ("fn f(a: i32, b: i32) -> i32 { return a - -b; }", &[5, 3], 8),
        ("fn f() -> i32 { let mut acc: i32 = 0; for i in 0..5 { acc += i; } return acc; }", &[], 10),
        ("fn f() -> i32 { let mut acc: i32 = 0; for i in -2..2 { acc += i; } return acc; }", &[], -2),
        ("fn f() -> i32 { let mut acc: i32 = 7; for i in 5..3 { acc += i; } return acc; }", &[], 7),
        ("fn f(n: i32) -> i32 { let mut acc: i32 = 0; for i in 0..n { acc += i; } return acc; }", &[4], 6),
        // Bounds are evaluated once before iteration; mutating `n` in the body
        // must not shorten the range after the first trip.
        ("fn f(n: i32) -> i32 { let mut m: i32 = n; let mut acc: i32 = 0; for i in 0..m { m = 0; acc += i; } return acc; }", &[4], 6),
    ];
    for (src, inputs, expected) in cases {
        assert_eq!(ir_exec(src, inputs), *expected, "{src} with {inputs:?}");
        assert_eq!(
            ast_interp(src, inputs),
            *expected,
            "AST interp: {src} with {inputs:?}"
        );
    }
}

#[test]
fn batched_lowering_maps_rust_entry_across_input_buffers() {
    let src = "\
fn f(a: i32, n: i32) -> i32 {
    let mut acc: i32 = a;
    for i in -3..n {
        if i < 0 {
            acc += i * 2;
        } else {
            acc += i + a;
        };
    }
    return acc;
}";
    let lanes = 257usize;
    let a: Vec<i32> = (0..lanes)
        .map(|lane| ((lane as i32 * 5) % 23) - 11)
        .collect();
    let n: Vec<i32> = (0..lanes)
        .map(|lane| ((lane as i32 * 7) % 17) - 4)
        .collect();
    let got = ir_exec_batched(src, &[a.clone(), n.clone()]);
    let expected: Vec<i32> = a
        .iter()
        .zip(n.iter())
        .map(|(&a, &n)| ast_interp(src, &[a, n]))
        .collect();
    assert_eq!(
        got, expected,
        "batched Rust lowering must map scalar entry semantics across every lane"
    );
}

// ---------------------------------------------------------------------------
// rustc compile+run ground truth (oracle #2)
// ---------------------------------------------------------------------------

fn rustc_run(src: &str, inputs: &[i32]) -> Option<i32> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vyre_lower_{}_{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let args = inputs
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let main = format!("\nfn main() {{ println!(\"{{}}\", f({args})); }}\n");
    let rs = dir.join("m.rs");
    std::fs::write(&rs, format!("{src}{main}")).expect("write");
    let exe = dir.join("m");
    let build = std::process::Command::new("rustc")
        .args(["--edition", "2021", "-O", "--cap-lints", "allow", "-o"])
        .arg(&exe)
        .arg(&rs)
        .output()
        .expect("rustc on PATH");
    let result = if build.status.success() {
        std::process::Command::new(&exe)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<i32>()
                    .ok()
            })
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
fn lowered_ir_matches_rustc_execution() {
    let mut checked = 0;
    for seed in 0..80u64 {
        let (src, nparams) = gen_program(seed);
        let inputs = gen_inputs(seed.wrapping_mul(13).wrapping_add(1), nparams);
        let Some(expected) = rustc_run(&src, &inputs) else {
            continue;
        };
        let got = ir_exec(&src, &inputs);
        assert_eq!(
            got, expected,
            "lowered IR diverged from rustc-run at seed {seed} inputs {inputs:?}:\n  {src}"
        );
        checked += 1;
    }
    assert!(
        checked >= 40,
        "expected most generated programs to compile+run under rustc, got {checked}"
    );
}

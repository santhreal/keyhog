# String Operations

## The layer between bytes and meaning

A DFA scanner operates on bytes. It does not know that the byte
sequence `65 76 61 6C` is the identifier `eval` in a JavaScript
program. It does not know that the same bytes inside a string
literal `"eval"` are data, not code. It does not know that the
same bytes inside a comment `// eval` are dead text. To the DFA,
bytes are bytes. The context is invisible.

This blindness is a problem for security scanning. A scanner that
matches `eval` in a JavaScript file will fire on every occurrence —
in executable code, in string literals, in comments, in variable
names that happen to contain the substring. The false positive rate
is catastrophic. A codebase with 100,000 JavaScript files will
contain thousands of occurrences of `eval` that are not calls to
the `eval()` function. A scanner that reports all of them is
useless; the developer stops reading the results after the tenth
false positive.

The solution is token-aware scanning. Before the DFA runs, each
byte of the input is classified into a token type: identifier,
string literal, comment, number, operator, whitespace, regex
literal, unknown. The DFA matches are then filtered by token type.
A match on `eval` inside a comment is suppressed. A match inside a
string literal is flagged differently (it might be a string passed
to `eval()`). A match inside an identifier in executable code is
the finding the user cares about.

Token classification is the job of string operations. The
`string.tokenize` op classifies each byte of a source buffer into
its token type. The classification is parallel — each byte's token
type depends only on its local context (the surrounding bytes within
a bounded window) — which makes it a natural fit for GPU execution.

## The cost of not tokenizing

Without tokenization, a scanner has two options for handling false
positives:

**Option 1: Accept them.** The scanner reports every match and lets
the user sort out which ones matter. This works for small codebases
and doesn't work for anything else. A team with 10,000 findings per
scan run will ignore all of them.

**Option 2: Implement ad-hoc filtering.** The scanner adds rules
like "ignore matches preceded by `//`" and "ignore matches between
quotes." These rules are fragile because they don't handle edge
cases: nested quotes, multi-line comments, template literals,
heredocs, regex literals that contain quote-like characters. Every
ad-hoc rule has a bypass that an attacker can exploit. The filtering
is never complete because it is reimplementing a tokenizer without
admitting it.

Tokenization done properly, once, in the substrate, eliminates both
problems. The scanner inherits correct token classification. The
classification handles edge cases because it is a proper state
machine, not a collection of regex heuristics. The classification
runs on the GPU in the same pipeline as the DFA scan, so there is
no performance penalty — the bytes pass through the tokenizer and
the DFA in successive dispatches without returning to the CPU.

## Operations

### string.tokenize

**Identifier:** `string.tokenize`

**Current state:** Legacy WGSL-only. Production shader included from
the `gputokenize` crate via `include_str!`. Does not implement
`Op::program()`.

**Signature:** `(Bytes) -> U32`

**What this operation does:** Classify each byte of a JavaScript
source buffer into a token type. One invocation per byte. The output
buffer has one `u32` per input byte, where `output[i]` is the token
type of byte `i`.

**Token types:**

| ID | Name | What it covers |
|----|------|---------------|
| 0 | String | Single-quoted, double-quoted, and template literal (backtick) string content. Includes the opening and closing delimiters. Handles escape sequences (`\"`, `\\`, `\n`, `\u{...}`) correctly — an escaped quote does not end the string. |
| 1 | Identifier | Variable names, keywords, property names. Starts with a letter, `_`, or `$`; continues with letters, digits, `_`, or `$`. Does not distinguish keywords from user identifiers — both are type 1. |
| 2 | Number | Integer literals (`42`, `0xFF`, `0b1010`, `0o77`), float literals (`3.14`, `1e10`), and BigInt literals (`42n`). Handles all JavaScript numeric syntaxes including underscores as separators (`1_000_000`). |
| 3 | Comment | Line comments (`// ...`) and block comments (`/* ... */`). Includes the opening and closing delimiters. |
| 4 | Regex | Regular expression literals (`/.../flags`). Disambiguated from division by examining the preceding token context: a `/` after an expression-terminating token (identifier, number, `)`, `]`) is division; a `/` after an operator, keyword, or statement start is a regex. |
| 5 | Operator | Punctuation and operators: `+`, `-`, `*`, `/` (when not regex), `=`, `{`, `}`, `(`, `)`, `[`, `]`, `;`, `,`, `.`, `?`, `:`, `<`, `>`, `!`, `&`, `|`, `^`, `~`, `%`. Multi-character operators (`===`, `!==`, `=>`, `?.`, `**`) are classified byte-by-byte — each byte is type 5. |
| 6 | Whitespace | Spaces, tabs (`\t`), carriage returns (`\r`), newlines (`\n`), form feeds, and other Unicode whitespace characters in the ASCII range. |
| 7 | Unknown | Any byte that does not belong to the above categories. Includes non-ASCII bytes outside known escape sequences, control characters, and malformed input. |

**Why these specific categories:** The categories are chosen for
security scanning utility, not for parsing completeness. A parser
needs to distinguish `if` from `while` from `return` — the
tokenizer does not, because all three are identifiers (type 1) and
the scanner's DFA patterns match specific keywords by content. The
categories the tokenizer provides are the categories the DFA filter
needs: "is this match in executable code (type 1, 5), in a string
(type 0), in a comment (type 3), or in a regex (type 4)?" That is
the question the scanner asks, and those categories answer it.

**The regex disambiguation problem:**

The hardest part of JavaScript tokenization is distinguishing regex
literals from division operators. Both use `/`:

```javascript
let x = a / b;          // division
let re = /pattern/g;    // regex literal
let y = (a + b) / c;    // division
if (/test/.test(s)) {}  // regex literal
```

The tokenizer resolves this by tracking the preceding token context.
The rule is:

- If the `/` follows an expression-producing token (identifier,
  number, `)`, `]`), it is division.
- If the `/` follows anything else (operator, keyword, `(`, `[`,
  `;`, `,`, `{`, start of input), it is a regex.

This heuristic matches the JavaScript specification's grammar rules
and handles the vast majority of real-world code correctly. There
are pathological cases where the heuristic fails (e.g., a regex
literal immediately after a label followed by a colon), but these
are rare in production code and do not affect security scanning
accuracy in practice.

**Template literals:**

Template literals (backtick strings) in JavaScript can contain
embedded expressions: `` `Hello, ${name}!` ``. The tokenizer handles
this by tracking brace depth within template literals. Bytes inside
`${ ... }` are classified by their normal token types (identifier,
operator, etc.), not as string content. Bytes outside interpolation
regions are classified as string (type 0).

This is one of the more complex state transitions in the tokenizer
and is a common source of bugs in hand-written tokenizers. The GPU
implementation handles it correctly because the state machine tracks
template nesting depth explicitly.

**Dispatch model:** One invocation per byte. Workgroup size is
shader-dependent (typically 256). The invocation reads its byte and
a bounded window of surrounding bytes to determine context, then
writes the token type to `output[gid.x]`.

**Why one invocation per byte:** The alternative — one invocation
per token — would require a preliminary pass to identify token
boundaries, which is itself a tokenization problem. One invocation
per byte avoids the circular dependency. Each invocation classifies
its byte independently based on local context. The classification
may examine preceding bytes (for regex disambiguation) and following
bytes (for multi-character tokens), but the window is bounded and
the access pattern is predictable.

**Performance characteristics:** The tokenizer processes one byte
per invocation. For a 1MB JavaScript file, this is 1M invocations.
At 256 invocations per workgroup, that is ~4,000 workgroups. A
modern GPU dispatches this in under 1ms. The tokenizer is not a
bottleneck — it is a preprocessing step that runs in the time it
takes the CPU to finish uploading the next file.

## Composition in the pipeline

Token-aware scanning uses the tokenizer output as a mask:

```text
file bytes → GPU tokenize → DFA scan → filter matches by token type → eval
```

The filter step is a simple composition: for each DFA match at byte
position `start`, check `token_types[start]`. If the token type is
comment (3), the match is a false positive in most security
contexts. If the token type is string (0), the match may be relevant
(strings passed to `eval()`, `innerHTML`, etc.) but is flagged
differently. If the token type is identifier (1) or operator (5),
the match is in executable code and is the primary finding.

The filter can be a composed IR expression if both the tokenizer and
the DFA scan are IR-first:

```text
Select(Ne(Load(token_types, match_start), LitU32(3)), match_result, LitU32(0))
```

This inlines into the DFA scanning shader, eliminating the separate
filter dispatch. The GPU classifies, scans, and filters in one pass.

## Beyond security scanning

Tokenization was motivated by reducing false positives in security scanning,
but tokenization is a universal preprocessing step:

- **Code search.** GitHub-scale code search tokenizes before indexing. GPU
  tokenization could preprocess billions of files for indexing in hours
  instead of days.

- **Syntax highlighting.** Every editor and code viewer tokenizes source
  for display. Batch tokenization of large codebases for documentation
  rendering benefits from GPU parallelism.

- **Code metrics.** Counting lines of code, comment density, identifier
  frequency, and complexity metrics all require tokenization as a first
  step.

- **Refactoring tools.** Finding all references to an identifier requires
  distinguishing identifiers from string contents and comments — exactly
  what the tokenizer provides.

- **Language-aware diff.** Diff tools that understand syntax (ignoring
  whitespace changes inside strings, treating comment changes differently)
  need token classification.

The tokenizer is a byte classifier. It answers "what kind of thing is at
this position?" for every byte in the input. The answer is useful for
security scanning, code analysis, and any other application that needs to
understand source code structure.

## Language generality

The current tokenizer is JavaScript-specific. JavaScript is the
highest-priority language for web security scanning (client-side XSS,
DOM manipulation, prototype pollution, supply chain attacks in npm).
But the tokenization problem exists for every language:

- **Python:** f-strings have the same interpolation complexity as
  JavaScript template literals. Triple-quoted strings span multiple
  lines. Indentation is syntactically significant.
- **Go:** backtick raw strings contain no escape sequences. Rune
  literals use single quotes.
- **Rust:** raw strings (`r#"..."#`) have variable delimiter depth.
  Lifetime annotations use `'a` syntax that looks like character
  literals.
- **Java:** text blocks (`"""..."""`) span multiple lines. Unicode
  escapes are processed before tokenization (unlike every other
  language).
- **PHP:** heredoc/nowdoc syntax. Variable interpolation in
  double-quoted strings.

Each language's tokenizer is a separate op (`string.tokenize_python`,
`string.tokenize_go`, etc.) with the same signature `(Bytes) -> U32`
and the same token type numbering. The token type IDs are
language-independent: type 0 is always string, type 1 is always
identifier, type 3 is always comment. Language-specific token types
(e.g., Python decorators, Rust attributes) use IDs 8+.

A language-generic tokenizer that accepts a token grammar as a
parameter buffer is an attractive future direction but is
architecturally complex (the grammar would need to be compiled into
a state machine on the host and uploaded as a lookup table). It is
not on the immediate roadmap but is compatible with vyre's
architecture (the grammar table would use V2 convention's lookup
buffer).

## Migration to IR-first

The tokenizer shader is a complex state machine with:

- A state variable tracking the current token context (normal,
  string, comment, regex, template literal, interpolation).
- Lookback for regex disambiguation (what was the preceding token
  type?).
- Lookahead for multi-character operators and numeric formats.
- Template literal nesting depth tracking.

Expressing this as an `ir::Program` requires:

- Multiple `Node::If` branches for state transitions.
- Local variables for the current state, lookback context, and
  nesting depth.
- Bounded lookback via `Load` at `gid.x - 1`, `gid.x - 2`, etc.
  (with OOB returning zero for bytes before the start of input).
- Output via `Store` of the token type ID.

The IR supports all of these. The migration is complex because the
state machine is large (dozens of states, hundreds of transitions),
but each transition is a simple conditional on byte values and state
variables. The IR's `Node::If` and `Expr::BinOp(Eq, ...)` cover
every transition.

## What the conformance suite will verify

**Empty input.** Expected: empty output.

**Single-token inputs.** One identifier, one string, one comment,
one number, one regex, one operator. Expected: every byte classified
correctly.

**JavaScript edge cases:**
- Escaped quotes inside strings (`"he said \"hello\""`) — all bytes
  inside the string should be type 0.
- Regex vs. division (`a / b` vs. `/pattern/g`) — correct
  disambiguation.
- Template literals with interpolation (`` `${x + y}` ``) — bytes
  inside `${}` should have their normal types; bytes outside should
  be type 0.
- Nested template literals (`` `${`nested`}` ``) — correct nesting
  depth tracking.
- Block comments spanning multiple lines — all bytes type 3.
- Line comments ending at newline — newline is type 6 (whitespace),
  not type 3.

**Adversarial inputs:**
- A file that is 100% string content (one long string literal with
  no closing quote). Expected: all bytes type 0 or type 7 (depending
  on unterminated-string handling).
- A file with deeply nested template literal interpolations.
- A file with all 256 possible byte values.

**Determinism:** Same input, 100 runs. Expected: identical token
type arrays.

## Permanence

The operation identifier `string.tokenize` is permanent. The token
type IDs (0–7) and their meanings are permanent. Future token types
use IDs 8+. The per-byte output format (one `u32` per input byte)
is permanent. The JavaScript-specific tokenization rules
(regex disambiguation, template literal nesting) are permanent for
this op; language-specific variants will be separate ops.

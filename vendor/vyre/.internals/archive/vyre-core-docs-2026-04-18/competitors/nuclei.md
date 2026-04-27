# ProjectDiscovery Nuclei

ProjectDiscovery Nuclei is a vulnerability scanning engine driven by templates.
Templates describe protocol requests, matchers, extractors, variables, payloads,
and workflow logic. This makes Nuclei highly extensible for security scanning:
new checks can be shipped as data without rebuilding the engine.

vyre should not embed a Nuclei-like product surface. The useful comparison is
Nuclei's template extensibility versus vyre's IR composition strategy for
security domains.

## Where Nuclei is stronger

Nuclei is product-complete for network and application scanning. Its template
format lets security teams write checks for HTTP, DNS, TCP, file, and other
protocol contexts. Matchers and extractors are close to the scanning workflow,
which makes templates accessible to practitioners who are not compiler or GPU
engineers.

Nuclei also owns orchestration concerns that vyre should not own: target
selection, protocol clients, request scheduling, response capture, output
formatting, and workflow-level scan behavior.

## Where vyre differs

vyre's Tier B rule extensibility should compile into IR compositions, not into a
runtime template interpreter. A TOML rule frontend can parse product-level rules
and lower supported operations into `ops/rule/`, `ops/match_ops/`, decode,
hash, and primitive compositions. Once lowered, the result is an ordinary vyre
program or operation graph subject to the same validation, wire format, lowering,
and conformance gates as hand-authored IR.

That is cleaner than embedding Nuclei templates inside vyre because it preserves
layer boundaries. Template syntax is a product concern. IR composition is the
substrate concern. If a rule needs URL decoding, hashing, byte matching, and DFA
scan, the frontend emits those domain operations as IR. vyre does not need to
know whether the source was a TOML rule, a YARA-like rule, or a generated policy
graph.

Runtime template interpretation would be a Category B violation in vyre. It
would add an execution model beside the IR and lowerings, making performance and
semantics depend on an interpreter loop. The correct path is compile once into
IR, validate, serialize if needed, and lower to the backend.

## Practical boundary

Nuclei is a scanner with a template language. vyre is a GPU compute IR with
security-relevant operation domains. Downstream tools can adopt Nuclei-like
ergonomics at their own layer, but `core` should only expose the primitives and
domain compositions needed to execute the compiled form.

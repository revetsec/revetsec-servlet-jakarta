# Explicit executable signatures

`ExecutableNullabilityContractTests` attributes all authored main/test Java signatures and this checker with the
actual test classpath. Reference parameters and returns, including nested generic/array/wildcard positions,
constructors and record components, require exactly one explicit JSpecify meaning. Primitive and void types are
exempt. Intentional malformed source fixtures retain their calibrations.

The pinned core `ClaimsLintTests` drift comparison ignores only JSpecify tokens/imports and their resulting whitespace.
Executable Java tokens, comments and literal contents must still match; calibrated positive/negative cases enforce
that boundary. The reference checker retains its Revetware Apache-2.0 header.

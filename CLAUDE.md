# glci

## Go conventions

### Naming
- Reuse a single `err` across a scope's operations. When two or more errors coexist, give each an `xErr` name (`readErr`, `closeErr`). Name a closure's own error `inErr`, adding an `in` per nesting level (`inErr`, `inInErr`) even when the outer func has no `err`. An error passed into a closure as a parameter takes a descriptive name, not `inErr`.
- A context is `ctx`, or an `xCtx` (`taskCtx`, `runnerCtx`) when `ctx` would shadow.
- Name a callback parameter for the verb it performs (`visit`, `read`, `write`, `match`), not `fn`.
- Name a mutex `xMtx` for the field or concept `x` it guards (`cacheMtx`).
- Name a membership set (a presence-only `map[K]struct{}`) with the plural member noun (`nodes`), not `xSet`, prefixing `all` if taken (`allNodes`). When it marks a member state, use the state word instead (`seen`, `visited`), adding the member noun where unclear, as on a struct field (`visitedNodes`).
- For `len(x)` of a named slice, map, or string, suffix the name with `Len` (`items` -> `itemsLen`). For any other count, use `num` plus the plural noun (`numRetries`). A single io byte-count is `n`. Never a `Count` suffix, never a bare plural for a count.
- Prefix `iota` enum values with the type name (`Color` -> `ColorRed`). For an established term of art, keep the suffix form (`Order` -> `PostOrder`, not `OrderPost`).
- Never name a local variable the same as an imported package.

### Declarations and literals
- Always write struct literals across multiple lines, even single-field.
  ```go
  x := T{
      F: 1,
  }
  ```
- Never `:=` when any LHS variable already exists in scope, even though Go permits it. Pre-declare and use `=`.
  ```go
  var x int
  x, err = f()
  ```
- Prefer `var x bool` over `x := false`.
- For empty maps, use `make(map[K]V)`, not `map[K]V{}`. Use the composite literal only when giving the map initial entries.
- For sets (presence-only, value never read), use `map[K]struct{}` not `map[K]bool`.

### Struct fields
- Order struct fields in this sequence, each group set off by a blank line, optionally subdivided by more blank lines.
  - Embedded types.
  - A framework handle or a `self` interface pointer.
  - Given values and representations derived from them.
  - Mutable state.
  - Lifecycle controls.
- Group a mutex above the fields it guards, set off by blank lines from other fields.
- When several of a struct's fields are referenced together, follow struct-definition order unless another order is required.

### Types and interfaces
- Types implementing `error` use pointer receivers, even empty-struct markers. Functions return `error`, never `*T`.
- To probe a value for optional methods, assert a named interface, never inline `x.(interface{ ... })`. Prefer an existing one like `io.Closer`, else declare it function-local, lift to package scope only when a second function asserts it.

### Control flow
- Never assign in the `if` statement.
  ```go
  err := f()
  if err != nil { ... }
  ```
- Never name result parameters. Declare locals in the body and return them explicitly.

### Errors
- Wrap only to add context the error lacks, the operation attempted and values that clarify the failure.
- Don't name your own input params.
  ```go
  return fmt.Errorf("cannot make directory: %w", err)  // no path
  ```
  - "Copy exception". Name your own param when the error would otherwise be ambiguous about which of several things an operation touched.
    ```go
    func copy(src, tgt string) error {  // opens both src and tgt
        ...
        return fmt.Errorf("cannot open %q: %w", src, err)
    }
    ```
  - "Visit exception". When a library invokes your function as a callback or interface method (a graph library's `visit(node)`), name your own input param.
- Phrase an operation failure as `cannot <verb>` (`cannot open %q`).
- Phrase a bad value as `invalid`/`missing` plus the noun (`invalid port %d`). For unexpected values append `expected X, got Y` (`invalid port: expected 1-65535, got %d`).
- Inline compile-time constants in error messages, and use `%q` for runtime values.
  ```go
  fmt.Errorf("invalid type: expected init, got %q", x)
  ```
- Never write `panic(...)`.

### Concurrency
- Defer the unlock immediately after the lock. For narrow scope, use an anonymous func.

### Resources
- Clean up resources with both a `defer` for failure paths and an explicit error-checked close at the end of the happy path.

### Filesystem
- A dir that exists only to be mounted over uses `0o700`.
- In `filepath.Join`, each variable is a separate arg, fixed segments stay one slash-joined string (`filepath.Join(varDir, "etc/apt/sources.list")`).

### Formatting
- Commutative ops with a numeric literal put the literal on the right (`time.Second * 7` not `7 * time.Second`).

### Comments
- Do not add comments, including package or private-item doc comments, unless a linter requires it, or explicitly asked.
- A doc comment fits on one line within the project's configured line-length limit, no `:`, `;`, or `-`.

### File names
- A `.go` file name is a single lowercase word or mashed-lowercase compound (`ringbuffer.go`), never a verb.
- A primary-type file holds one type and its methods, named for the type minus any suffix repeating the package or interface (`Store` -> `store.go`, `memStore` -> `mem.go`).
- A package-name file holds the package's public API, interfaces, or entry point (`codec` -> `codec.go`).
- A concept-noun file holds related helpers with no single owner type (`hash.go`).
- A test mirrors its source file, exported in `x_test.go` (`package x_test`), unexported in `x_internal_test.go` (`package x`). `TestMain` and package-wide fixtures go in `<pkg>_test.go`.

### File layout
- Declarations follow this order, higher rules taking precedence on conflict:
  - Package-level `const` at the top, directly below imports.
  - Package-level `var` directly below the constants.
  - `init()` (if any) directly below the variables.
  - Public methods in interface declaration order.
  - Sub-types of T directly below T. A sub-type is a type T structurally requires in its definition (a field type or type parameter), not one appearing only in a method signature.
  - Constructor `NewT` between T (with its sub-types) and T's methods.
  - A private impl of a public interface directly below the constructor returning it, struct then methods.
  - Utilities directly after their callers in call order, those with multiple callers after their last caller.
  - A type used by a single function just above it.

### Tests
- Maximize test coverage. A path is exempt only when exercising it is genuinely impossible (syscall failures that don't fail in practice, privileges the test env can't provide, hardware failures). Everything else is in scope no matter what it takes.
- Never modify prod code for the sake of tests. If a test needs that, propose first.
- You own test files outright, write them as you like. The rules are advisory in tests. They must pass the linter.

### Logging
- INF is what a user should always see, what the system is doing.
- DBG is what a developer needs when things go wrong, enough to pinpoint the failure. Verbose is fine, duplication isn't.
- Attach a value to the context, not the message, unless it belongs to that one message alone.

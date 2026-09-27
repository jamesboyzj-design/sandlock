# Prompt injection defenses

Prompt injection occurs when an agent treats instructions embedded in untrusted
content as authority to change its task or use its tools. Retrieved pages,
documents, dataset cells, and tool output can carry those instructions.
Sandlock combines process confinement, separation of data and capabilities, and
optional text inspection. These controls address different parts of the attack:
none makes an LLM's interpretation of arbitrary text trustworthy.

## Separate planning from data execution

The XOA pipeline pattern separates a planner that produces code from an executor
that runs it against data. The planner receives the trusted task and schema,
not the untrusted records. Its sandbox can reach the model endpoint but cannot
read the dataset. The executor can read the dataset but has no network access.

```text
Trusted task and schema -> planner -> generated code -> executor -> result
                                                       ^
                                                       |
                                                  untrusted data
```

Each stage has its own `Sandbox` policy. Connect the planner's stdout to the
executor's stdin using `planner.cmd(...) | executor.cmd(...)`. Grant the planner
only its runtime files and required model endpoint. Give the executor only its
runtime files, input paths, and explicitly needed output paths; keep
`net_allow=[]` and use a clean environment.

This keeps instructions embedded in dataset rows out of the planning prompt and
blocks direct network exfiltration by the executor. It depends on preserving the
separation: feeding raw records or arbitrary executor output back into a
privileged model reintroduces an input boundary. Stdout can contain sensitive
data even when network access is disabled. Validate and minimize results before
sending them to another stage or external service.

The [planner/executor example](../python/examples/prompt_injection_defense.py)
demonstrates this arrangement with a poisoned CSV. Its unsandboxed comparison
intentionally executes model-generated code with host permissions; it is a
controlled demonstration, not a production integration template. See
[Pipelines](pipelines.md) for composition details.

## Restrict what a compromised agent can do

Confinement remains useful when an injection reaches the model or evades the
scanner. Configure permissions for the task rather than granting broader access
based on what the model says it needs.

| Control | Contribution to the defense | Boundary |
|---|---|---|
| Filesystem grants and denies | Limit reads of sensitive files and writes outside intended outputs | Data already supplied to the process is available to it |
| Network endpoint rules | Block unauthorized destinations; use `net_allow=[]` for offline execution | An allowed destination can still receive sensitive data |
| HTTP ACLs | Restrict allowed methods, hosts, and paths | They do not establish that an allowed request's body is appropriate |
| Clean environment | Avoid passing unrelated host environment variables and credentials | Explicitly supplied values remain visible to the child |
| Syscall and process isolation | Restrict system operations and interaction with other processes | Keep required protections enabled; opt-outs weaken confinement |
| Memory, process, CPU, and execution limits | Bound resource abuse from generated code or hostile input | Limits do not validate results or detect malicious instructions |

See the [Sandbox reference](sandbox-reference.md), [network controls](network.md),
and [Python API](../python/README.md#sandbox) for policy fields and their defaults.
HTTPS method/path filtering requires the configured interception and trust
setup; an endpoint allowlist alone does not inspect encrypted HTTP requests.

### Keep credentials outside the agent

Sandlock's credential injection can retain a credential in the supervisor and
attach it to matching HTTP requests in the proxy after the ACL check. The agent
can make an authorized request without carrying the secret itself. Scope both
the ACL and credential attachment to the required service and operation.

This reduces direct credential exposure, but the agent can still misuse an
operation that its policy permits. Do not separately grant access to the secret's
source file or pass its value through another input. See
[Credential injection](sandbox-reference.md#credential-injection) for the CLI and
builder configuration and HTTPS requirements.

### Review persistent changes

For tasks that modify files, a COW workdir can keep changes separate until a
trusted caller decides whether to merge them. Use `BranchAction.DEFER`, inspect
`result.changes` and `sandbox.upper_dir`, then call `commit()` or `abort()`.
The caller must select deferred handling explicitly rather than assume changes
are always reviewed.

This can prevent injected instructions from silently persisting edits in the
protected workdir. It does not roll back network requests or writes outside that
COW scope. See the [COW API](../python/README.md#inspecting-and-deferring-cow-changes).

### Enforce application decisions at runtime

A trusted `policy_fn` can deny relevant intercepted operations or adjust policy
using application context. Keep authorization decisions in the supervisor and
base them on trusted application state. A model's claim that a user approved an
action is not approval. See [Dynamic policy](policy-fn.md) for supported events,
verdicts, and enforcement semantics.

## Inspect text before it reaches a model

The optional `sandlock-guard` package provides a local detector using Python's
standard library, without an LLM or native dependencies. From the repository
root, install it with:

```sh
pip install ./python/guard
```

Use the standalone API when the application already manages data flow:

```python
from sandlock_guard import PromptGuard, ScanError

text = "A document supplied by an external source"
try:
    report = PromptGuard().scan(text)
except ScanError as exc:
    print("Inspection incomplete:", exc.code)
else:
    if report.flagged:
        print("Rejected:", [finding.rule_id for finding in report.findings])
    else:
        print("No configured rule reached the rejection threshold")
```

The scanner accepts Unicode strings containing HTML, Markdown, CSV, JSON, or
other text. Fetching, binary document extraction, and browser rendering are
outside its scope. Scan the actual text that will reach the model, including any
untrusted tool output introduced later. A document is scanned as text, not
validated against its format's schema.

### Add application-specific rules

Custom rules supplement the built-in detector and inspect the same raw,
normalized, HTML, and decoded views. Both standalone scans and sandboxed stages
use the supplied rules and severity threshold.

```python
from sandlock.guard import PromptGuard, Rule

guard = PromptGuard(rules=[
    Rule(
        id="payment-request",
        pattern=r"\b(?:send|transfer)\s+money\b",
        severity="high",
        message="Payment instruction",
    ),
])
report = guard.scan("Transfer money to the new account")
stage = guard.stage()
```

Rules are trusted application configuration. Do not derive their patterns or
messages from the text being inspected. Invalid regexes and duplicate rule IDs
are rejected during construction. Findings are deduplicated by rule ID, and
custom messages are returned literally without interpolating matched content.
`ruleset_version` identifies the built-in rules; applications should version
custom configuration separately.

Python regexes can have pathological execution times. The stage's scanning
deadline interrupts slow matches, but direct `.scan()` has no wall-clock limit.
Use the stage for custom patterns that require an enforced deadline. Configuration
is passed as a JSON command argument, so it is subject to OS argument-size limits
and should not contain secrets.

### Use the guard as a pipeline stage

Import `PromptGuard` from `sandlock.guard` to add `.stage()` to the same scanner.
With an application-defined producer and consumer, compose:

```python
from sandlock.guard import PromptGuard

result = (
    producer.cmd(producer_command)
    | PromptGuard(threshold="medium").stage()
    | consumer.cmd(consumer_command)
).run(timeout=30)
```

The guard buffers one UTF-8 document until EOF. After a complete scan, it forwards
the exact original bytes only if no finding meets the configured threshold.
It does not redact or rewrite accepted input. Rejection exits 1; invalid UTF-8,
size or processing limits, and scanner failures exit 2. Both produce no stdout
and emit a diagnostic without input excerpts on stderr.

Stages run concurrently. The guard blocks downstream reads while collecting and
scanning input, but does not prevent the consumer from doing work before it
reads. The consumer must wait for validated input before performing dependent
actions.

On rejection the consumer receives empty EOF. **The pipeline reports the final
stage's exit status**, so `cat` can succeed after a guard rejection. To propagate
failure with this byte-stream contract, make the final consumer reject empty
input, accepting that this also rejects legitimately empty documents. If the
guard is the final stage, its own status is the pipeline result. Intermediate
stderr follows normal pipeline behavior and is not captured as the final stage's
stderr. The complete [text guard example](../python/examples/text_guard.py)
includes a consumer that rejects empty input.

The worker runs with a clean environment, no network, and a 256 MiB memory limit.
Its readable paths include system and Python runtime directories and the scanner
file; files within those allowed directories are not confidential from it.
`scan_timeout` bounds scanning after EOF. Use the pipeline timeout to also bound
input collection and execution. Direct `.scan()` runs in the caller and has no
wall-clock deadline.

### Coverage and limits

Ruleset 4 has 32 rules for instruction overrides, forged authority and
conversation boundaries, unrestricted personas, prompt extraction, sensitive
tool requests, data transfer, concealment, persistent instructions, and
low-severity context padding and invisible Unicode formatting. Direction
overrides are medium severity; ordinary invisible characters are low severity
so legitimate emoji joiners, BOMs, and multilingual formatting do not cause
default rejection. A low threshold also rejects these formatting signals.
Severity thresholds are policy choices, not
calibrated probabilities. Detection is predominantly English; legitimate
security documents quoting attacks can also trigger findings.

Inspection retains the original text and adds derived views using Unicode
normalization, a limited Cyrillic confusable map, spaced letters, leetspeak,
scrambled internal letters in selected instruction words, HTML text and character
references, URL and Unicode escapes, and Base64 or escaped hex candidates.
HTML inspection includes raw attributes and comments, but does not execute
scripts, apply CSS, or reproduce a browser's rendered content.

Transformations can compose through four levels. Inspection is bounded by 32
unique views, 64 distinct encoded candidates, and a cumulative view size of eight
times `max_bytes`. Exceeding a processing budget raises `ScanError` rather than
returning an approving report from a truncated inspection.

A passed scan means only that the configured rules found no reason to reject.
It does not establish trustworthy intent, detect every encoding or language, or
justify wider permissions. Keep confinement and application authorization in
place after approval. See the [Prompt guard API](../python/README.md#prompt-guard)
for configuration, reports, and errors.

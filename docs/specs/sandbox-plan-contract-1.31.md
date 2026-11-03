# Sandbox Plan contract 1.31

Contract 1.31 extends `SandboxPlanRequest2` with `credential_denials`, a bounded
list of additional absolute credential paths supplied by the trusted host. The
module combines these paths with the native roots derived from the registered
home. For a plan using process-level folder confinement, `SandboxArtifact2`
returns the canonical exclusion list as `deny_read`; the host passes it to
TinyBox without recomputing the credential floor.

The request list is limited to 64 absolute paths of at most 4096 bytes each.
NUL and parent-directory components are refused. The module includes lexical
and resolved aliases in the returned exclusions. A workspace or writable grant
inside a denied credential store is refused because excluding that store would
also remove the execution location.

`accept_process_isolation` applies only to a trusted host source outside SaaS
and permits a process-level jail such as macOS Seatbelt to provide folder
confinement. The resulting artifact continues to state
`minimum_isolation: process`; it never claims kernel isolation. Untrusted
sources and mandatory-isolation deployments still require an eligible kernel
or microVM executor.

OpenHuman's `SandboxMode::ReadOnly` is a host-side tool filter that removes
write and execute tools. It maps to no sandbox backend, with network allowed;
it does not create a filesystem-confinement claim or a `Plan2` artifact. The
host must preserve that tool filter independently of TinySecurity's sandbox
planner.

The artifact's `grants` are canonical, floor-checked, pre-admitted roots. Hosts
may use these roots directly at execution and must still revalidate TinyBox's
live capability and enforcement before launch.

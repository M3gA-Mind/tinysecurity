# Native scoped egress

The 1.4 contract implements immutable destination and original-data policies in
`tinysecurity-egress`, privately linked by the native module. Hosts link the bus
contract only. `RegisterEgressPolicy` is host configuration on a confidential
trusted channel; the JSON `SubjectScope` is not authentication. The adapter must
construct user, workspace, agent, access ceiling, classification and transport
capability from its verified operation. Public/model forwarding is unsupported.
A later authenticated TinyBus sender contract will enforce that channel boundary.

`ScopedUrlGuard` authorizes generic agent HTTP(S) destinations. `ScopedEgressCheck`
additionally supports an explicit host-local service capability. That capability
is an exact loopback IP origin, path and independently constructed host metadata
category; it never grants a generic agent URL access to private addresses.
`LocalOnly` blocks nonlocal requests before DNS. Hosts classify configured
provider endpoint hosts through `ClassifyProviderEndpoint2`: only loopback,
unspecified and `localhost` names are on-device. RFC 1918/LAN, link-local and
IPv6 unique-local hosts are external because they can name another device; no
DNS lookup is used to classify names. If classification fails, treat the
endpoint as external. See the
[contract 1.32 specification](specs/local-provider-endpoint-1.32.md).
`Sensitive` denies unassessed external user content; it allows only assessed
`none`/`low` user content with no identifying categories. Standard requires a declared
endpoint and data category. Sensitive additionally refuses credentials,
identifiers, unknown classification and original payloads, URLs or headers the
shared redactor changes. The descriptor is the registered policy's
`data_categories` plus the adapter-constructed request category: a category the
policy does not list, or `Unknown`, denies in every mode, and Sensitive denies
`Credentials` and `Identifiers` even when listed. Complete actual headers include host-injected credentials;
Host/authority/routing overrides and unsupported HTTP methods are refused.
Sensitive inspects UTF-8 plain text, JSON and form bodies. Form fields are
percent/+ decoded before independent credential/identifier checks; malformed
escapes or UTF-8, duplicate representation headers, unsupported media/charset
parameters and compressed encodings deny. Native calls use the active SDK
exact-secret registry. Transformation grants are
refused until a genuine approval and transformation engine exists.

Legacy `UrlGuard` and `EgressCheck` retain their strict serialized shapes and
always deny: per-request privacy/locality claims cannot grant authority. Empty
registered destination lists deny external access; wildcard rules are rejected
atomically. Exact rules may explicitly include canonical DNS subdomains, with
scheme and effective port binding. Public IPv6 is supported. Alternate numeric
IPv4, encoded authority, userinfo, zones and controls are refused. Every DNS
candidate passes the unconditional address floor, independently of policy or
autonomy. System DNS has a two-second wait, 64-answer bound and eight outstanding
worker bound; timed-out OS lookups may finish later, never blocking the SDK worker.

Authorizations bind the immutable owner/policy, effective generation, exact URL,
canonical hostname, port, complete vetted socket set and monotonic deadline.
`ConsumeEgressAuthorization` accepts only an exact issued live grant once, with
a SHA-256 fingerprint of the complete original scoped request. Fingerprints use
the UTF-8 `serde_json::to_vec` encoding in the contract field declaration order;
no caller URL, HTTP method, header order/value, payload or scope may change.
Expired, modified, replayed or previous-generation grants deny. Clock rollback
latches that scope closed. DNS authorizations are never cacheable across calls.
Successful reinit advances one shared generation before activation, so late old
DNS calls cannot issue grants or remove current ones. Invalid reinit retains the
effective policy and registries. Consume enforces the same URL/body/header and
aggregate bounds before checking membership and hashing; serialization/hashing
run off the sole SDK worker without registry locks.

This module does not implement generic HTTP execution. TinyTools and each other
transport owner must connect only to the approved sockets, preserve URL Host,
TLS SNI and hostname verification, disable automatic redirects and ambient
proxy/system DNS fallback, and enforce validity before send or retry. No claim
is made that current host transports consume this contract. Browser and proxy
routes without verified per-hop target enforcement deny. Redirects require a
fresh scoped check; a previous URL string cannot grant authority.

Contract 1.28 adds `AuthorizeBrowserDial`, `ConsumeBrowserDial`, and
`ValidateBrowserDial` for the browser's opaque CONNECT transport. The host
explicitly classifies these connections as `opaque_browser_traffic`; the
request carries the private proxy `session_id`, `expected_generation`, and the
destination scheme, canonical hostname, and port. It never carries a fabricated
HTTP method, body, or header fingerprint. The authorization binds the vetted
address set, scope, generation, deadline, and one-use nonce to that proxy
session; the transport consumes it for one exact `SocketAddr` immediately
before dialing. While a CONNECT or WebSocket tunnel is live, the transport must
call `ValidateBrowserDial`; it must close both sides if validation returns false
or the bus call fails. See the
[browser-dial contract 1.28 specification](specs/browser-dial-contract-1.28.md).
`Sensitive` and `LocalOnly` modes refuse opaque browser traffic. This grants no
HTTP payload approval and does not prove that a transport consumed the grant;
TinyComputer must enforce the proxy and pin the actual socket itself.

Sibling tests inject clocks/resolvers without third-party services. Test-only
HTTP/TLS executors use locally constructed fixture grants (never production
floor exemptions), retain the original hostname and nondefault port, perform no
second DNS, leave redirects unfollowed, assert SNI, and reject a wrong-host
certificate. These establish the pinning contract's feasibility, not protection
of an unrelated host transport. The checked-in TLS key/certificate are public
local test fixtures only, with no production authority.

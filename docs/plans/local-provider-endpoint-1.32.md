# Local provider endpoint implementation plan

1. Add the transport-free 1.32 request and response types and the advertised
   `ClassifyProviderEndpoint2` method name. Pin bounds, wire names and contract
   compatibility in bus tests.
2. Implement host-literal classification in `tinysecurity-egress`: parse with
   the existing URL dependency, avoid DNS, classify same-machine-reserved
   hosts only, and test loopback, mapped loopback, unspecified, LAN, ULA,
   link-local, names and malformed input.
3. Dispatch the method from the native module adapter and exercise it through
   the TinyBus service tests, including invalid bounded input.
4. Document how hosts feed the resulting locality into `PrivacyCheck2`, the
   fail-closed behavior, and the existing `Sensitive` assessment rule.
5. Run the focused bus, egress and module tests, then workspace fmt, Clippy,
   build and all-feature tests before opening the fork PR.

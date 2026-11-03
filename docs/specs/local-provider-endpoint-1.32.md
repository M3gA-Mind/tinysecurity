# Local provider endpoint classification (contract 1.32)

`ClassifyProviderEndpoint2` gives a host the module-owned locality decision used
by `LocalOnly` privacy checks. The request contains only the host component
returned by the host URL parser. TinySecurity performs no DNS lookup and does
not receive the provider URL's path, query, fragment, credentials or payload.

Only loopback and unspecified IP literals, IPv4-mapped loopback/unspecified
addresses, and `localhost` names (including subdomains) classify as `on_device`.
RFC 1918 addresses, IPv4 and IPv6 link-local addresses, IPv6 unique-local
addresses, and all other names classify as `external`. A private or link-local
address can name another device on the network; `LocalOnly` means the provider
is on this machine, not merely on the same LAN. The classifier does not resolve
names, so DNS aliases cannot turn an external hostname into a local endpoint.
Malformed or unrecognized host literals classify as external.

Hosts use the result as the `external` fact supplied to `PrivacyCheck2`. If the
classification call fails or the endpoint cannot be parsed, the host must treat
the transfer as external. The method is informational and does not authorize a
network connection or replace transport address validation.

The existing `Sensitive` privacy decision remains stricter than LocalOnly for
external user content: unassessed user content is denied; only a `none` or
`low` assessment with no identifying categories is allowed. Metadata remains
allowed, while control-plane requests are exempt in every mode.

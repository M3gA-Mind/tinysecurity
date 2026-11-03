//! Inventory regression against the hash-admitted, genuinely loaded artifact.
use std::collections::BTreeSet;
use tinybus::{
    module::{HostCallbackProxy, manifest::ModuleManifest},
    version::InterfaceVersion,
};
use tinysecurity_bus::{PolicyInfo, callback_names2, names};

pub(super) async fn verify(
    manifest: &ModuleManifest,
    proxy: &HostCallbackProxy,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy: PolicyInfo = proxy.call(names::methods::POLICY_INFO, ()).await?;
    let provided = manifest
        .provided(&names::INTERFACE.parse()?)
        .ok_or("loaded artifact omits policy interface")?;
    let methods: BTreeSet<_> = provided
        .methods
        .iter()
        .map(tinybus::MemberName::as_str)
        .collect();
    let canonical: BTreeSet<_> = names::METHODS.iter().copied().collect();
    let runtime: BTreeSet<_> = policy.capabilities.iter().map(String::as_str).collect();
    assert_eq!(
        methods, canonical,
        "loaded artifact must advertise every implemented permission method"
    );
    assert_eq!(
        methods.len(),
        provided.methods.len(),
        "no duplicate methods"
    );
    assert_eq!(
        methods, runtime,
        "manifest must agree with actual PolicyInfo"
    );
    assert_eq!(manifest.provides.len(), 1, "only policy is implemented");
    let expected: BTreeSet<_> = [
        callback_names2::AUDIT_SINK,
        callback_names2::APPROVAL_STORE,
        callback_names2::APPROVAL_PROMPT,
        callback_names2::SECRET_BACKEND,
        callback_names2::SECRET_CIPHER_CONSUMER,
        callback_names2::KEYRING_CONSENT,
        callback_names2::DEVICE_PAIRING_HOST,
    ]
    .into_iter()
    .collect();
    let required: BTreeSet<_> = manifest
        .requires
        .iter()
        .map(|dependency| dependency.interface.interface.as_str())
        .collect();
    assert_eq!(
        required, expected,
        "only implemented callbacks may be advertised"
    );
    assert_eq!(
        required.len(),
        manifest.requires.len(),
        "no duplicate callbacks"
    );
    for interface in expected {
        let dependency = manifest
            .requires
            .iter()
            .find(|d| d.interface.interface.as_str() == interface)
            .ok_or("missing implemented callback dependency")?;
        assert!(dependency.optional, "absent capabilities need no callback");
        assert_eq!(
            dependency.interface,
            InterfaceVersion::consumed(interface.parse()?, manifest.module.version.clone())
        );
    }
    Ok(())
}

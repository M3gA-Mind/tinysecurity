//! Synthetic sender-bound callback fixture shared by unit and native acceptance.
#[path = "../approval_native_contract/store.rs"]
pub(crate) mod store;
use std::sync::{Arc, Mutex};
use tinysecurity_bus::{
    AccessTier, ApprovalChoice2, ApprovalLifecycle2, ApprovalRow2, ApprovalScope2, AuditConfig2,
    AuditCorrelation2, DecideRequest2, DeviceConfig2, DeviceOperation2, DeviceRequest2,
    DeviceResponse2, DeviceScope2, EvaluateDeviceRequest2, ExecuteDeviceRequest2, Origin,
    SubjectScope, names,
};
pub(crate) fn audit(sequence: u64) -> AuditCorrelation2 {
    AuditCorrelation2 {
        event_id: format!("{sequence:032x}"),
        expected_tail: sequence - 1,
        generation: 1,
    }
}
pub(crate) fn registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "a".repeat(32),
        subject: SubjectScope {
            user: "fixture-user".into(),
            workspace: "fixture-workspace".into(),
            agent: "fixture-agent".into(),
        },
        policy_ref: "immutable-device-fixture".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
pub(crate) fn other_registration() -> ApprovalScope2 {
    ApprovalScope2 {
        scope_id: "b".repeat(32),
        subject: SubjectScope {
            user: "fixture-other-user".into(),
            workspace: "fixture-other-workspace".into(),
            agent: "fixture-other-agent".into(),
        },
        policy_ref: "immutable-other-device-fixture".into(),
        generation: 1,
        ceiling: AccessTier::Full,
        require_approval: true,
        auto_approve_all: false,
    }
}
pub(crate) fn device_config() -> DeviceConfig2 {
    DeviceConfig2 {
        scopes: vec![
            DeviceScope2 {
                scope_id: "a".repeat(32),
                origin: Origin::Operator,
                static_secret: Some([7; 32]),
            },
            DeviceScope2 {
                scope_id: "b".repeat(32),
                origin: Origin::Operator,
                static_secret: Some([8; 32]),
            },
        ],
        max_handles: 32,
        max_in_flight: 4,
        operations_per_minute: 4096,
        frames_per_minute: 12_000,
        max_ttl_ms: 300_000,
        max_message_bytes: 1024,
        max_bootstrap_nonces: 64,
    }
}
pub(crate) fn audit_config(native_path: Option<String>) -> AuditConfig2 {
    AuditConfig2 {
        scope: registration().subject,
        stream_id: "c".repeat(32),
        timeout_ms: 30_000,
        required: true,
        native_path,
        max_bytes: 1_000_000,
        max_archives: 3,
        journal_max_bytes: 4_000_000,
        journal_max_events: 10_000,
    }
}
pub(crate) fn request(instance: u64, operation: DeviceOperation2) -> DeviceRequest2 {
    DeviceRequest2 {
        scope_id: "a".repeat(32),
        call_id: format!("fixture-{instance}"),
        ttl_ms: 300_000,
        operation,
    }
}
pub(crate) async fn run_at(
    proxy: &tinybus::module::HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
    sequence: &mut u64,
    operation: DeviceOperation2,
    generation: u64,
) -> tinybus::Result<DeviceResponse2> {
    let request = request(*sequence, operation);
    let row: ApprovalRow2 = proxy
        .call_confidential(
            names::methods::EVALUATE_DEVICE2,
            (EvaluateDeviceRequest2 {
                request: request.clone(),
                audit: {
                    let mut audit = audit(*sequence);
                    audit.generation = generation;
                    audit
                },
            },),
        )
        .await?;
    let row = if row.state == ApprovalLifecycle2::Pending {
        let ticket = store
            .lock()
            .map_err(|_| tinybus::Error::failed("fixture store"))?
            .human_action(row.clone(), ApprovalChoice2::Once)?;
        let mut correlation = audit(*sequence + 1);
        correlation.generation = generation;
        proxy
            .call(
                names::methods::DECIDE2,
                (DecideRequest2 {
                    scope_id: "a".repeat(32),
                    request_id: row.request_id,
                    decision_ticket: ticket,
                    audit: correlation,
                },),
            )
            .await?
    } else {
        row
    };
    if row.state != ApprovalLifecycle2::Approved {
        return Err(tinybus::Error::failed("fixture approval"));
    }
    let result = proxy
        .call_confidential(
            names::methods::EXECUTE_DEVICE2,
            (ExecuteDeviceRequest2 {
                request,
                request_id: row.request_id,
                audit: {
                    let mut audit = audit(*sequence + 2);
                    audit.generation = generation;
                    audit
                },
            },),
        )
        .await;
    *sequence += 3;
    result
}

pub(crate) async fn run(
    proxy: &tinybus::module::HostCallbackProxy,
    store: &Arc<Mutex<store::DiskStore>>,
    sequence: &mut u64,
    operation: DeviceOperation2,
) -> tinybus::Result<DeviceResponse2> {
    run_at(proxy, store, sequence, operation, 1).await
}

//! Closed local Host Control v2 Connector lifecycle transport.
//!
//! The only executable is the immutable Host Supervisor path.  This module
//! deliberately has no remote transport, caller-controlled command, URL, or
//! environment seam.
#![allow(
    clippy::items_after_statements,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::single_char_pattern,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::unnecessary_map_or,
    reason = "wire construction mirrors the fixed six-field protocol and keeps secret material local"
)]
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt;
use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    deployment::{DeploymentManifest, DeploymentTarget},
    error::{ReleaseError, Result, io_error},
};

const SUPERVISOR: &str = "/usr/local/libexec/dirextalk/dtx-agent-host-supervisor";
const STATE_DIR: &str = ".dirextalk-connector-execution-state";
const MAX_FILE: u64 = 65_536;
const MAX_OUTPUT: usize = 65_536;
const OP_TIMEOUT: Duration = Duration::from_secs(45);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(45);

pub struct ConnectorApplyInputs {
    pub manifest: PathBuf,
    pub target: String,
    pub plan: PathBuf,
    pub handoff: PathBuf,
    pub config: PathBuf,
    pub enrollment_ca: PathBuf,
    pub control_ca: PathBuf,
    pub issuer_ca: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyResult {
    pub operation_id: String,
    pub lifecycle_operation_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorExecutionRecordV1 {
    schema: String,
    operation_id: String,
    lifecycle_operation_id: String,
    target: String,
    tenant_id: String,
    host_id: String,
    connector_id: String,
    adapter: String,
    release_sha256: String,
    expiry_millis: u64,
    plan_sha256: String,
    handoff_sha256: String,
    config_sha256: String,
    enrollment_ca_sha256: String,
    control_ca_sha256: String,
    issuer_ca_sha256: String,
    material_sha256: String,
    initial_desired_revision: u64,
    initial_observed_revision: Option<u64>,
    prepare_host_operation_id: String,
    start_host_operation_id: String,
    finalize_host_operation_id: String,
    phase: Phase,
    prepared_receipt_sha256: Option<String>,
    prepare_revision: Option<Revision>,
    prepare_response: Option<SanitizedV2Response>,
    observation_revision: Option<Revision>,
    finalized_receipt_sha256: Option<String>,
    finalize_response: Option<SanitizedV2Response>,
    integrity_sha256: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Claimed,
    Prepared,
    Started,
    Running,
    Finalized,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    desired: u64,
    #[serde(default)]
    observed: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SanitizedV2Response {
    application: String,
    disposition: String,
    lifecycle_state: String,
}
#[derive(Clone, Debug)]
struct PlanFacts {
    lifecycle_operation_id: String,
    tenant_id: String,
    host_id: String,
    connector_id: String,
    adapter: String,
    release_sha256: String,
    expiry_millis: u64,
}

trait Operator {
    fn invoke(&self, frame: &[u8]) -> Result<Vec<u8>>;
}
struct ProductionOperator;
impl Operator for ProductionOperator {
    fn invoke(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let mut child = Command::new(SUPERVISOR)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ReleaseError::CommandStart(SUPERVISOR.into()))?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| ReleaseError::CommandStart(SUPERVISOR.into()))?;
        input.write_all(frame).map_err(io_error(SUPERVISOR))?;
        drop(input);
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().map_err(io_error(SUPERVISOR))? {
                if !status.success() {
                    return Err(ReleaseError::CommandFailed {
                        program: SUPERVISOR.into(),
                        status,
                    });
                }
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ReleaseError::Deployment(
                    "host supervisor deadline exceeded".into(),
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| ReleaseError::CommandStart(SUPERVISOR.into()))?
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut out)
            .map_err(io_error(SUPERVISOR))?;
        if out.is_empty() || out.len() > MAX_OUTPUT {
            return Err(ReleaseError::Deployment(
                "host supervisor response is invalid".into(),
            ));
        }
        Ok(out)
    }
}

pub fn apply(inputs: ConnectorApplyInputs) -> Result<ApplyResult> {
    apply_with(inputs, &ProductionOperator)
}
fn apply_with(inputs: ConnectorApplyInputs, operator: &dyn Operator) -> Result<ApplyResult> {
    if geteuid().as_raw() != 0 {
        return Err(ReleaseError::Deployment(
            "deployment-connector-apply requires root".into(),
        ));
    }
    let manifest = DeploymentManifest::load(&inputs.manifest)?;
    let plan = secure_read(&inputs.plan, false)?;
    let handoff = secure_read(&inputs.handoff, true)?;
    let config = secure_read(&inputs.config, false)?;
    let enrollment = secure_read(&inputs.enrollment_ca, false)?;
    let control = secure_read(&inputs.control_ca, false)?;
    let issuer = secure_read(&inputs.issuer_ca, false)?;
    let facts = parse_plan(&plan)?;
    validate_manifest(&manifest, &inputs.target, &facts, &handoff)?;
    let root = std::env::current_dir()
        .map_err(io_error("."))?
        .join(STATE_DIR);
    ensure_dir(&root)?;
    let _lock = lock(&root.join(format!("{}.lock", facts.lifecycle_operation_id)))?;
    let record_path = root.join(format!("{}.json", facts.lifecycle_operation_id));
    let digests = MaterialDigests::new(&plan, &handoff, &config, &enrollment, &control, &issuer);
    let mut record = match read_record(&record_path)? {
        Some(record) => {
            verify_record(&record)?;
            record_matches(&record, &facts, &inputs.target, &digests)?;
            record
        }
        None => {
            let snapshot = snapshot(operator, &facts)?;
            let (desired, observed) = snapshot_identity(&snapshot, &facts)?;
            let r = ConnectorExecutionRecordV1 {
                schema: "dirextalk.deployer.connector-execution.v1".into(),
                operation_id: facts.lifecycle_operation_id.clone(),
                lifecycle_operation_id: facts.lifecycle_operation_id.clone(),
                target: inputs.target.clone(),
                tenant_id: facts.tenant_id.clone(),
                host_id: facts.host_id.clone(),
                connector_id: facts.connector_id.clone(),
                adapter: facts.adapter.clone(),
                release_sha256: facts.release_sha256.clone(),
                expiry_millis: facts.expiry_millis,
                plan_sha256: digests.plan.clone(),
                handoff_sha256: digests.handoff.clone(),
                config_sha256: digests.config.clone(),
                enrollment_ca_sha256: digests.enrollment.clone(),
                control_ca_sha256: digests.control.clone(),
                issuer_ca_sha256: digests.issuer.clone(),
                material_sha256: digests.material.clone(),
                initial_desired_revision: desired,
                initial_observed_revision: observed,
                prepare_host_operation_id: Uuid::now_v7().to_string(),
                start_host_operation_id: Uuid::now_v7().to_string(),
                finalize_host_operation_id: Uuid::now_v7().to_string(),
                phase: Phase::Claimed,
                prepared_receipt_sha256: None,
                prepare_revision: None,
                prepare_response: None,
                observation_revision: None,
                finalized_receipt_sha256: None,
                finalize_response: None,
                integrity_sha256: String::new(),
            };
            write_record(&record_path, &r)?;
            r
        }
    };
    let material = material(&config, &enrollment, &control, &issuer, &plan, &handoff)?;
    if record.phase == Phase::Claimed {
        let response = invoke_v2(
            operator,
            &record,
            "prepare_connector_material",
            record.initial_desired_revision,
            record.initial_observed_revision,
            &material,
            None,
        )?;
        let (revision, receipt, summary) = v2_result(&response, "prepared")?;
        record.prepare_revision = Some(revision);
        record.prepared_receipt_sha256 = Some(receipt);
        record.prepare_response = Some(summary);
        record.phase = Phase::Prepared;
        write_record(&record_path, &record)?;
    }
    if record.phase == Phase::Prepared {
        let rev = record
            .prepare_revision
            .clone()
            .ok_or_else(|| ReleaseError::Deployment("missing persisted prepare revision".into()))?;
        let response = start(operator, &record, &rev)?;
        let revision = v1_revision(&response)?;
        record.observation_revision = Some(revision);
        record.phase = Phase::Started;
        write_record(&record_path, &record)?;
    }
    if record.phase == Phase::Started {
        let revision = observe_running(operator, &record)?;
        record.observation_revision = Some(revision);
        record.phase = Phase::Running;
        write_record(&record_path, &record)?;
    }
    if record.phase == Phase::Running {
        let rev = record.observation_revision.clone().ok_or_else(|| {
            ReleaseError::Deployment("missing persisted observation revision".into())
        })?;
        let receipt = record
            .prepared_receipt_sha256
            .clone()
            .ok_or_else(|| ReleaseError::Deployment("missing prepared receipt".into()))?;
        let response = invoke_v2(
            operator,
            &record,
            "finalize_connector_material",
            rev.desired,
            rev.observed,
            &material,
            Some(receipt),
        )?;
        let (_, finalized, summary) = v2_result(&response, "finalized")?;
        record.finalized_receipt_sha256 = Some(finalized);
        record.finalize_response = Some(summary);
        record.phase = Phase::Finalized;
        write_record(&record_path, &record)?;
    }
    Ok(ApplyResult {
        operation_id: record.operation_id,
        lifecycle_operation_id: record.lifecycle_operation_id,
        state: "finalized".into(),
    })
}

struct MaterialDigests {
    plan: String,
    handoff: String,
    config: String,
    enrollment: String,
    control: String,
    issuer: String,
    material: String,
}
impl MaterialDigests {
    fn new(p: &[u8], h: &[u8], c: &[u8], e: &[u8], co: &[u8], i: &[u8]) -> Self {
        let material = material(c, e, co, i, p, h).expect("bounded material");
        Self {
            plan: hash(p),
            handoff: hash(h),
            config: hash(c),
            enrollment: hash(e),
            control: hash(co),
            issuer: hash(i),
            material: hash(&material),
        }
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn material(c: &[u8], e: &[u8], co: &[u8], i: &[u8], p: &[u8], h: &[u8]) -> Result<Vec<u8>> {
    let fields = [c, e, co, i, p, h];
    let limits = [65536, 65536, 65536, 65536, 65536, 65536];
    if fields
        .iter()
        .zip(limits)
        .any(|(x, n)| x.is_empty() || x.len() > n)
    {
        return Err(ReleaseError::Deployment(
            "invalid bootstrap material".into(),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"DTXBMT01");
    for f in fields {
        out.extend_from_slice(
            &(u32::try_from(f.len())
                .map_err(|_| ReleaseError::Deployment("material too large".into()))?)
            .to_be_bytes(),
        );
    }
    for f in fields {
        out.extend_from_slice(f);
    }
    if out.len() > 384 * 1024 {
        return Err(ReleaseError::Deployment("material too large".into()));
    }
    Ok(out)
}
fn invoke_v2(
    operator: &dyn Operator,
    r: &ConnectorExecutionRecordV1,
    op: &str,
    desired: u64,
    observed: Option<u64>,
    material: &[u8],
    receipt: Option<String>,
) -> Result<Value> {
    let header = json!({"protocol":"dirextalk.host-control.operator.v2","tenant_id":r.tenant_id,"host_id":r.host_id,"host_operation_id":if op=="prepare_connector_material" {&r.prepare_host_operation_id} else {&r.finalize_host_operation_id},"expected_desired_revision":desired,"expected_observed_revision":observed,"connector_id":r.connector_id,"adapter":r.adapter,"approved_release_sha256":r.release_sha256,"lifecycle_operation_id":r.lifecycle_operation_id,"platform_target":platform()?,"expiry_millis":r.expiry_millis,"plan_sha256":r.plan_sha256,"handoff_sha256":r.handoff_sha256,"config_sha256":r.config_sha256,"enrollment_ca_sha256":r.enrollment_ca_sha256,"control_ca_sha256":r.control_ca_sha256,"issuer_ca_sha256":r.issuer_ca_sha256,"lifecycle_material_sha256":r.material_sha256,"payload_sha256":r.material_sha256,"prepared_receipt_sha256":receipt,"operation":op});
    let header = serde_json::to_vec(&header)?;
    let mut frame = Vec::new();
    frame.extend_from_slice(b"DTXHC02\0");
    frame.extend_from_slice(
        &(u32::try_from(header.len())
            .map_err(|_| ReleaseError::Deployment("header too large".into()))?)
        .to_be_bytes(),
    );
    frame.extend_from_slice(&header);
    frame.extend_from_slice(
        &(u32::try_from(material.len())
            .map_err(|_| ReleaseError::Deployment("material too large".into()))?)
        .to_be_bytes(),
    );
    frame.extend_from_slice(material);
    parse_response(&operator.invoke(&frame)?)
}
fn snapshot(o: &dyn Operator, f: &PlanFacts) -> Result<Value> {
    v1(o, &f.tenant_id, &f.host_id, json!({"kind":"snapshot"}))
}
fn start(o: &dyn Operator, r: &ConnectorExecutionRecordV1, rev: &Revision) -> Result<Value> {
    v1(
        o,
        &r.tenant_id,
        &r.host_id,
        json!({"kind":"execute","operation_id":r.start_host_operation_id,"expected_desired_revision":rev.desired,"expected_observed_revision":rev.observed,"command":{"command":"start","connector_id":r.connector_id}}),
    )
}
fn observe_running(o: &dyn Operator, r: &ConnectorExecutionRecordV1) -> Result<Revision> {
    let deadline = Instant::now() + OBSERVE_TIMEOUT;
    loop {
        let v = v1(
            o,
            &r.tenant_id,
            &r.host_id,
            json!({"kind":"observe","connector_id":r.connector_id}),
        )?;
        let result = v
            .get("result")
            .ok_or_else(|| ReleaseError::Deployment("invalid observe response".into()))?;
        if result.get("actual_observation").and_then(Value::as_str) == Some("running") {
            return v1_revision(&v);
        }
        if Instant::now() >= deadline {
            return Err(ReleaseError::Deployment(
                "connector did not reach Running".into(),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn v1(o: &dyn Operator, tenant: &str, host: &str, request: Value) -> Result<Value> {
    let header = serde_json::to_vec(
        &json!({"protocol":"dirextalk.host-control.operator.v1","tenant_id":tenant,"host_id":host,"request":request}),
    )?;
    let mut frame = Vec::new();
    frame.extend_from_slice(b"DTXHC01\0");
    frame.extend_from_slice(
        &(u32::try_from(header.len())
            .map_err(|_| ReleaseError::Deployment("header too large".into()))?)
        .to_be_bytes(),
    );
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&0u32.to_be_bytes());
    parse_response(&o.invoke(&frame)?)
}
fn parse_response(bytes: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(bytes)?;
    if v.get("status").and_then(Value::as_str) != Some("succeeded") {
        return Err(ReleaseError::Deployment(
            "host supervisor rejected request".into(),
        ));
    }
    Ok(v)
}
fn v2_result(v: &Value, name: &str) -> Result<(Revision, String, SanitizedV2Response)> {
    let r = v
        .get("result")
        .ok_or_else(|| ReleaseError::Deployment("invalid v2 response".into()))?;
    let rev = Revision {
        desired: r
            .get("desired_revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReleaseError::Deployment("missing v2 revision".into()))?,
        observed: r.get("observed_revision").and_then(Value::as_u64),
    };
    let key = format!("{name}_receipt_sha256");
    let receipt = r
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| is_digest(s))
        .ok_or_else(|| ReleaseError::Deployment("missing receipt digest".into()))?
        .to_owned();
    let string = |key| {
        r.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ReleaseError::Deployment("invalid v2 response".into()))
    };
    let summary = SanitizedV2Response {
        application: string("application")?,
        disposition: string("disposition")?,
        lifecycle_state: string("lifecycle_state")?,
    };
    Ok((rev, receipt, summary))
}
fn v1_revision(v: &Value) -> Result<Revision> {
    let x = &v["result"]["revision"];
    Ok(Revision {
        desired: x["desired"]
            .as_u64()
            .ok_or_else(|| ReleaseError::Deployment("missing v1 revision".into()))?,
        observed: x["observed"].as_u64(),
    })
}
fn platform() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("linux-amd64"),
        "aarch64" => Ok("linux-arm64"),
        _ => Err(ReleaseError::Deployment("unsupported host platform".into())),
    }
}
fn parse_plan(bytes: &[u8]) -> Result<PlanFacts> {
    let p: Value = serde_json::from_slice(bytes)?;
    let string = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ReleaseError::Deployment(format!("invalid bootstrap plan {k}")))
    };
    if string(&p, "schema")? != "dirextalk.connector-bootstrap-plan"
        || p.get("schema_version").and_then(Value::as_u64) != Some(1)
        || string(&p, "state")? != "issued"
    {
        return Err(ReleaseError::Deployment(
            "invalid bootstrap plan identity".into(),
        ));
    }
    let host = p
        .get("host")
        .ok_or_else(|| ReleaseError::Deployment("missing bootstrap host".into()))?;
    let connector = p
        .get("connector")
        .ok_or_else(|| ReleaseError::Deployment("missing bootstrap connector".into()))?;
    let artifact = p
        .get("connector_artifact")
        .ok_or_else(|| ReleaseError::Deployment("missing bootstrap artifact".into()))?;
    let f = PlanFacts {
        lifecycle_operation_id: string(&p, "operation_id")?,
        tenant_id: string(host, "tenant_id")?,
        host_id: string(host, "host_id")?,
        connector_id: string(connector, "instance_id")?,
        adapter: string(connector, "adapter_kind")?,
        release_sha256: string(artifact, "digest")?,
        expiry_millis: connector
            .get("expires_at_millis")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReleaseError::Deployment("invalid bootstrap expiry".into()))?,
    };
    if !is_uuid7(&f.lifecycle_operation_id)
        || !is_uuid7(&f.tenant_id)
        || !is_uuid7(&f.host_id)
        || !is_uuid7(&f.connector_id)
        || !is_digest(&f.release_sha256)
        || f.expiry_millis == 0
        || !matches!(
            f.adapter.as_str(),
            "codex" | "openclaw_acp" | "eino" | "rig" | "claude_code" | "custom_acp" | "hermes_acp"
        )
    {
        return Err(ReleaseError::Deployment(
            "invalid bootstrap plan facts".into(),
        ));
    }
    Ok(f)
}
fn validate_manifest(
    m: &DeploymentManifest,
    target: &str,
    f: &PlanFacts,
    handoff: &[u8],
) -> Result<()> {
    let t = m
        .contract()
        .targets
        .iter()
        .find(|t| t.id() == target)
        .ok_or_else(|| ReleaseError::Deployment("target absent from manifest".into()))?;
    let DeploymentTarget::ConnectorHost {
        host, connectors, ..
    } = t
    else {
        return Err(ReleaseError::Deployment(
            "target is not a connector host".into(),
        ));
    };
    if host.tenant_id != f.tenant_id
        || host.host_id != f.host_id
        || m.contract().connector.digest != f.release_sha256
    {
        return Err(ReleaseError::Deployment(
            "manifest and plan mismatch".into(),
        ));
    }
    let binding = connectors
        .iter()
        .find(|c| c.instance_id == f.connector_id)
        .ok_or_else(|| ReleaseError::Deployment("connector absent from target".into()))?;
    if format!("{:?}", binding.adapter_kind)
        .to_lowercase()
        .replace("_", "")
        != f.adapter.replace("_", "")
        || binding.handoff_digest != hash(handoff)
    {
        return Err(ReleaseError::Deployment(
            "connector binding mismatch".into(),
        ));
    }
    Ok(())
}
fn snapshot_identity(v: &Value, f: &PlanFacts) -> Result<(u64, Option<u64>)> {
    let h = &v["result"]["host"];
    if h["tenant_id"].as_str() != Some(&f.tenant_id) || h["host_id"].as_str() != Some(&f.host_id) {
        return Err(ReleaseError::Deployment(
            "snapshot identity mismatch".into(),
        ));
    }
    let r = &h["revision"];
    let d = r["desired"]
        .as_u64()
        .filter(|x| *x > 0)
        .ok_or_else(|| ReleaseError::Deployment("invalid snapshot revision".into()))?;
    let o = r["observed"].as_u64();
    if o.is_some_and(|x| x > d) {
        return Err(ReleaseError::Deployment("invalid snapshot revision".into()));
    }
    Ok((d, o))
}
fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn is_uuid7(s: &str) -> bool {
    Uuid::parse_str(s).is_ok_and(|u| u.get_version_num() == 7)
}
fn ensure_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let descriptor = match open(
        p,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            rustix::fs::mkdir(p, Mode::from_raw_mode(0o700))
                .map_err(|e| io_error(p)(std::io::Error::from(e)))?;
            open(
                p,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|e| io_error(p)(std::io::Error::from(e)))?
        }
        Err(e) => return Err(io_error(p)(std::io::Error::from(e))),
    };
    let directory: fs::File = descriptor.into();
    let m = directory.metadata().map_err(io_error(p))?;
    if !m.is_dir() || m.mode() & 0o777 != 0o700 || m.uid() != geteuid().as_raw() {
        return Err(ReleaseError::StateUnsafe(p.into()));
    }
    Ok(())
}
fn lock(p: &Path) -> Result<fs::File> {
    let fd = open(
        p,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| io_error(p)(std::io::Error::from(e)))?;
    let f: fs::File = fd.into();
    f.try_lock_exclusive().map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            ReleaseError::OperationLocked
        } else {
            io_error(p)(e)
        }
    })?;
    Ok(f)
}
fn secure_read(p: &Path, protected: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let fd = open(
        p,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| io_error(p)(std::io::Error::from(e)))?;
    let f: fs::File = fd.into();
    let m = f.metadata().map_err(io_error(p))?;
    let mode = m.mode() & 0o777;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > MAX_FILE
        || (protected && (mode != 0o600 || m.uid() != 0))
    {
        return Err(ReleaseError::UnsafeFile(p.into()));
    }
    let mut b = Vec::new();
    f.take(MAX_FILE + 1)
        .read_to_end(&mut b)
        .map_err(io_error(p))?;
    if b.len() as u64 != m.len() {
        return Err(ReleaseError::UnsafeFile(p.into()));
    }
    Ok(b)
}
fn read_record(p: &Path) -> Result<Option<ConnectorExecutionRecordV1>> {
    if !p.exists() {
        return Ok(None);
    }
    let b = secure_read(p, true)?;
    Ok(Some(serde_json::from_slice(&b)?))
}
fn write_record(p: &Path, r: &ConnectorExecutionRecordV1) -> Result<()> {
    let mut c = r.clone();
    c.integrity_sha256.clear();
    c.integrity_sha256 = hash(&serde_json::to_vec(&c)?);
    let b = serde_json::to_vec(&c)?;
    let tmp = p.with_extension(format!("{}.tmp", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io_error(&tmp))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = f.metadata().map_err(io_error(&tmp))?.permissions();
        permissions.set_mode(0o600);
        f.set_permissions(permissions).map_err(io_error(&tmp))?;
    }
    f.write_all(&b)
        .and_then(|()| f.sync_all())
        .map_err(io_error(&tmp))?;
    fs::rename(&tmp, p).map_err(io_error(p))?;
    Ok(())
}
fn verify_record(r: &ConnectorExecutionRecordV1) -> Result<()> {
    let mut c = r.clone();
    let digest = std::mem::take(&mut c.integrity_sha256);
    if !is_digest(&digest) || hash(&serde_json::to_vec(&c)?) != digest {
        return Err(ReleaseError::Deployment(
            "execution record integrity mismatch".into(),
        ));
    }
    Ok(())
}
fn record_matches(
    r: &ConnectorExecutionRecordV1,
    f: &PlanFacts,
    target: &str,
    d: &MaterialDigests,
) -> Result<()> {
    if r.schema != "dirextalk.deployer.connector-execution.v1"
        || r.target != target
        || r.lifecycle_operation_id != f.lifecycle_operation_id
        || r.tenant_id != f.tenant_id
        || r.host_id != f.host_id
        || r.connector_id != f.connector_id
        || r.adapter != f.adapter
        || r.release_sha256 != f.release_sha256
        || r.expiry_millis != f.expiry_millis
        || r.plan_sha256 != d.plan
        || r.handoff_sha256 != d.handoff
        || r.config_sha256 != d.config
        || r.enrollment_ca_sha256 != d.enrollment
        || r.control_ca_sha256 != d.control
        || r.issuer_ca_sha256 != d.issuer
        || r.material_sha256 != d.material
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingOperator(Mutex<Vec<Vec<u8>>>);
    impl Operator for RecordingOperator {
        fn invoke(&self, frame: &[u8]) -> Result<Vec<u8>> {
            self.0.lock().expect("lock").push(frame.to_vec());
            Ok(
                br#"{"status":"succeeded","result":{"revision":{"desired":2,"observed":2}}}"#
                    .to_vec(),
            )
        }
    }

    #[test]
    fn v1_operator_seam_emits_closed_start_frame() {
        let operator = RecordingOperator(Mutex::new(Vec::new()));
        let response = v1(
            &operator,
            "0197f1f0-0000-7000-8000-000000000001",
            "0197f1f0-0000-7000-8000-000000000002",
            json!({"kind":"execute","operation_id":"0197f1f0-0000-7000-8000-000000000003","expected_desired_revision":1,"expected_observed_revision":1,"command":{"command":"start","connector_id":"0197f1f0-0000-7000-8000-000000000004"}}),
        ).expect("response");
        assert_eq!(v1_revision(&response).expect("revision").desired, 2);
        let calls = operator.0.lock().expect("lock");
        assert_eq!(&calls[0][..8], b"DTXHC01\0");
        assert!(
            !calls[0]
                .windows(SUPERVISOR.len())
                .any(|x| x == SUPERVISOR.as_bytes())
        );
    }

    #[test]
    fn material_is_bounded_and_deterministic() {
        let bytes = material(
            b"config",
            b"enrollment",
            b"control",
            b"issuer",
            b"plan",
            b"handoff",
        )
        .expect("material");
        assert_eq!(&bytes[..8], b"DTXBMT01");
        assert_eq!(hash(&bytes), hash(&bytes));
        assert!(material(&[], b"e", b"c", b"i", b"p", b"h").is_err());
    }
}

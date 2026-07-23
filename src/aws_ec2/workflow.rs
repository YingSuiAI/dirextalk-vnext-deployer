use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::Ipv4Addr,
    path::Path,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::bundle::{BundleFacts, InstallRequest, InstalledReceipt, hash};
use super::provision::{HostReadyReceipt, ProvisionRequest};
use super::store::Store;
use super::{
    AWS, AmiRecord, AwsEc2Manifest, AwsExecutor, BundleRecord, CURL, Ec2State, EipRecord,
    FixedCommand, GETENT, HEALTH_PATH, HostKeyRecord, InfrastructureRecord, KeyRecord,
    LifecyclePhase, OwnedRecordSet, REGION, REMOTE_BUNDLE, REMOTE_CURRENT_RECEIPT,
    REMOTE_INSTALLER, REMOTE_INSTALLER_ATOMIC, REMOTE_INSTALLER_UPLOAD, REMOTE_PROVISION_REQUEST,
    REMOTE_PROVISIONER, REMOTE_PROVISIONER_ATOMIC, REMOTE_PROVISIONER_UPLOAD, REMOTE_READY_RECEIPT,
    REMOTE_RECEIPT_READER, REMOTE_RECEIPT_READER_ATOMIC, REMOTE_RECEIPT_READER_UPLOAD,
    REMOTE_REQUEST, ReceiptState, RegistryExecutor, SCP, SSH, SSH_KEYGEN, SSH_KEYSCAN,
    StatusReport, UBUNTU_OWNER, UBUNTU_PATTERN, VerifyReport, contract, enforce_cost_guard,
    expected_tags, resolve_latest_digest,
};
use crate::{ReleaseError, Result};

const APPLY_BUNDLE_SUFFIX: &str = "current.bundle";
const APPLY_REQUEST_SUFFIX: &str = "current.request";
const USER_DATA_SUFFIX: &str = "cloud-init.yaml";
pub(crate) const PRIVATE_KEY_SUFFIX: &str = "id_ed25519";
const PUBLIC_KEY_SUFFIX: &str = "id_ed25519.pub";
const KNOWN_HOSTS_SUFFIX: &str = "known_hosts";
const PROVISION_REQUEST_SUFFIX: &str = "current.provision";
const UPDATE_BUNDLE_SUFFIX: &str = "update-candidate.bundle";
const UPDATE_REQUEST_SUFFIX: &str = "update-candidate.request";
const ROLLBACK_REQUEST_SUFFIX: &str = "rollback.request";
const UPDATE_CAPACITY_BYTES: u64 = 128 * 1024 * 1024;
const UPDATE_CAPACITY_INODES: u64 = 128;

pub fn apply(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    max_monthly_usd: u32,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let facts = manifest.bundle()?;
    let estimate = enforce_cost_guard(manifest, max_monthly_usd)?;
    if !execute {
        return new_state(manifest, &facts, estimate, max_monthly_usd);
    }
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = if let Some(state) = read_verified_state(&store)? {
        ensure_apply_resumable_phase(&state.phase)?;
        ensure_apply_identity(&state, manifest, &facts)?;
        state
    } else {
        let mut state = new_state(manifest, &facts, estimate, max_monthly_usd)?;
        persist(&store, &mut state)?;
        state
    };
    bind_account(&store, &mut state, executor)?;
    resolve_ami(&store, &mut state, executor)?;
    ensure_key(&store, &mut state, manifest, executor)?;
    ensure_security_group(&store, &mut state, manifest, executor)?;
    ensure_instance(&store, &mut state, manifest, executor)?;
    ensure_eip(&store, &mut state, executor)?;
    ensure_dns(&store, &mut state, executor)?;
    ensure_host_key(&store, &mut state, executor)?;
    ensure_host_helpers(&store, &mut state, manifest, &facts, executor)?;
    if state.current.is_none() {
        install_initial(&store, &mut state, manifest, &facts, executor)?;
    }
    if state.host_ready_receipt.is_none() {
        provision_initial(&store, &mut state, manifest, &facts, executor)?;
    }
    let report = verify_live_locked(&store, &mut state, manifest, executor)?;
    state.phase = LifecyclePhase::Verified;
    state.pending_effect = None;
    persist(&store, &mut state)?;
    debug_assert_eq!(report.server_image, manifest.server_image);
    Ok(state)
}

pub fn resume(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    max_monthly_usd: u32,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    manifest.bundle()?;
    enforce_cost_guard(manifest, max_monthly_usd)?;
    let state = {
        let store = Store::lock(state_dir, &manifest.target)?;
        load_state(&store, manifest)?
    };
    ensure_apply_resumable_phase(&state.phase)?;
    if !execute {
        return Ok(state);
    }
    apply(manifest, state_dir, max_monthly_usd, true, executor)
}

fn ensure_apply_resumable_phase(phase: &LifecyclePhase) -> Result<()> {
    match phase {
        LifecyclePhase::Planned
        | LifecyclePhase::AccountBound
        | LifecyclePhase::AmiResolved
        | LifecyclePhase::KeyReady
        | LifecyclePhase::SecurityGroupReady
        | LifecyclePhase::InstanceReady
        | LifecyclePhase::EipReady
        | LifecyclePhase::DnsReady
        | LifecyclePhase::HostKeyPinned
        | LifecyclePhase::ProvisionPending
        | LifecyclePhase::Provisioning
        | LifecyclePhase::HostReady
        | LifecyclePhase::Installed
        | LifecyclePhase::Verified => Ok(()),
        LifecyclePhase::UpdateStaged
        | LifecyclePhase::UpdateInstalling
        | LifecyclePhase::UpdateVerifying
        | LifecyclePhase::RollbackStaged
        | LifecyclePhase::RollbackInstalling
        | LifecyclePhase::RolledBack => Err(contract(
            "apply/resume refuses update or rollback lifecycle state",
        )),
        LifecyclePhase::Destroying
        | LifecyclePhase::InfrastructureRemovedVolumeRetained
        | LifecyclePhase::VolumePurged => Err(contract(
            "apply/resume refuses destroying or terminal lifecycle state",
        )),
    }
}

fn new_state(
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
    estimate: u64,
    max_monthly_usd: u32,
) -> Result<Ec2State> {
    let operation_id = Uuid::now_v7().to_string();
    let client_token = operation_id.clone();
    let client_token_sha256 = hash(client_token.as_bytes());
    let mut ownership_tags = BTreeMap::new();
    ownership_tags.insert("DirextalkManaged".into(), "true".into());
    ownership_tags.insert("DirextalkTarget".into(), manifest.target.clone());
    ownership_tags.insert("DirextalkOperation".into(), operation_id.clone());
    ownership_tags.insert(
        "DirextalkClientTokenSha256".into(),
        client_token_sha256.clone(),
    );
    ownership_tags.insert("DirextalkDomain".into(), manifest.domain.clone());
    Ec2State {
        schema: "dirextalk.aws-ec2-lifecycle".into(),
        schema_version: 1,
        operation_id,
        client_token,
        client_token_sha256,
        target: manifest.target.clone(),
        account_id: None,
        region: REGION.into(),
        domain: manifest.domain.clone(),
        tenant_id: Uuid::now_v7().to_string(),
        indexer_id: Uuid::now_v7().to_string(),
        ownership_tags,
        monthly_estimate_cents: estimate,
        max_monthly_usd,
        infrastructure: InfrastructureRecord::from_manifest(manifest),
        desired: BundleRecord::from_facts(facts, manifest),
        current: None,
        previous: None,
        ami: None,
        key: None,
        vpc_id: None,
        security_group_id: None,
        instance_id: None,
        private_ipv4: None,
        volume_id: None,
        eip: None,
        dns: None,
        host_key: None,
        current_receipt: None,
        previous_receipt: None,
        rollback_receipt: None,
        host_ready_receipt: None,
        current_bundle_suffix: None,
        current_request_suffix: None,
        previous_bundle_suffix: None,
        previous_request_suffix: None,
        candidate_bundle_suffix: None,
        candidate_request_suffix: None,
        provision_request_suffix: None,
        phase: LifecyclePhase::Planned,
        pending_effect: None,
        retained_volume: false,
        integrity_sha256: String::new(),
    }
    .seal()
}

fn ensure_apply_identity(
    state: &Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
) -> Result<()> {
    if state.target != manifest.target
        || state.region != manifest.region
        || state.domain != manifest.domain
        || state.infrastructure != InfrastructureRecord::from_manifest(manifest)
        || state.desired != BundleRecord::from_facts(facts, manifest)
        || state
            .key
            .as_ref()
            .is_some_and(|key| key.key_name != manifest.key_name)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn persist(store: &Store, state: &mut Ec2State) -> Result<()> {
    *state = state.clone().seal()?;
    store.write(state)
}

fn before_effect(store: &Store, state: &mut Ec2State, effect: &str) -> Result<()> {
    state.pending_effect = Some(effect.into());
    persist(store, state)
}

fn after_effect(store: &Store, state: &mut Ec2State) -> Result<()> {
    state.pending_effect = None;
    persist(store, state)
}

pub(super) fn run_effect(
    store: &Store,
    state: &mut Ec2State,
    command: &FixedCommand,
    executor: &dyn AwsExecutor,
) -> Result<super::ExecOutput> {
    before_effect(store, state, &command.id)?;
    let output = executor.run(command)?;
    after_effect(store, state)?;
    Ok(output)
}

fn bind_account(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let output = executor.run(&FixedCommand::new(
        "get-caller-identity",
        AWS,
        ["sts", "get-caller-identity", "--output", "json"],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let account = value["Account"]
        .as_str()
        .ok_or_else(|| contract("AWS caller account is missing"))?;
    if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(contract("AWS caller account is malformed"));
    }
    if state
        .account_id
        .as_deref()
        .is_some_and(|old| old != account)
    {
        return Err(ReleaseError::OperationConflict);
    }
    state.account_id = Some(account.into());
    state.phase = LifecyclePhase::AccountBound;
    persist(store, state)
}

fn resolve_ami(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    if state.ami.is_some() {
        return Ok(());
    }
    let output = executor.run(&FixedCommand::new(
        "resolve-ubuntu-ami",
        AWS,
        [
            "ec2",
            "describe-images",
            "--region",
            REGION,
            "--owners",
            UBUNTU_OWNER,
            "--filters",
            &format!("Name=name,Values={UBUNTU_PATTERN}"),
            "Name=architecture,Values=x86_64",
            "Name=root-device-type,Values=ebs",
            "Name=virtualization-type,Values=hvm",
            "Name=state,Values=available",
            "--output",
            "json",
        ],
        false,
        45,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let images = value["Images"]
        .as_array()
        .ok_or_else(|| contract("AWS AMI response is malformed"))?;
    let mut candidates = Vec::new();
    for image in images {
        let record = AmiRecord {
            image_id: json_string(image, "ImageId")?,
            name: json_string(image, "Name")?,
            creation_date: json_string(image, "CreationDate")?,
            owner_id: json_string(image, "OwnerId")?,
            architecture: json_string(image, "Architecture")?,
            root_device_type: json_string(image, "RootDeviceType")?,
            virtualization_type: json_string(image, "VirtualizationType")?,
        };
        validate_ami(&record)?;
        candidates.push(record);
    }
    candidates.sort_by(|left, right| left.creation_date.cmp(&right.creation_date));
    let latest = candidates
        .pop()
        .ok_or_else(|| contract("Canonical Ubuntu 24.04 amd64 AMI is unavailable"))?;
    if candidates
        .last()
        .is_some_and(|other| other.creation_date == latest.creation_date)
    {
        return Err(contract("latest Canonical AMI selection is ambiguous"));
    }
    state.ami = Some(latest);
    state.phase = LifecyclePhase::AmiResolved;
    persist(store, state)
}

fn validate_ami(ami: &AmiRecord) -> Result<()> {
    let prefix = UBUNTU_PATTERN.trim_end_matches('*');
    if ami.owner_id != UBUNTU_OWNER
        || !ami.name.starts_with(prefix)
        || ami.architecture != "x86_64"
        || ami.root_device_type != "ebs"
        || ami.virtualization_type != "hvm"
        || !ami.image_id.starts_with("ami-")
        || ami.creation_date.is_empty()
    {
        return Err(contract("AMI is outside the Canonical Ubuntu allowlist"));
    }
    Ok(())
}

fn ensure_key(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let private = store.artifact_path(PRIVATE_KEY_SUFFIX)?;
    let public = store.artifact_path(PUBLIC_KEY_SUFFIX)?;
    if state.key.is_none() {
        let private_exists = fs::symlink_metadata(&private).is_ok();
        let public_exists = fs::symlink_metadata(&public).is_ok();
        if private_exists != public_exists {
            return Err(ReleaseError::OperationConflict);
        }
        if !private_exists {
            run_effect(
                store,
                state,
                &FixedCommand::new(
                    "generate-local-ed25519-key",
                    SSH_KEYGEN,
                    [
                        "-q".into(),
                        "-t".into(),
                        "ed25519".into(),
                        "-N".into(),
                        String::new(),
                        "-C".into(),
                        format!("dirextalk:{}:{}", state.target, state.operation_id),
                        "-f".into(),
                        private.display().to_string(),
                    ],
                    true,
                    30,
                ),
                executor,
            )?;
        }
        set_key_modes(&private, &public)?;
        let public_bytes = fs::read(&public).map_err(crate::error::io_error(&public))?;
        if public_bytes.is_empty() || public_bytes.len() > 16 * 1024 {
            return Err(contract("local SSH public key is invalid"));
        }
        let public_text = std::str::from_utf8(&public_bytes)
            .map_err(|_| contract("local SSH public key is not UTF-8"))?;
        let public_fields = public_text.split_ascii_whitespace().collect::<Vec<_>>();
        let expected_comment = format!("dirextalk:{}:{}", state.target, state.operation_id);
        if public_fields.len() != 3
            || public_fields[0] != "ssh-ed25519"
            || public_fields[2] != expected_comment
        {
            return Err(ReleaseError::OperationConflict);
        }
        decode_canonical_base64(public_fields[1], "local SSH public key")?;
        let derived = executor
            .run(&FixedCommand::new(
                "derive-local-ed25519-public-key",
                SSH_KEYGEN,
                ["-y".into(), "-f".into(), private.display().to_string()],
                false,
                15,
            ))?
            .stdout;
        validate_derived_public_key(
            &derived,
            public_fields[0],
            public_fields[1],
            &expected_comment,
        )?;
        let fingerprint = executor
            .run(&FixedCommand::new(
                "fingerprint-local-ed25519-key",
                SSH_KEYGEN,
                [
                    "-lf".into(),
                    public.display().to_string(),
                    "-E".into(),
                    "sha256".into(),
                ],
                false,
                15,
            ))?
            .stdout;
        let fingerprint = parse_ssh_fingerprint(&fingerprint)?;
        state.key = Some(KeyRecord {
            key_name: manifest.key_name.clone(),
            private_key_suffix: PRIVATE_KEY_SUFFIX.into(),
            public_key_suffix: PUBLIC_KEY_SUFFIX.into(),
            public_key_sha256: hash(&public_bytes),
            fingerprint,
            imported: false,
        });
        persist(store, state)?;
    }
    let key_name = state.key.as_ref().expect("key state").key_name.clone();
    let existing = describe_key_pairs(&key_name, executor)?;
    match existing.as_slice() {
        [] => {
            let public = store.artifact_path(PUBLIC_KEY_SUFFIX)?;
            run_effect(
                store,
                state,
                &FixedCommand::new(
                    "import-owned-key-pair",
                    AWS,
                    [
                        "ec2".into(),
                        "import-key-pair".into(),
                        "--region".into(),
                        REGION.into(),
                        "--key-name".into(),
                        key_name.clone(),
                        "--public-key-material".into(),
                        format!("fileb://{}", public.display()),
                        "--tag-specifications".into(),
                        tag_spec("key-pair", state),
                        "--output".into(),
                        "json".into(),
                    ],
                    true,
                    45,
                ),
                executor,
            )?;
        }
        [pair] => validate_key_pair(pair, state)?,
        _ => return Err(ReleaseError::OperationConflict),
    }
    let reconciled = describe_key_pairs(&key_name, executor)?;
    if reconciled.len() != 1 {
        return Err(contract("owned EC2 key pair did not reconcile exactly"));
    }
    validate_key_pair(&reconciled[0], state)?;
    let aws_fingerprint = reconciled[0]["KeyFingerprint"]
        .as_str()
        .ok_or_else(|| contract("EC2 key fingerprint is missing"))?;
    let local = &state.key.as_ref().expect("key").fingerprint;
    if !fingerprints_match(aws_fingerprint, local)? {
        return Err(ReleaseError::OperationConflict);
    }
    state.key.as_mut().expect("key").imported = true;
    state.phase = LifecyclePhase::KeyReady;
    persist(store, state)
}

pub(super) fn validate_derived_public_key(
    derived: &str,
    expected_type: &str,
    expected_key: &str,
    expected_comment: &str,
) -> Result<()> {
    let fields = derived.split_ascii_whitespace().collect::<Vec<_>>();
    if !(fields.len() == 2 || fields.len() == 3)
        || fields[0] != expected_type
        || fields[1] != expected_key
        || fields
            .get(2)
            .is_some_and(|comment| *comment != expected_comment)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn set_key_modes(private: &Path, public: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for path in [private, public] {
            let metadata = fs::symlink_metadata(path).map_err(crate::error::io_error(path))?;
            if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(ReleaseError::StateUnsafe(path.to_owned()));
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(crate::error::io_error(path))?;
        }
    }
    Ok(())
}

fn parse_ssh_fingerprint(value: &str) -> Result<String> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 4 || fields[0].parse::<u16>().ok() != Some(256) || fields[3] != "(ED25519)" {
        return Err(contract(
            "ssh-keygen returned an invalid Ed25519 fingerprint",
        ));
    }
    let fingerprint = fields[1]
        .strip_prefix("SHA256:")
        .ok_or_else(|| contract("ssh-keygen fingerprint is not SHA-256"))?;
    if fingerprint.is_empty() || fingerprint.len() > 64 {
        return Err(contract("ssh-keygen fingerprint is malformed"));
    }
    Ok(format!("SHA256:{fingerprint}"))
}

pub(super) fn fingerprints_match(left: &str, right: &str) -> Result<bool> {
    Ok(decode_fingerprint(left)? == decode_fingerprint(right)?)
}

fn decode_fingerprint(value: &str) -> Result<Vec<u8>> {
    let encoded = value.strip_prefix("SHA256:").unwrap_or(value);
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| contract("Ed25519 fingerprint is not canonical base64"))?;
    if decoded.len() != 32
        || (STANDARD.encode(&decoded) != encoded && STANDARD_NO_PAD.encode(&decoded) != encoded)
    {
        return Err(contract("Ed25519 fingerprint is not canonical SHA-256"));
    }
    Ok(decoded)
}

fn describe_key_pairs(key_name: &str, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let output = executor.run(&FixedCommand::new(
        "describe-key-pair",
        AWS,
        [
            "ec2".into(),
            "describe-key-pairs".into(),
            "--region".into(),
            REGION.into(),
            "--filters".into(),
            format!("Name=key-name,Values={key_name}"),
            "--output".into(),
            "json".into(),
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    value["KeyPairs"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("EC2 key pair response is malformed"))
}

fn validate_key_pair(pair: &Value, state: &Ec2State) -> Result<()> {
    if pair["KeyName"].as_str() != state.key.as_ref().map(|key| key.key_name.as_str())
        || !tags_match(&pair["Tags"], state)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn ensure_security_group(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    if state.vpc_id.is_none() {
        let output = executor.run(&FixedCommand::new(
            "resolve-default-vpc",
            AWS,
            [
                "ec2",
                "describe-vpcs",
                "--region",
                REGION,
                "--filters",
                "Name=is-default,Values=true",
                "--output",
                "json",
            ],
            false,
            30,
        ))?;
        let value: Value = serde_json::from_str(&output.stdout)?;
        let vpcs = value["Vpcs"]
            .as_array()
            .ok_or_else(|| contract("default VPC response is malformed"))?;
        if vpcs.len() != 1 {
            return Err(contract("ap-east-1 must expose exactly one default VPC"));
        }
        state.vpc_id = Some(json_string(&vpcs[0], "VpcId")?);
        persist(store, state)?;
    }
    let groups = describe_owned_security_groups(state, executor)?;
    let group = match groups.as_slice() {
        [] => {
            let output = run_effect(
                store,
                state,
                &FixedCommand::new(
                    "create-owned-security-group",
                    AWS,
                    [
                        "ec2".into(),
                        "create-security-group".into(),
                        "--region".into(),
                        REGION.into(),
                        "--group-name".into(),
                        format!("dtx-{}", state.operation_id),
                        "--description".into(),
                        "Dirextalk vNext immutable node".into(),
                        "--vpc-id".into(),
                        state.vpc_id.clone().expect("vpc"),
                        "--tag-specifications".into(),
                        tag_spec("security-group", state),
                        "--output".into(),
                        "json".into(),
                    ],
                    true,
                    45,
                ),
                executor,
            )?;
            let value: Value = serde_json::from_str(&output.stdout)?;
            let id = json_string(&value, "GroupId")?;
            state.security_group_id = Some(id);
            persist(store, state)?;
            describe_owned_security_groups(state, executor)?
        }
        [_] => groups,
        _ => return Err(ReleaseError::OperationConflict),
    };
    if group.len() != 1 || !tags_match(&group[0]["Tags"], state) {
        return Err(ReleaseError::OperationConflict);
    }
    let id = json_string(&group[0], "GroupId")?;
    state.security_group_id = Some(id.clone());
    let permissions = ingress_permissions(manifest);
    if !permissions_match(&group[0]["IpPermissions"], &permissions)? {
        if group[0]["IpPermissions"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return Err(ReleaseError::OperationConflict);
        }
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "authorize-minimal-ingress",
                AWS,
                [
                    "ec2".into(),
                    "authorize-security-group-ingress".into(),
                    "--region".into(),
                    REGION.into(),
                    "--group-id".into(),
                    id,
                    "--ip-permissions".into(),
                    serde_json::to_string(&permissions)?,
                ],
                true,
                45,
            ),
            executor,
        )?;
        let check = describe_owned_security_groups(state, executor)?;
        if check.len() != 1 || !permissions_match(&check[0]["IpPermissions"], &permissions)? {
            return Err(contract("security group ingress did not reconcile"));
        }
    }
    state.phase = LifecyclePhase::SecurityGroupReady;
    persist(store, state)
}

fn describe_owned_security_groups(
    state: &Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<Vec<Value>> {
    let mut argv = vec![
        "ec2".into(),
        "describe-security-groups".into(),
        "--region".into(),
        REGION.into(),
        "--filters".into(),
        format!(
            "Name=vpc-id,Values={}",
            state.vpc_id.as_deref().unwrap_or_default()
        ),
    ];
    append_tag_filters(&mut argv, state);
    argv.extend(["--output".into(), "json".into()]);
    let output = executor.run(&FixedCommand::new(
        "describe-owned-security-group",
        AWS,
        argv,
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    value["SecurityGroups"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("security group response is malformed"))
}

fn ingress_permissions(manifest: &AwsEc2Manifest) -> Value {
    json!([
        {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk ACME HTTP challenge"}]},
        {"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk public HTTPS"}]},
        {"IpProtocol":"tcp","FromPort":9443,"ToPort":9445,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk Agent Control TLS"}]},
        {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":manifest.operator_ssh_cidr,"Description":"Dirextalk operator SSH"}]}
    ])
}

fn permissions_match(actual: &Value, expected: &Value) -> Result<bool> {
    let actual = actual
        .as_array()
        .ok_or_else(|| contract("security group permissions are malformed"))?;
    let expected = expected
        .as_array()
        .ok_or_else(|| contract("expected security group permissions are malformed"))?;
    Ok(normalize_permissions(actual)? == normalize_permissions(expected)?)
}

type PermissionTuple = (String, i64, i64, String, String);

fn normalize_permissions(items: &[Value]) -> Result<BTreeSet<PermissionTuple>> {
    let mut normalized = BTreeSet::new();
    for item in items {
        for name in ["Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"] {
            if item
                .get(name)
                .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
            {
                return Err(contract("security group contains non-IPv4 ingress"));
            }
        }
        let ranges = item["IpRanges"]
            .as_array()
            .filter(|ranges| !ranges.is_empty())
            .ok_or_else(|| contract("security group ingress must have IPv4 ranges"))?;
        let protocol = item["IpProtocol"]
            .as_str()
            .filter(|protocol| *protocol == "tcp")
            .ok_or_else(|| contract("security group protocol is invalid"))?;
        let from_port = item["FromPort"]
            .as_i64()
            .ok_or_else(|| contract("security group from-port is invalid"))?;
        let to_port = item["ToPort"]
            .as_i64()
            .ok_or_else(|| contract("security group to-port is invalid"))?;
        for range in ranges {
            let tuple = (
                protocol.to_owned(),
                from_port,
                to_port,
                range["CidrIp"]
                    .as_str()
                    .ok_or_else(|| contract("security group IPv4 range is invalid"))?
                    .to_owned(),
                range["Description"]
                    .as_str()
                    .ok_or_else(|| contract("security group description is invalid"))?
                    .to_owned(),
            );
            if !normalized.insert(tuple) {
                return Err(contract("security group ingress contains duplicates"));
            }
        }
    }
    Ok(normalized)
}

fn ensure_instance(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let mut instances = describe_owned_instances(state, executor)?;
    if instances.is_empty() {
        let user_data = cloud_init(state)?;
        let user_data_path = store.write_artifact(USER_DATA_SUFFIX, user_data.as_bytes(), 0o600)?;
        let ami = state
            .ami
            .as_ref()
            .ok_or_else(|| contract("AMI state is missing"))?;
        let key = state
            .key
            .as_ref()
            .ok_or_else(|| contract("key state is missing"))?;
        let security_group = state
            .security_group_id
            .as_deref()
            .ok_or_else(|| contract("security group state is missing"))?;
        let block = format!(
            "DeviceName=/dev/sda1,Ebs={{VolumeType=gp3,VolumeSize={},DeleteOnTermination=false,Encrypted=true}}",
            manifest.disk_gib
        );
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "run-owned-instance",
                AWS,
                [
                    "ec2".into(),
                    "run-instances".into(),
                    "--region".into(),
                    REGION.into(),
                    "--client-token".into(),
                    state.client_token.clone(),
                    "--image-id".into(),
                    ami.image_id.clone(),
                    "--instance-type".into(),
                    manifest.instance_type.clone(),
                    "--key-name".into(),
                    key.key_name.clone(),
                    "--security-group-ids".into(),
                    security_group.into(),
                    "--block-device-mappings".into(),
                    block,
                    "--metadata-options".into(),
                    "HttpTokens=required,HttpEndpoint=enabled".into(),
                    "--user-data".into(),
                    format!("fileb://{}", user_data_path.display()),
                    "--tag-specifications".into(),
                    tag_spec("instance", state),
                    tag_spec("volume", state),
                    "--output".into(),
                    "json".into(),
                ],
                true,
                90,
            ),
            executor,
        )?;
        instances = describe_owned_instances(state, executor)?;
    }
    if instances.len() != 1 {
        return Err(ReleaseError::OperationConflict);
    }
    let instance = &instances[0];
    if !tags_match(&instance["Tags"], state)
        || instance["ImageId"].as_str() != state.ami.as_ref().map(|ami| ami.image_id.as_str())
        || instance["InstanceType"].as_str() != Some(manifest.instance_type.as_str())
        || instance["KeyName"].as_str() != state.key.as_ref().map(|key| key.key_name.as_str())
        || instance["ClientToken"].as_str() != Some(state.client_token.as_str())
        || instance["Architecture"].as_str() != Some("x86_64")
        || instance["MetadataOptions"]["HttpTokens"].as_str() != Some("required")
        || instance["MetadataOptions"]["HttpEndpoint"].as_str() != Some("enabled")
        || instance["SecurityGroups"].as_array().is_none_or(|groups| {
            groups.len() != 1 || groups[0]["GroupId"].as_str() != state.security_group_id.as_deref()
        })
    {
        return Err(ReleaseError::OperationConflict);
    }
    let instance_id = json_string(instance, "InstanceId")?;
    let private_ipv4 = json_string(instance, "PrivateIpAddress")?;
    if !private_ipv4
        .parse::<Ipv4Addr>()
        .is_ok_and(|address| address.is_private())
    {
        return Err(ReleaseError::OperationConflict);
    }
    let mappings = instance["BlockDeviceMappings"]
        .as_array()
        .filter(|items| items.len() == 1)
        .ok_or_else(|| contract("instance root volume mapping is invalid"))?;
    if mappings[0]["DeviceName"].as_str() != Some("/dev/sda1")
        || mappings[0]["Ebs"]["DeleteOnTermination"].as_bool() != Some(false)
    {
        return Err(ReleaseError::OperationConflict);
    }
    let volume_id = mappings[0]["Ebs"]["VolumeId"]
        .as_str()
        .ok_or_else(|| contract("instance root volume is missing"))?
        .to_owned();
    state.instance_id = Some(instance_id.clone());
    state.private_ipv4 = Some(private_ipv4);
    state.volume_id = Some(volume_id.clone());
    persist(store, state)?;
    for (id, waiter) in [
        ("wait-instance-running", "instance-running"),
        ("wait-instance-status-ok", "instance-status-ok"),
    ] {
        run_effect(
            store,
            state,
            &FixedCommand::new(
                id,
                AWS,
                [
                    "ec2".into(),
                    "wait".into(),
                    waiter.into(),
                    "--region".into(),
                    REGION.into(),
                    "--instance-ids".into(),
                    instance_id.clone(),
                ],
                false,
                600,
            ),
            executor,
        )?;
    }
    verify_owned_volume(state, &volume_id, false, executor)?;
    let volumes = describe_volumes_by_id(&volume_id, executor)?;
    if volumes.len() != 1
        || volumes[0]["Size"].as_u64() != Some(u64::from(manifest.disk_gib))
        || volumes[0]["Encrypted"].as_bool() != Some(true)
        || volumes[0]["VolumeType"].as_str() != Some("gp3")
    {
        return Err(ReleaseError::OperationConflict);
    }
    state.phase = LifecyclePhase::InstanceReady;
    persist(store, state)
}

fn describe_owned_instances(state: &Ec2State, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let mut argv = vec![
        "ec2".into(),
        "describe-instances".into(),
        "--region".into(),
        REGION.into(),
        "--filters".into(),
        format!("Name=client-token,Values={}", state.client_token),
        "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down".into(),
    ];
    append_tag_filters(&mut argv, state);
    argv.extend(["--output".into(), "json".into()]);
    let output = executor.run(&FixedCommand::new(
        "describe-owned-instance",
        AWS,
        argv,
        false,
        45,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let reservations = value["Reservations"]
        .as_array()
        .ok_or_else(|| contract("instance response is malformed"))?;
    Ok(reservations
        .iter()
        .flat_map(|reservation| {
            reservation["Instances"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned()
        })
        .collect())
}

pub(super) fn cloud_init(state: &Ec2State) -> Result<String> {
    let ami = state
        .ami
        .as_ref()
        .ok_or_else(|| contract("AMI state is missing"))?;
    let attestor = format!(
        r#"#!/bin/sh
set -eu
/usr/bin/ssh-keygen -A
TOKEN=$(/usr/bin/curl -fsS --max-time 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)
INSTANCE=$(/usr/bin/curl -fsS --max-time 5 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
set -- $(/usr/bin/cat /etc/ssh/ssh_host_ed25519_key.pub)
test "$1" = ssh-ed25519
KEY=$2
KEYSHA=$(printf '%s' "$KEY" | /usr/bin/base64 -d | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)
printf 'DTXHK01 %s {} {} %s %s\n' "$INSTANCE" "$KEY" "$KEYSHA" > /dev/console
"#,
        state.client_token_sha256, ami.image_id
    );
    Ok(format!(
        "#cloud-config\npackage_update: true\npackages:\n  - ca-certificates\n  - curl\n  - docker.io\n  - docker-compose-v2\n  - openssl\nwrite_files:\n  - path: /usr/local/libexec/dirextalk/attest-vnext-host-key\n    owner: root:root\n    permissions: '0555'\n    encoding: b64\n    content: {}\nruncmd:\n  - [ /usr/bin/systemctl, enable, --now, docker.service ]\n  - [ /usr/local/libexec/dirextalk/attest-vnext-host-key ]\n",
        STANDARD.encode(attestor.as_bytes()),
    ))
}

fn ensure_eip(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let mut addresses = describe_owned_addresses(state, executor)?;
    if addresses.is_empty() {
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "allocate-owned-eip",
                AWS,
                [
                    "ec2".into(),
                    "allocate-address".into(),
                    "--region".into(),
                    REGION.into(),
                    "--domain".into(),
                    "vpc".into(),
                    "--tag-specifications".into(),
                    tag_spec("elastic-ip", state),
                    "--output".into(),
                    "json".into(),
                ],
                true,
                45,
            ),
            executor,
        )?;
        addresses = describe_owned_addresses(state, executor)?;
    }
    if addresses.len() != 1 || !tags_match(&addresses[0]["Tags"], state) {
        return Err(ReleaseError::OperationConflict);
    }
    let allocation_id = json_string(&addresses[0], "AllocationId")?;
    let public_ip = json_string(&addresses[0], "PublicIp")?;
    public_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| contract("owned EIP is not IPv4"))?;
    let instance_id = state
        .instance_id
        .clone()
        .ok_or_else(|| contract("instance state is missing"))?;
    let association_id = addresses[0]["AssociationId"].as_str().map(str::to_owned);
    let associated_instance = addresses[0]["InstanceId"].as_str();
    let association_id = if let Some(id) = association_id {
        if associated_instance != Some(instance_id.as_str()) {
            return Err(ReleaseError::OperationConflict);
        }
        id
    } else {
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "associate-owned-eip",
                AWS,
                [
                    "ec2".into(),
                    "associate-address".into(),
                    "--region".into(),
                    REGION.into(),
                    "--allocation-id".into(),
                    allocation_id.clone(),
                    "--instance-id".into(),
                    instance_id.clone(),
                    "--no-allow-reassociation".into(),
                    "--output".into(),
                    "json".into(),
                ],
                true,
                45,
            ),
            executor,
        )?;
        let reconciled = describe_owned_addresses(state, executor)?;
        if reconciled.len() != 1
            || reconciled[0]["InstanceId"].as_str() != Some(instance_id.as_str())
        {
            return Err(contract("EIP association did not reconcile"));
        }
        json_string(&reconciled[0], "AssociationId")?
    };
    state.eip = Some(EipRecord {
        allocation_id,
        association_id,
        public_ip,
    });
    state.phase = LifecyclePhase::EipReady;
    persist(store, state)
}

fn describe_owned_addresses(state: &Ec2State, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let mut argv = vec![
        "ec2".into(),
        "describe-addresses".into(),
        "--region".into(),
        REGION.into(),
        "--filters".into(),
    ];
    append_tag_filters(&mut argv, state);
    argv.extend(["--output".into(), "json".into()]);
    let output = executor.run(&FixedCommand::new(
        "describe-owned-eip",
        AWS,
        argv,
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    value["Addresses"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("EIP response is malformed"))
}

fn ensure_dns(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let output = executor.run(&FixedCommand::new(
        "list-public-hosted-zones",
        AWS,
        [
            "route53",
            "list-hosted-zones",
            "--no-paginate",
            "--output",
            "json",
        ],
        false,
        45,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let zones = value["HostedZones"]
        .as_array()
        .ok_or_else(|| contract("Route53 hosted zone response is malformed"))?;
    let domain = normalize_dns_name(&state.domain);
    let mut candidates = zones
        .iter()
        .filter_map(|zone| {
            if zone["Config"]["PrivateZone"].as_bool() != Some(false) {
                return None;
            }
            let name = normalize_dns_name(zone["Name"].as_str()?);
            if domain == name || domain.ends_with(&format!(".{name}")) {
                Some((
                    name.len(),
                    name,
                    zone["Id"]
                        .as_str()?
                        .trim_start_matches("/hostedzone/")
                        .to_owned(),
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.0);
    let (_, zone_name, zone_id) = candidates
        .pop()
        .ok_or_else(|| contract("no matching public Route53 zone exists"))?;
    if candidates
        .last()
        .is_some_and(|candidate| candidate.0 == zone_name.len())
    {
        return Err(contract("longest-suffix public Route53 zone is ambiguous"));
    }
    let record_name = format!("{}.", state.domain);
    let eip_public_ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.clone())
        .ok_or_else(|| contract("EIP state is missing"))?;
    let existing = read_record_set(&zone_id, &record_name, executor)?;
    let pending_create = state.pending_effect.as_deref() == Some("create-owned-dns-record");
    if let Some(record) = existing {
        let exact = record["Type"].as_str() == Some("A")
            && record["TTL"].as_u64() == Some(60)
            && record["ResourceRecords"].as_array().is_some_and(|records| {
                records.len() == 1 && records[0]["Value"].as_str() == Some(eip_public_ip.as_str())
            });
        let recorded = state.dns.as_ref().is_some_and(|owned| {
            owned.hosted_zone_id == zone_id
                && owned.name == record_name
                && owned.value == eip_public_ip
        });
        if !exact || (!recorded && !pending_create) {
            return Err(ReleaseError::OperationConflict);
        }
        if state.dns.is_none()
            || state
                .dns
                .as_ref()
                .is_some_and(|owned| owned.change_id == "create-pending")
        {
            state.dns = Some(OwnedRecordSet {
                hosted_zone_id: zone_id,
                hosted_zone_name: format!("{zone_name}."),
                name: record_name,
                record_type: "A".into(),
                ttl: 60,
                value: eip_public_ip.clone(),
                change_id: "reconciled-lost-response".into(),
            });
        }
    } else {
        let change_batch = route53_change("CREATE", &record_name, &eip_public_ip);
        state.dns = Some(OwnedRecordSet {
            hosted_zone_id: zone_id.clone(),
            hosted_zone_name: format!("{zone_name}."),
            name: record_name.clone(),
            record_type: "A".into(),
            ttl: 60,
            value: eip_public_ip.clone(),
            change_id: "create-pending".into(),
        });
        persist(store, state)?;
        let response = run_effect(
            store,
            state,
            &FixedCommand::new(
                "create-owned-dns-record",
                AWS,
                [
                    "route53".into(),
                    "change-resource-record-sets".into(),
                    "--hosted-zone-id".into(),
                    zone_id.clone(),
                    "--change-batch".into(),
                    serde_json::to_string(&change_batch)?,
                    "--output".into(),
                    "json".into(),
                ],
                true,
                45,
            ),
            executor,
        )?;
        let response: Value = serde_json::from_str(&response.stdout)?;
        let change_id = response["ChangeInfo"]["Id"]
            .as_str()
            .ok_or_else(|| contract("Route53 change id is missing"))?
            .trim_start_matches("/change/")
            .to_owned();
        state.dns = Some(OwnedRecordSet {
            hosted_zone_id: zone_id,
            hosted_zone_name: format!("{zone_name}."),
            name: record_name,
            record_type: "A".into(),
            ttl: 60,
            value: eip_public_ip.clone(),
            change_id,
        });
        persist(store, state)?;
    }
    let change_id = state
        .dns
        .as_ref()
        .map(|record| record.change_id.clone())
        .expect("dns record");
    if change_id != "reconciled-lost-response" {
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "wait-owned-dns-change",
                AWS,
                [
                    "route53".into(),
                    "wait".into(),
                    "resource-record-sets-changed".into(),
                    "--id".into(),
                    change_id,
                ],
                false,
                300,
            ),
            executor,
        )?;
    }
    state.phase = LifecyclePhase::DnsReady;
    persist(store, state)
}

fn read_record_set(
    zone_id: &str,
    record_name: &str,
    executor: &dyn AwsExecutor,
) -> Result<Option<Value>> {
    let output = executor.run(&FixedCommand::new(
        "read-exact-dns-record",
        AWS,
        [
            "route53",
            "list-resource-record-sets",
            "--hosted-zone-id",
            zone_id,
            "--start-record-name",
            record_name,
            "--start-record-type",
            "A",
            "--max-items",
            "1",
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let records = value["ResourceRecordSets"]
        .as_array()
        .ok_or_else(|| contract("Route53 record response is malformed"))?;
    Ok(records
        .first()
        .filter(|record| {
            record["Name"].as_str() == Some(record_name) && record["Type"].as_str() == Some("A")
        })
        .cloned())
}

fn route53_change(action: &str, name: &str, value: &str) -> Value {
    json!({"Comment":"Dirextalk owned immutable node","Changes":[{"Action":action,"ResourceRecordSet":{"Name":name,"Type":"A","TTL":60,"ResourceRecords":[{"Value":value}]}}]})
}

fn ensure_host_key(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    if state.host_key.is_some() {
        return Ok(());
    }
    let instance_id = state
        .instance_id
        .as_deref()
        .ok_or_else(|| contract("instance state is missing"))?;
    let ami_id = state
        .ami
        .as_ref()
        .map(|ami| ami.image_id.as_str())
        .ok_or_else(|| contract("AMI state is missing"))?;
    let console = executor.run(&FixedCommand::new(
        "read-authenticated-console-output",
        AWS,
        [
            "ec2",
            "get-console-output",
            "--region",
            REGION,
            "--instance-id",
            instance_id,
            "--latest",
            "--output",
            "json",
        ],
        false,
        45,
    ))?;
    let value: Value = serde_json::from_str(&console.stdout)?;
    let encoded_output = value["Output"]
        .as_str()
        .ok_or_else(|| contract("EC2 console output is missing"))?;
    let output = decode_console_output(encoded_output)?;
    let attestation =
        parse_console_host_key(&output, instance_id, &state.client_token_sha256, ami_id)?;
    let ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.as_str())
        .ok_or_else(|| contract("EIP state is missing"))?;
    let scan = executor.run(&FixedCommand::new(
        "scan-pinned-ed25519-host-key",
        SSH_KEYSCAN,
        ["-T", "15", "-t", "ed25519", ip],
        false,
        30,
    ))?;
    let scanned = parse_scanned_host_key(&scan.stdout, ip)?;
    if scanned.0 != attestation.0 || scanned.1 != attestation.1 {
        return Err(contract(
            "ssh-keyscan does not match AWS-authenticated console attestation",
        ));
    }
    let known_hosts = format!(
        "{} ssh-ed25519 {}\n{} ssh-ed25519 {}\n",
        state.domain, attestation.0, ip, attestation.0
    );
    store.write_artifact(KNOWN_HOSTS_SUFFIX, known_hosts.as_bytes(), 0o600)?;
    state.host_key = Some(HostKeyRecord {
        algorithm: "ssh-ed25519".into(),
        key_base64: attestation.0,
        key_sha256: attestation.1,
        console_line_sha256: attestation.2,
        known_hosts_suffix: KNOWN_HOSTS_SUFFIX.into(),
    });
    state.phase = LifecyclePhase::HostKeyPinned;
    persist(store, state)
}

pub(super) fn decode_console_output(value: &str) -> Result<String> {
    if value.lines().any(|line| line.starts_with("DTXHK01 ")) {
        return Ok(value.to_owned());
    }
    let decoded = decode_canonical_base64(value, "EC2 console output")?;
    String::from_utf8(decoded).map_err(|_| contract("EC2 console output is not UTF-8"))
}

fn parse_console_host_key(
    output: &str,
    instance_id: &str,
    client_token_sha256: &str,
    ami_id: &str,
) -> Result<(String, String, String)> {
    let lines = output
        .lines()
        .filter(|line| line.starts_with("DTXHK01 "))
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(contract(
            "console host-key attestation is absent or ambiguous",
        ));
    }
    let fields = lines[0].split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 6
        || fields[0] != "DTXHK01"
        || fields[1] != instance_id
        || fields[2] != client_token_sha256
        || fields[3] != ami_id
    {
        return Err(contract("console host-key attestation binding mismatch"));
    }
    let key_bytes = decode_canonical_base64(fields[4], "console host key")?;
    let key_sha = hash(&key_bytes);
    if key_sha != fields[5] {
        return Err(contract("console host-key digest mismatch"));
    }
    Ok((fields[4].into(), key_sha, hash(lines[0].as_bytes())))
}

fn parse_scanned_host_key(output: &str, ip: &str) -> Result<(String, String)> {
    let lines = output
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(contract("ssh-keyscan result is absent or ambiguous"));
    }
    let fields = lines[0].split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != ip || fields[1] != "ssh-ed25519" {
        return Err(contract("ssh-keyscan result is malformed"));
    }
    let key = decode_canonical_base64(fields[2], "ssh-keyscan key")?;
    Ok((fields[2].into(), hash(&key)))
}

fn decode_canonical_base64(value: &str, name: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| contract(&format!("{name} is not canonical base64")))?;
    if decoded.is_empty() || STANDARD.encode(&decoded) != value {
        return Err(contract(&format!("{name} is not canonical base64")));
    }
    Ok(decoded)
}

struct HostHelperSpec<'a> {
    label: &'static str,
    local: &'a Path,
    sha256: &'a str,
    size: usize,
    upload: &'static str,
    upload_name: &'static str,
    atomic: &'static str,
    atomic_name: &'static str,
    installed: &'static str,
    installed_name: &'static str,
}

pub(super) struct RemoteFileMetadata {
    pub kind: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
    pub links: String,
    pub size: usize,
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InstallInputState {
    Absent,
    UbuntuStaged,
    UbuntuProtected,
    RootProtected,
}

pub(super) fn classify_install_input(
    metadata: Option<&RemoteFileMetadata>,
    path: &str,
    size: usize,
) -> Result<InstallInputState> {
    let Some(metadata) = metadata else {
        return Ok(InstallInputState::Absent);
    };
    if metadata.kind != "f"
        || metadata.links != "1"
        || metadata.size != size
        || metadata.path != path
    {
        return Err(ReleaseError::OperationConflict);
    }
    match (
        metadata.owner.as_str(),
        metadata.group.as_str(),
        metadata.mode.as_str(),
    ) {
        ("ubuntu", "ubuntu", "600") => Ok(InstallInputState::UbuntuStaged),
        ("ubuntu", "ubuntu", "400") => Ok(InstallInputState::UbuntuProtected),
        ("root", "root", "400") => Ok(InstallInputState::RootProtected),
        _ => Err(ReleaseError::OperationConflict),
    }
}

fn ensure_host_helpers(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let helpers = [
        HostHelperSpec {
            label: "host-installer",
            local: &manifest.host_installer_path,
            sha256: &facts.host_installer_sha256,
            size: facts.host_installer.len(),
            upload: REMOTE_INSTALLER_UPLOAD,
            upload_name: "install-vnext.upload",
            atomic: REMOTE_INSTALLER_ATOMIC,
            atomic_name: ".install-vnext.new",
            installed: REMOTE_INSTALLER,
            installed_name: "install-vnext",
        },
        HostHelperSpec {
            label: "host-provisioner",
            local: &manifest.host_provisioner_path,
            sha256: &facts.host_provisioner_sha256,
            size: facts.host_provisioner.len(),
            upload: REMOTE_PROVISIONER_UPLOAD,
            upload_name: "provision-vnext.upload",
            atomic: REMOTE_PROVISIONER_ATOMIC,
            atomic_name: ".provision-vnext.new",
            installed: REMOTE_PROVISIONER,
            installed_name: "provision-vnext",
        },
        HostHelperSpec {
            label: "receipt-reader",
            local: &manifest.receipt_reader_path,
            sha256: &facts.receipt_reader_sha256,
            size: facts.receipt_reader.len(),
            upload: REMOTE_RECEIPT_READER_UPLOAD,
            upload_name: "read-vnext-receipt.upload",
            atomic: REMOTE_RECEIPT_READER_ATOMIC,
            atomic_name: ".read-vnext-receipt.new",
            installed: REMOTE_RECEIPT_READER,
            installed_name: "read-vnext-receipt",
        },
    ];
    for helper in &helpers {
        ensure_host_helper(store, state, helper, executor)?;
    }
    Ok(())
}

fn ensure_host_helper(
    store: &Store,
    state: &mut Ec2State,
    helper: &HostHelperSpec<'_>,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    if let Some(metadata) = inspect_remote_file(
        state,
        store,
        executor,
        &format!("inspect-installed-{}", helper.label),
        "/usr/local/libexec/dirextalk",
        helper.installed_name,
    )? {
        require_remote_metadata(
            &metadata,
            helper.installed,
            "root",
            "root",
            "555",
            helper.size,
        )?;
        verify_remote_helper_hash(
            state,
            store,
            executor,
            &format!("verify-installed-{}", helper.label),
            helper.installed,
            helper.sha256,
            true,
        )?;
        return Ok(());
    }

    run_effect(
        store,
        state,
        &ssh_command(
            &format!("clear-upload-{}", helper.label),
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/rm",
                "--force",
                "--",
                helper.upload,
            ],
            true,
            30,
        )?,
        executor,
    )?;
    run_effect(
        store,
        state,
        &scp_command(
            &format!("stage-{}", helper.label),
            state,
            store,
            helper.local,
            helper.upload,
        )?,
        executor,
    )?;
    let uploaded = inspect_remote_file(
        state,
        store,
        executor,
        &format!("inspect-uploaded-{}", helper.label),
        "/home/ubuntu",
        helper.upload_name,
    )?
    .ok_or(ReleaseError::OperationConflict)?;
    if uploaded.kind != "f"
        || uploaded.owner != "ubuntu"
        || uploaded.group != "ubuntu"
        || uploaded.links != "1"
        || uploaded.size != helper.size
        || uploaded.path != helper.upload
    {
        return Err(ReleaseError::OperationConflict);
    }
    verify_remote_helper_hash(
        state,
        store,
        executor,
        &format!("verify-uploaded-{}", helper.label),
        helper.upload,
        helper.sha256,
        false,
    )?;
    run_effect(
        store,
        state,
        &ssh_command(
            &format!("protect-uploaded-{}", helper.label),
            state,
            store,
            ["/usr/bin/chmod", "0400", helper.upload],
            true,
            30,
        )?,
        executor,
    )?;
    let protected = inspect_remote_file(
        state,
        store,
        executor,
        &format!("inspect-protected-{}", helper.label),
        "/home/ubuntu",
        helper.upload_name,
    )?
    .ok_or(ReleaseError::OperationConflict)?;
    require_remote_metadata(
        &protected,
        helper.upload,
        "ubuntu",
        "ubuntu",
        "400",
        helper.size,
    )?;

    run_effect(
        store,
        state,
        &ssh_command(
            &format!("clear-atomic-{}", helper.label),
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/rm",
                "--force",
                "--",
                helper.atomic,
            ],
            true,
            30,
        )?,
        executor,
    )?;
    run_effect(
        store,
        state,
        &ssh_command(
            &format!("prepare-atomic-{}", helper.label),
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/install",
                "--owner=root",
                "--group=root",
                "--mode=0555",
                "--no-target-directory",
                helper.upload,
                helper.atomic,
            ],
            true,
            30,
        )?,
        executor,
    )?;
    let atomic = inspect_remote_file(
        state,
        store,
        executor,
        &format!("inspect-atomic-{}", helper.label),
        "/usr/local/libexec/dirextalk",
        helper.atomic_name,
    )?
    .ok_or(ReleaseError::OperationConflict)?;
    require_remote_metadata(&atomic, helper.atomic, "root", "root", "555", helper.size)?;
    verify_remote_helper_hash(
        state,
        store,
        executor,
        &format!("verify-atomic-{}", helper.label),
        helper.atomic,
        helper.sha256,
        true,
    )?;
    run_effect(
        store,
        state,
        &ssh_command(
            &format!("activate-{}", helper.label),
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/mv",
                "--no-clobber",
                "--no-target-directory",
                "--",
                helper.atomic,
                helper.installed,
            ],
            true,
            30,
        )?,
        executor,
    )?;
    let installed = inspect_remote_file(
        state,
        store,
        executor,
        &format!("reconcile-installed-{}", helper.label),
        "/usr/local/libexec/dirextalk",
        helper.installed_name,
    )?
    .ok_or(ReleaseError::OperationConflict)?;
    require_remote_metadata(
        &installed,
        helper.installed,
        "root",
        "root",
        "555",
        helper.size,
    )?;
    verify_remote_helper_hash(
        state,
        store,
        executor,
        &format!("reconcile-hash-{}", helper.label),
        helper.installed,
        helper.sha256,
        true,
    )
}

fn inspect_remote_file(
    state: &Ec2State,
    store: &Store,
    executor: &dyn AwsExecutor,
    id: &str,
    parent: &str,
    name: &str,
) -> Result<Option<RemoteFileMetadata>> {
    let output = executor.run(&ssh_command(
        id,
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/find",
            parent,
            "-maxdepth",
            "1",
            "-mindepth",
            "1",
            "-name",
            name,
            "-printf",
            "%y %u %g %m %n %s %p\\n",
        ],
        false,
        30,
    )?)?;
    parse_remote_file_metadata(&output.stdout)
}

fn parse_remote_file_metadata(output: &str) -> Result<Option<RemoteFileMetadata>> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.lines().count() != 1 {
        return Err(ReleaseError::OperationConflict);
    }
    let fields = trimmed.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 7 {
        return Err(ReleaseError::OperationConflict);
    }
    let size = fields[5]
        .parse::<usize>()
        .map_err(|_| ReleaseError::OperationConflict)?;
    Ok(Some(RemoteFileMetadata {
        kind: fields[0].to_owned(),
        owner: fields[1].to_owned(),
        group: fields[2].to_owned(),
        mode: fields[3].to_owned(),
        links: fields[4].to_owned(),
        size,
        path: fields[6].to_owned(),
    }))
}

fn require_remote_metadata(
    metadata: &RemoteFileMetadata,
    path: &str,
    owner: &str,
    group: &str,
    mode: &str,
    size: usize,
) -> Result<()> {
    if metadata.kind != "f"
        || metadata.owner != owner
        || metadata.group != group
        || metadata.mode != mode
        || metadata.links != "1"
        || metadata.size != size
        || metadata.path != path
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_helper_hash(
    state: &Ec2State,
    store: &Store,
    executor: &dyn AwsExecutor,
    id: &str,
    path: &str,
    expected: &str,
    sudo: bool,
) -> Result<()> {
    let output = if sudo {
        executor.run(&ssh_command(
            id,
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/sha256sum",
                path,
            ],
            false,
            30,
        )?)?
    } else {
        executor.run(&ssh_command(
            id,
            state,
            store,
            ["/usr/bin/sha256sum", path],
            false,
            30,
        )?)?
    };
    verify_single_remote_hash(&output.stdout, path, expected)
}

fn install_initial(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    store.copy_artifact(
        APPLY_BUNDLE_SUFFIX,
        &manifest.stack_bundle_path,
        &facts.bundle_sha256,
    )?;
    let request = InstallRequest::new(&state.domain, facts, None);
    store.write_artifact(APPLY_REQUEST_SUFFIX, &request.canonical_bytes()?, 0o600)?;
    let receipt = stage_install_read_receipt(
        store,
        state,
        APPLY_BUNDLE_SUFFIX,
        APPLY_REQUEST_SUFFIX,
        &request,
        ReceiptState::Installed,
        None,
        executor,
    )?;
    state.current = Some(BundleRecord::from_facts(facts, manifest));
    state.current_receipt = Some(receipt);
    state.current_bundle_suffix = Some(APPLY_BUNDLE_SUFFIX.into());
    state.current_request_suffix = Some(APPLY_REQUEST_SUFFIX.into());
    state.phase = LifecyclePhase::ProvisionPending;
    persist(store, state)
}

fn provision_initial(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let request = ProvisionRequest::new(manifest, state, facts)?;
    let request_bytes = request.canonical_bytes()?;
    let request_sha = hash(&request_bytes);
    let local = store.write_artifact(PROVISION_REQUEST_SUFFIX, &request_bytes, 0o600)?;
    state.provision_request_suffix = Some(PROVISION_REQUEST_SUFFIX.into());
    state.phase = LifecyclePhase::Provisioning;
    persist(store, state)?;

    let remote = executor.run(&ssh_command(
        "inspect-fixed-provision-request",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/find",
            "/home/ubuntu",
            "-maxdepth",
            "1",
            "-type",
            "f",
            "-name",
            "dirextalk-vnext.provision",
            "-printf",
            "%u %g %m %s %p\\n",
        ],
        false,
        30,
    )?)?;
    if remote.stdout.is_empty() {
        run_effect(
            store,
            state,
            &scp_command(
                "stage-exact-provision-request",
                state,
                store,
                &local,
                REMOTE_PROVISION_REQUEST,
            )?,
            executor,
        )?;
        let staged = executor.run(&ssh_command(
            "verify-staged-provision-request",
            state,
            store,
            ["/usr/bin/sha256sum", REMOTE_PROVISION_REQUEST],
            false,
            30,
        )?)?;
        verify_single_remote_hash(&staged.stdout, REMOTE_PROVISION_REQUEST, &request_sha)?;
        for (id, argv) in [
            (
                "own-fixed-provision-request",
                [
                    "/usr/bin/sudo",
                    "--non-interactive",
                    "/usr/bin/chown",
                    "root:root",
                    REMOTE_PROVISION_REQUEST,
                ],
            ),
            (
                "mode-fixed-provision-request",
                [
                    "/usr/bin/sudo",
                    "--non-interactive",
                    "/usr/bin/chmod",
                    "0400",
                    REMOTE_PROVISION_REQUEST,
                ],
            ),
        ] {
            run_effect(
                store,
                state,
                &ssh_command(id, state, store, argv, true, 30)?,
                executor,
            )?;
        }
    } else {
        let fields = remote.stdout.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 5
            || fields[0] != "root"
            || fields[1] != "root"
            || fields[2] != "400"
            || fields[3].parse::<usize>().ok() != Some(request_bytes.len())
            || fields[4] != REMOTE_PROVISION_REQUEST
        {
            return Err(ReleaseError::OperationConflict);
        }
        let staged = executor.run(&ssh_command(
            "verify-owned-provision-request",
            state,
            store,
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/sha256sum",
                REMOTE_PROVISION_REQUEST,
            ],
            false,
            30,
        )?)?;
        verify_single_remote_hash(&staged.stdout, REMOTE_PROVISION_REQUEST, &request_sha)?;
    }
    run_effect(
        store,
        state,
        &ssh_command(
            "run-fixed-host-provisioner",
            state,
            store,
            ["/usr/bin/sudo", "--non-interactive", REMOTE_PROVISIONER],
            true,
            900,
        )?,
        executor,
    )?;
    let ready = read_host_ready_receipt(state, store, &request, executor)?;
    state.host_ready_receipt = Some(ready);
    state.phase = LifecyclePhase::HostReady;
    persist(store, state)?;
    state.phase = LifecyclePhase::Installed;
    persist(store, state)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_install_read_receipt(
    store: &Store,
    state: &mut Ec2State,
    bundle_suffix: &str,
    request_suffix: &str,
    request: &InstallRequest,
    expected_state: ReceiptState,
    retained: Option<(&InstallRequest, ReceiptState)>,
    executor: &dyn AwsExecutor,
) -> Result<InstalledReceipt> {
    match read_existing_install_receipt(state, store, request, expected_state, retained, executor)?
    {
        ExistingInstallReceipt::PostEffect(receipt) => return Ok(*receipt),
        ExistingInstallReceipt::PreEffect => clear_remote_install_inputs(store, state, executor)?,
        ExistingInstallReceipt::Absent => {}
    }
    let bundle_path = store.artifact_path(bundle_suffix)?;
    let request_path = store.artifact_path(request_suffix)?;
    let bundle_bytes = fs::read(&bundle_path).map_err(crate::error::io_error(&bundle_path))?;
    let request_bytes = fs::read(&request_path).map_err(crate::error::io_error(&request_path))?;
    for (label, local, remote, name, bytes) in [
        (
            "stack-bundle",
            &bundle_path,
            REMOTE_BUNDLE,
            "dirextalk-vnext.bundle",
            bundle_bytes.as_slice(),
        ),
        (
            "install-request",
            &request_path,
            REMOTE_REQUEST,
            "dirextalk-vnext.request",
            request_bytes.as_slice(),
        ),
    ] {
        reconcile_install_input(
            store,
            state,
            label,
            local,
            remote,
            name,
            bytes.len(),
            &hash(bytes),
            executor,
        )?;
    }
    run_effect(
        store,
        state,
        &ssh_command(
            "run-fixed-stack-installer",
            state,
            store,
            ["/usr/bin/sudo", "--non-interactive", REMOTE_INSTALLER],
            true,
            900,
        )?,
        executor,
    )?;
    let receipt = executor.run(&ssh_command(
        "read-authenticated-installed-receipt",
        state,
        store,
        ["/usr/bin/sudo", "--non-interactive", REMOTE_RECEIPT_READER],
        false,
        30,
    )?)?;
    InstalledReceipt::parse_and_verify(receipt.stdout.as_bytes(), request, expected_state)
}

pub(super) enum ExistingInstallReceipt {
    Absent,
    PreEffect,
    PostEffect(Box<InstalledReceipt>),
}

fn read_existing_install_receipt(
    state: &Ec2State,
    store: &Store,
    request: &InstallRequest,
    expected_state: ReceiptState,
    retained: Option<(&InstallRequest, ReceiptState)>,
    executor: &dyn AwsExecutor,
) -> Result<ExistingInstallReceipt> {
    let metadata = executor.run(&ssh_command(
        "inspect-current-installed-receipt",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/find",
            "/var/lib",
            "-maxdepth",
            "3",
            "-mindepth",
            "3",
            "-path",
            REMOTE_CURRENT_RECEIPT,
            "-printf",
            "%y %u %g %m %n %s %p\\n",
        ],
        false,
        30,
    )?)?;
    let Some(metadata) = parse_remote_file_metadata(&metadata.stdout)? else {
        return Ok(ExistingInstallReceipt::Absent);
    };
    if metadata.kind != "f"
        || metadata.owner != "root"
        || metadata.group != "root"
        || metadata.mode != "600"
        || metadata.links != "1"
        || metadata.size == 0
        || metadata.size > 64 * 1024
        || metadata.path != REMOTE_CURRENT_RECEIPT
    {
        return Err(ReleaseError::OperationConflict);
    }
    let output = executor.run(&ssh_command(
        "read-existing-installed-receipt",
        state,
        store,
        ["/usr/bin/sudo", "--non-interactive", REMOTE_RECEIPT_READER],
        false,
        30,
    )?)?;
    if output.stdout.len() != metadata.size {
        return Err(ReleaseError::OperationConflict);
    }
    classify_existing_install_receipt(output.stdout.as_bytes(), request, expected_state, retained)
}

pub(super) fn classify_existing_install_receipt(
    bytes: &[u8],
    request: &InstallRequest,
    expected_state: ReceiptState,
    retained: Option<(&InstallRequest, ReceiptState)>,
) -> Result<ExistingInstallReceipt> {
    if let Ok(receipt) = InstalledReceipt::parse_and_verify(bytes, request, expected_state) {
        return Ok(ExistingInstallReceipt::PostEffect(Box::new(receipt)));
    }
    if let Some((retained_request, retained_state)) = retained
        && InstalledReceipt::parse_and_verify(bytes, retained_request, retained_state).is_ok()
    {
        return Ok(ExistingInstallReceipt::PreEffect);
    }
    Err(ReleaseError::OperationConflict)
}

fn clear_remote_install_inputs(
    store: &Store,
    state: &mut Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let clear = ssh_command(
        "clear-retained-install-inputs-before-replay",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/rm",
            "--force",
            "--",
            REMOTE_BUNDLE,
            REMOTE_REQUEST,
        ],
        true,
        30,
    )?;
    run_effect(store, state, &clear, executor).map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn reconcile_install_input(
    store: &Store,
    state: &mut Ec2State,
    label: &str,
    local: &Path,
    remote: &str,
    name: &str,
    size: usize,
    expected_sha256: &str,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let mut metadata = inspect_remote_file(
        state,
        store,
        executor,
        &format!("inspect-{label}"),
        "/home/ubuntu",
        name,
    )?;
    let mut disposition = classify_install_input(metadata.as_ref(), remote, size)?;
    if disposition == InstallInputState::Absent {
        run_effect(
            store,
            state,
            &scp_command(&format!("stage-exact-{label}"), state, store, local, remote)?,
            executor,
        )?;
        metadata = inspect_remote_file(
            state,
            store,
            executor,
            &format!("inspect-staged-{label}"),
            "/home/ubuntu",
            name,
        )?;
        disposition = classify_install_input(metadata.as_ref(), remote, size)?;
        if disposition != InstallInputState::UbuntuStaged {
            return Err(ReleaseError::OperationConflict);
        }
    }
    if matches!(
        disposition,
        InstallInputState::UbuntuStaged | InstallInputState::UbuntuProtected
    ) {
        verify_remote_helper_hash(
            state,
            store,
            executor,
            &format!("verify-staged-{label}"),
            remote,
            expected_sha256,
            false,
        )?;
        if disposition == InstallInputState::UbuntuStaged {
            run_effect(
                store,
                state,
                &ssh_command(
                    &format!("protect-staged-{label}"),
                    state,
                    store,
                    ["/usr/bin/chmod", "0400", remote],
                    true,
                    30,
                )?,
                executor,
            )?;
            metadata = inspect_remote_file(
                state,
                store,
                executor,
                &format!("inspect-protected-{label}"),
                "/home/ubuntu",
                name,
            )?;
            if classify_install_input(metadata.as_ref(), remote, size)?
                != InstallInputState::UbuntuProtected
            {
                return Err(ReleaseError::OperationConflict);
            }
        }
        run_effect(
            store,
            state,
            &ssh_command(
                &format!("own-protected-{label}"),
                state,
                store,
                [
                    "/usr/bin/sudo",
                    "--non-interactive",
                    "/usr/bin/chown",
                    "root:root",
                    remote,
                ],
                true,
                30,
            )?,
            executor,
        )?;
        metadata = inspect_remote_file(
            state,
            store,
            executor,
            &format!("inspect-owned-{label}"),
            "/home/ubuntu",
            name,
        )?;
        disposition = classify_install_input(metadata.as_ref(), remote, size)?;
    }
    if disposition != InstallInputState::RootProtected {
        return Err(ReleaseError::OperationConflict);
    }
    verify_remote_helper_hash(
        state,
        store,
        executor,
        &format!("verify-owned-{label}"),
        remote,
        expected_sha256,
        true,
    )
}

fn verify_single_remote_hash(output: &str, path: &str, expected: &str) -> Result<()> {
    let mut fields = output.split_ascii_whitespace();
    let digest = fields.next().unwrap_or_default();
    let actual_path = fields.next().unwrap_or_default().trim_start_matches('*');
    if fields.next().is_some() || digest != expected || actual_path != path {
        return Err(contract("remote staged material digest mismatch"));
    }
    Ok(())
}

fn read_host_ready_receipt(
    state: &Ec2State,
    store: &Store,
    request: &ProvisionRequest,
    executor: &dyn AwsExecutor,
) -> Result<HostReadyReceipt> {
    executor.run(&ssh_command(
        "verify-host-ready-receipt-regular-file",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/test",
            "-f",
            REMOTE_READY_RECEIPT,
        ],
        false,
        30,
    )?)?;
    let metadata = executor.run(&ssh_command(
        "verify-host-ready-receipt-metadata",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/stat",
            "--format=%u %g %a %h %s",
            REMOTE_READY_RECEIPT,
        ],
        false,
        30,
    )?)?;
    let fields = metadata.stdout.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || fields[0] != "0"
        || fields[1] != "0"
        || fields[2] != "600"
        || fields[3] != "1"
        || fields[4]
            .parse::<usize>()
            .ok()
            .is_none_or(|size| size == 0 || size > 64 * 1024)
    {
        return Err(ReleaseError::OperationConflict);
    }
    let output = executor.run(&ssh_command(
        "read-sanitized-host-ready-receipt",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/cat",
            REMOTE_READY_RECEIPT,
        ],
        false,
        30,
    )?)?;
    if fields[4].parse::<usize>().ok() != Some(output.stdout.len()) {
        return Err(ReleaseError::OperationConflict);
    }
    HostReadyReceipt::parse_and_verify(output.stdout.as_bytes(), request)
}

pub(crate) fn scp_command(
    id: &str,
    state: &Ec2State,
    store: &Store,
    local: &Path,
    remote: &str,
) -> Result<FixedCommand> {
    let ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.as_str())
        .ok_or_else(|| contract("EIP state is missing"))?;
    let private = store.artifact_path(PRIVATE_KEY_SUFFIX)?;
    let known_hosts = store.artifact_path(KNOWN_HOSTS_SUFFIX)?;
    let local = fs::canonicalize(local).map_err(crate::error::io_error(local))?;
    Ok(FixedCommand::new(
        id,
        SCP,
        [
            "-q".into(),
            "-i".into(),
            private.display().to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            "--".into(),
            local.display().to_string(),
            format!("ubuntu@{ip}:{remote}"),
        ],
        true,
        180,
    ))
}

pub(crate) fn scp_from_command(
    id: &str,
    state: &Ec2State,
    store: &Store,
    remote: &str,
    local: &Path,
) -> Result<FixedCommand> {
    let ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.as_str())
        .ok_or_else(|| contract("EIP state is missing"))?;
    let private = store.artifact_path(PRIVATE_KEY_SUFFIX)?;
    let known_hosts = store.artifact_path(KNOWN_HOSTS_SUFFIX)?;
    let local = fs::canonicalize(local)
        .map_err(|_| contract("client binding SCP staging path is unavailable"))?;
    Ok(FixedCommand::new(
        id,
        SCP,
        [
            "-q".into(),
            "-i".into(),
            private.display().to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            "--".into(),
            format!("ubuntu@{ip}:{remote}"),
            local.display().to_string(),
        ],
        false,
        180,
    ))
}

pub(crate) fn ssh_command<const N: usize>(
    id: &str,
    state: &Ec2State,
    store: &Store,
    remote_argv: [&str; N],
    mutation: bool,
    timeout: u64,
) -> Result<FixedCommand> {
    let ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.as_str())
        .ok_or_else(|| contract("EIP state is missing"))?;
    let private = store.artifact_path(PRIVATE_KEY_SUFFIX)?;
    let known_hosts = store.artifact_path(KNOWN_HOSTS_SUFFIX)?;
    let remote_command = render_remote_command(remote_argv)?;
    let argv = vec![
        "-i".into(),
        private.display().to_string(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        format!("ubuntu@{ip}"),
        remote_command,
    ];
    Ok(FixedCommand::new(id, SSH, argv, mutation, timeout))
}

pub(super) fn render_remote_command<const N: usize>(remote_argv: [&str; N]) -> Result<String> {
    let mut rendered = Vec::with_capacity(N);
    for argument in remote_argv {
        if argument.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(contract(
                "remote command argument contains control characters",
            ));
        }
        rendered.push(format!("'{}'", argument.replace('\'', "'\"'\"'")));
    }
    if rendered.is_empty() {
        return Err(contract("remote command must not be empty"));
    }
    Ok(rendered.join(" "))
}

fn verify_live_locked(
    store: &Store,
    state: &mut Ec2State,
    manifest: &AwsEc2Manifest,
    executor: &dyn AwsExecutor,
) -> Result<VerifyReport> {
    verify_caller_account(state, executor)?;
    let ip = state
        .eip
        .as_ref()
        .map(|eip| eip.public_ip.clone())
        .ok_or_else(|| contract("owned EIP is absent"))?;
    let dns = executor.run(&FixedCommand::new(
        "verify-dns-to-owned-eip",
        GETENT,
        ["ahostsv4", manifest.domain.as_str()],
        false,
        20,
    ))?;
    let addresses = dns
        .stdout
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().next())
        .filter_map(|value| value.parse::<Ipv4Addr>().ok())
        .collect::<BTreeSet<_>>();
    if addresses
        != BTreeSet::from([ip
            .parse::<Ipv4Addr>()
            .map_err(|_| contract("owned EIP is malformed"))?])
    {
        return Err(contract("DNS does not resolve exactly to the owned EIP"));
    }
    executor.run(&FixedCommand::new(
        "verify-system-tls-https-health",
        CURL,
        [
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "10",
            "--max-time",
            "20",
            "--output",
            "/dev/null",
            &format!("https://{}{HEALTH_PATH}", manifest.domain),
        ],
        false,
        30,
    ))?;
    let request_suffix = state
        .current_request_suffix
        .as_deref()
        .ok_or_else(|| contract("current install request is absent"))?;
    let request: InstallRequest =
        serde_json::from_slice(&store.read_artifact(request_suffix, 64 * 1024)?)?;
    let receipt_output = executor.run(&ssh_command(
        "verify-authenticated-installed-receipt",
        state,
        store,
        ["/usr/bin/sudo", "--non-interactive", REMOTE_RECEIPT_READER],
        false,
        30,
    )?)?;
    let receipt = InstalledReceipt::parse_and_verify(
        receipt_output.stdout.as_bytes(),
        &request,
        ReceiptState::Installed,
    )?;
    if state
        .current_receipt
        .as_ref()
        .is_some_and(|old| old.receipt_sha256 != receipt.receipt_sha256)
    {
        return Err(contract("remote installed receipt changed unexpectedly"));
    }
    let provision_suffix = state
        .provision_request_suffix
        .as_deref()
        .ok_or_else(|| contract("durable host provision request is absent"))?;
    let provision_bytes = store.read_artifact(provision_suffix, 64 * 1024)?;
    let provision = ProvisionRequest::parse_and_verify(&provision_bytes)?;
    let previous_ready = state
        .host_ready_receipt
        .as_ref()
        .ok_or_else(|| contract("host ready receipt state is absent"))?;
    if provision.sha256()? != previous_ready.request_sha256
        || provision.target != state.target
        || provision.domain != state.domain
        || provision.tenant_id != state.tenant_id
        || provision.indexer_id != state.indexer_id
        || Some(provision.private_ipv4.as_str()) != state.private_ipv4.as_deref()
    {
        return Err(contract(
            "durable host provision request changed unexpectedly",
        ));
    }
    let ready = read_host_ready_receipt(state, store, &provision, executor)?;
    if ready.receipt_sha256 != previous_ready.receipt_sha256 {
        return Err(contract("remote host ready receipt changed unexpectedly"));
    }
    state.current_receipt = Some(receipt.clone());
    state.host_ready_receipt = Some(ready);
    persist(store, state)?;
    Ok(VerifyReport {
        target: state.target.clone(),
        domain: state.domain.clone(),
        public_ip: ip,
        receipt_sha256: receipt.receipt_sha256,
        bundle_sha256: receipt.bundle_sha256,
        server_image: receipt.server_image,
        migrator_image: receipt.migrator_image,
        https_health_verified: true,
    })
}

fn verify_caller_account(state: &Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let output = executor.run(&FixedCommand::new(
        "verify-caller-account",
        AWS,
        ["sts", "get-caller-identity", "--output", "json"],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    if value["Account"].as_str() != state.account_id.as_deref() {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

pub fn status(manifest: &AwsEc2Manifest, state_dir: &Path) -> Result<StatusReport> {
    manifest.validate()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let state = load_state(&store, manifest)?;
    Ok(status_report(&state, None))
}

pub fn status_with_registry(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    registry: &dyn RegistryExecutor,
) -> Result<StatusReport> {
    manifest.validate()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let state = load_state(&store, manifest)?;
    let latest = resolve_latest_digest(registry)?;
    Ok(status_report(&state, Some(latest)))
}

fn status_report(state: &Ec2State, latest: Option<String>) -> StatusReport {
    let current_image = state
        .current_receipt
        .as_ref()
        .map(|receipt| receipt.server_image.clone())
        .or_else(|| {
            state
                .current
                .as_ref()
                .map(|record| record.server_image.clone())
        });
    let current_digest = current_image
        .as_deref()
        .and_then(|image| image.split_once("@sha256:"))
        .map(|(_, digest)| format!("sha256:{digest}"));
    let update_available = latest
        .as_ref()
        .zip(current_digest.as_ref())
        .map(|(latest, current)| latest != current);
    let offline_update_available = current_image
        .as_ref()
        .map(|current| current != &state.desired.server_image);
    StatusReport {
        target: state.target.clone(),
        operation_id: state.operation_id.clone(),
        account_id: state.account_id.clone(),
        region: state.region.clone(),
        domain: state.domain.clone(),
        phase: state.phase.clone(),
        current_image,
        desired_image: state.desired.server_image.clone(),
        latest_digest: latest,
        update_available,
        offline_update_available,
        instance_id: state.instance_id.clone(),
        public_ip: state.eip.as_ref().map(|eip| eip.public_ip.clone()),
        retained_volume_id: state
            .retained_volume
            .then(|| state.volume_id.clone())
            .flatten(),
    }
}

pub fn verify(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    executor: &dyn AwsExecutor,
) -> Result<VerifyReport> {
    manifest.validate()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = load_state(&store, manifest)?;
    if !matches!(
        state.phase,
        LifecyclePhase::Installed | LifecyclePhase::Verified
    ) {
        return Err(contract("verify requires an installed lifecycle"));
    }
    let report = verify_live_locked(&store, &mut state, manifest, executor)?;
    state.phase = LifecyclePhase::Verified;
    persist(&store, &mut state)?;
    Ok(report)
}

pub fn update(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let facts = manifest.bundle()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = load_state(&store, manifest)?;
    if state.phase == LifecyclePhase::RolledBack {
        return Err(contract(
            "a rolled-back lifecycle cannot start a new forward update",
        ));
    }
    let candidate = BundleRecord::from_facts(&facts, manifest);
    let (prior_bundle, prior_receipt) = if state.phase == LifecyclePhase::UpdateVerifying {
        (
            state
                .previous
                .clone()
                .ok_or_else(|| contract("retained immutable bundle is absent"))?,
            state
                .previous_receipt
                .clone()
                .ok_or_else(|| contract("retained installed receipt is absent"))?,
        )
    } else {
        (
            state
                .current
                .clone()
                .ok_or_else(|| contract("current immutable bundle is absent"))?,
            state
                .current_receipt
                .clone()
                .ok_or_else(|| contract("current installed receipt is absent"))?,
        )
    };
    if candidate == prior_bundle
        && matches!(
            state.phase,
            LifecyclePhase::Installed | LifecyclePhase::Verified | LifecyclePhase::RolledBack
        )
    {
        return Ok(state);
    }
    ensure_cross_version_contract(&prior_bundle, &prior_receipt, &candidate)?;
    match state.phase {
        LifecyclePhase::Installed | LifecyclePhase::Verified | LifecyclePhase::RolledBack => {}
        LifecyclePhase::UpdateStaged
        | LifecyclePhase::UpdateInstalling
        | LifecyclePhase::UpdateVerifying => {
            if state.desired != candidate {
                return Err(ReleaseError::OperationConflict);
            }
        }
        _ => {
            return Err(contract(
                "update recovery is fail-closed for this lifecycle phase",
            ));
        }
    }
    if !execute {
        return Ok(state);
    }

    if matches!(
        state.phase,
        LifecyclePhase::Installed | LifecyclePhase::Verified | LifecyclePhase::RolledBack
    ) {
        store.copy_artifact(
            UPDATE_BUNDLE_SUFFIX,
            &manifest.stack_bundle_path,
            &facts.bundle_sha256,
        )?;
        let request = InstallRequest::new(
            &state.domain,
            &facts,
            Some(prior_receipt.receipt_sha256.clone()),
        );
        store.write_artifact(UPDATE_REQUEST_SUFFIX, &request.canonical_bytes()?, 0o600)?;
        state.previous = Some(prior_bundle);
        state.previous_receipt = Some(prior_receipt);
        state
            .previous_bundle_suffix
            .clone_from(&state.current_bundle_suffix);
        state
            .previous_request_suffix
            .clone_from(&state.current_request_suffix);
        state.desired = candidate.clone();
        state.candidate_bundle_suffix = Some(UPDATE_BUNDLE_SUFFIX.into());
        state.candidate_request_suffix = Some(UPDATE_REQUEST_SUFFIX.into());
        state.phase = LifecyclePhase::UpdateStaged;
        state.pending_effect = None;
        persist(&store, &mut state)?;
    }
    ensure_update_capacity(&store, &state, executor)?;
    let bundle_suffix = state
        .candidate_bundle_suffix
        .clone()
        .ok_or_else(|| contract("candidate bundle fact is absent"))?;
    let request_suffix = state
        .candidate_request_suffix
        .clone()
        .ok_or_else(|| contract("candidate request fact is absent"))?;
    let request: InstallRequest =
        serde_json::from_slice(&store.read_artifact(&request_suffix, 64 * 1024)?)?;
    if request.bundle_sha256 != state.desired.bundle_sha256
        || request.previous_receipt_sha256
            != state
                .previous_receipt
                .as_ref()
                .map(|r| r.receipt_sha256.clone())
    {
        return Err(ReleaseError::OperationConflict);
    }
    let prior_request_suffix = state
        .previous_request_suffix
        .as_deref()
        .ok_or_else(|| contract("retained install request fact is absent"))?;
    let prior_request: InstallRequest =
        serde_json::from_slice(&store.read_artifact(prior_request_suffix, 64 * 1024)?)?;
    let retained_receipt = state
        .previous_receipt
        .as_ref()
        .ok_or_else(|| contract("retained receipt fact is absent"))?;
    if retained_receipt.state != ReceiptState::Installed
        || retained_receipt.bundle_sha256 != prior_request.bundle_sha256
        || retained_receipt.receipt_sha256
            != request.previous_receipt_sha256.clone().unwrap_or_default()
    {
        return Err(ReleaseError::OperationConflict);
    }
    state.phase = LifecyclePhase::UpdateInstalling;
    persist(&store, &mut state)?;
    let receipt = stage_install_read_receipt(
        &store,
        &mut state,
        &bundle_suffix,
        &request_suffix,
        &request,
        ReceiptState::Installed,
        Some((&prior_request, ReceiptState::Installed)),
        executor,
    )?;
    state.current = Some(candidate);
    state.current_receipt = Some(receipt);
    state.current_bundle_suffix = Some(bundle_suffix);
    state.current_request_suffix = Some(request_suffix);
    state.phase = LifecyclePhase::UpdateVerifying;
    persist(&store, &mut state)?;
    verify_live_locked(&store, &mut state, manifest, executor)?;
    state.phase = LifecyclePhase::Verified;
    state.pending_effect = None;
    persist(&store, &mut state)?;
    Ok(state)
}

fn ensure_cross_version_contract(
    prior: &BundleRecord,
    prior_receipt: &InstalledReceipt,
    candidate: &BundleRecord,
) -> Result<()> {
    let retained = prior.cross_version_compatibility.as_ref().ok_or_else(|| {
        contract("retained bundle lacks authenticated cross-version compatibility marker")
    })?;
    let proposed = candidate
        .cross_version_compatibility
        .as_ref()
        .ok_or_else(|| {
            contract("candidate bundle lacks authenticated cross-version compatibility marker")
        })?;
    retained.validate()?;
    proposed.validate()?;
    if prior.version != "0.1.1"
        || prior_receipt.version != prior.version
        || candidate.version != "0.1.4"
        || retained != proposed
        || retained.retained_version != prior.version
        || retained.candidate_version != candidate.version
    {
        return Err(contract(
            "only the authenticated forward 0.1.1 to 0.1.4 update is supported",
        ));
    }
    if candidate.postgres_image != prior.postgres_image
        || candidate.caddy_image != prior.caddy_image
        || candidate.probe_image != prior.probe_image
        || candidate.host_installer_sha256 != prior.host_installer_sha256
        || candidate.host_provisioner_sha256 != prior.host_provisioner_sha256
        || candidate.receipt_reader_sha256 != prior.receipt_reader_sha256
    {
        return Err(contract(
            "cross-version update cannot change retained host, dependency-image, or helper facts",
        ));
    }
    Ok(())
}

fn ensure_update_capacity(
    store: &Store,
    state: &Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let output = executor.run(&ssh_command(
        "check-authenticated-update-capacity",
        state,
        store,
        ["/usr/bin/df", "--output=avail,iavail", "-B1", "/"],
        false,
        30,
    )?)?;
    parse_update_capacity(&output.stdout)
}

pub(super) fn parse_update_capacity(output: &str) -> Result<()> {
    let values = output
        .lines()
        .skip(1)
        .flat_map(str::split_ascii_whitespace)
        .collect::<Vec<_>>();
    if values.len() != 2 {
        return Err(contract(
            "authenticated update capacity response is malformed",
        ));
    }
    let bytes = values[0]
        .parse::<u64>()
        .map_err(|_| contract("authenticated update capacity bytes are malformed"))?;
    let inodes = values[1]
        .parse::<u64>()
        .map_err(|_| contract("authenticated update capacity inodes are malformed"))?;
    if bytes < UPDATE_CAPACITY_BYTES || inodes < UPDATE_CAPACITY_INODES {
        return Err(contract(
            "authenticated remote capacity is insufficient for update",
        ));
    }
    Ok(())
}

/// A separately callable, code-only rollback primitive.  It never invokes a
/// down migration; the server-owned installer must authenticate a `rolled_back`
/// receipt against the retained request and candidate receipt chain.
pub fn rollback_update(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = load_state(&store, manifest)?;
    if !matches!(
        state.phase,
        LifecyclePhase::UpdateVerifying
            | LifecyclePhase::RollbackStaged
            | LifecyclePhase::RollbackInstalling
    ) {
        return Err(contract("rollback requires an unverified candidate update"));
    }
    let prior = state
        .previous
        .clone()
        .ok_or_else(|| contract("retained bundle is absent"))?;
    let candidate_receipt = state
        .current_receipt
        .clone()
        .ok_or_else(|| contract("candidate receipt is absent"))?;
    let marker = prior
        .cross_version_compatibility
        .as_ref()
        .ok_or_else(|| contract("retained rollback marker is absent"))?;
    marker.validate()?;
    state
        .desired
        .cross_version_compatibility
        .as_ref()
        .ok_or_else(|| contract("candidate rollback marker is absent"))?
        .validate()?;
    if !execute {
        return Ok(state);
    }
    let previous_bundle = state
        .previous_bundle_suffix
        .clone()
        .ok_or_else(|| contract("retained bundle artifact is absent"))?;
    let request = InstallRequest {
        schema: "dirextalk.vnext-install-request".into(),
        schema_version: 1,
        target: state.target.clone(),
        domain: state.domain.clone(),
        version: prior.version.clone(),
        source_commit: prior.source_commit.clone(),
        bundle_sha256: prior.bundle_sha256.clone(),
        manifest_sha256: prior.manifest_sha256.clone(),
        server_image: prior.server_image.clone(),
        migrator_image: prior.migrator_image.clone(),
        previous_receipt_sha256: Some(candidate_receipt.receipt_sha256),
    };
    store.write_artifact(ROLLBACK_REQUEST_SUFFIX, &request.canonical_bytes()?, 0o600)?;
    state.phase = LifecyclePhase::RollbackStaged;
    persist(&store, &mut state)?;
    state.phase = LifecyclePhase::RollbackInstalling;
    persist(&store, &mut state)?;
    let candidate_request_suffix = state
        .candidate_request_suffix
        .as_deref()
        .ok_or_else(|| contract("candidate install request fact is absent"))?;
    let candidate_request: InstallRequest =
        serde_json::from_slice(&store.read_artifact(candidate_request_suffix, 64 * 1024)?)?;
    let receipt = stage_install_read_receipt(
        &store,
        &mut state,
        &previous_bundle,
        ROLLBACK_REQUEST_SUFFIX,
        &request,
        ReceiptState::RolledBack,
        Some((&candidate_request, ReceiptState::Installed)),
        executor,
    )?;
    state.current = Some(prior);
    state.current_receipt = Some(receipt.clone());
    state.rollback_receipt = Some(receipt);
    state.current_bundle_suffix = Some(previous_bundle);
    state.current_request_suffix = Some(ROLLBACK_REQUEST_SUFFIX.into());
    state.phase = LifecyclePhase::RolledBack;
    state.pending_effect = None;
    persist(&store, &mut state)?;
    Ok(state)
}

/// Reconcile a narrowly fenced operator SSH CIDR recovery without changing lifecycle phase.
pub fn rebind_operator_cidr(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    expected_old_cidr: &str,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let facts = manifest.bundle()?;
    super::operator_cidr(expected_old_cidr)?;
    if expected_old_cidr == manifest.operator_ssh_cidr {
        return Err(contract(
            "expected old operator SSH CIDR must differ from manifest CIDR",
        ));
    }
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = read_verified_state(&store)?
        .ok_or_else(|| contract("no owned EC2 lifecycle state exists"))?;
    ensure_rebind_phase(&state.phase)?;
    ensure_rebind_pending_effect(state.pending_effect.as_deref())?;
    ensure_rebind_identity(&state, manifest, &facts)?;
    if state.infrastructure.operator_ssh_cidr != expected_old_cidr {
        return Err(ReleaseError::OperationConflict);
    }
    if !execute {
        return Ok(state);
    }
    verify_caller_account(&state, executor)?;
    let security_group_id = state
        .security_group_id
        .clone()
        .ok_or_else(|| contract("recorded security group is missing"))?;
    let group = describe_exact_owned_security_group(&state, &security_group_id, executor)?;
    let ingress = classify_rebind_ingress(
        &group["IpPermissions"],
        expected_old_cidr,
        &manifest.operator_ssh_cidr,
    )?;
    match ingress {
        RebindIngress::OldOnly => {
            run_effect(
                &store,
                &mut state,
                &operator_ingress_command(
                    "rebind-authorize-operator-ssh-cidr",
                    "authorize-security-group-ingress",
                    &security_group_id,
                    &manifest.operator_ssh_cidr,
                )?,
                executor,
            )?;
            if !matches!(
                classify_rebind_ingress(
                    &describe_exact_owned_security_group(&state, &security_group_id, executor)?["IpPermissions"],
                    expected_old_cidr,
                    &manifest.operator_ssh_cidr,
                )?,
                RebindIngress::Both
            ) {
                return Err(contract(
                    "operator SSH ingress did not reconcile after authorization",
                ));
            }
            revoke_old_operator_ingress(
                &store,
                &mut state,
                &security_group_id,
                expected_old_cidr,
                &manifest.operator_ssh_cidr,
                executor,
            )?;
        }
        RebindIngress::Both => revoke_old_operator_ingress(
            &store,
            &mut state,
            &security_group_id,
            expected_old_cidr,
            &manifest.operator_ssh_cidr,
            executor,
        )?,
        RebindIngress::NewOnly => {}
    }
    // A crash after revoke leaves state old but the exact new-only remote shape; this is
    // intentionally the only post-effect state accepted above and converges here.
    state
        .infrastructure
        .operator_ssh_cidr
        .clone_from(&manifest.operator_ssh_cidr);
    state.pending_effect = None;
    persist(&store, &mut state)?;
    Ok(state)
}

fn ensure_rebind_phase(phase: &LifecyclePhase) -> Result<()> {
    match phase {
        LifecyclePhase::UpdateStaged
        | LifecyclePhase::UpdateInstalling
        | LifecyclePhase::UpdateVerifying
        | LifecyclePhase::RollbackStaged
        | LifecyclePhase::RollbackInstalling
        | LifecyclePhase::RolledBack
        | LifecyclePhase::Destroying
        | LifecyclePhase::InfrastructureRemovedVolumeRetained
        | LifecyclePhase::VolumePurged => Err(contract(
            "operator SSH CIDR rebind refuses update, rollback, destroying, or terminal lifecycle state",
        )),
        _ => Ok(()),
    }
}

fn ensure_rebind_pending_effect(pending_effect: Option<&str>) -> Result<()> {
    if matches!(
        pending_effect,
        None | Some("rebind-authorize-operator-ssh-cidr" | "rebind-revoke-operator-ssh-cidr")
    ) {
        Ok(())
    } else {
        Err(ReleaseError::OperationConflict)
    }
}

fn ensure_rebind_identity(
    state: &Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &BundleFacts,
) -> Result<()> {
    let mut expected_infrastructure = InfrastructureRecord::from_manifest(manifest);
    expected_infrastructure
        .operator_ssh_cidr
        .clone_from(&state.infrastructure.operator_ssh_cidr);
    if state.target != manifest.target
        || state.region != manifest.region
        || state.domain != manifest.domain
        || state.infrastructure != expected_infrastructure
        || state.desired != BundleRecord::from_facts(facts, manifest)
        || state
            .key
            .as_ref()
            .is_some_and(|key| key.key_name != manifest.key_name)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

enum RebindIngress {
    OldOnly,
    Both,
    NewOnly,
}

fn describe_exact_owned_security_group(
    state: &Ec2State,
    security_group_id: &str,
    executor: &dyn AwsExecutor,
) -> Result<Value> {
    let output = executor.run(&FixedCommand::new(
        "describe-exact-owned-security-group",
        AWS,
        [
            "ec2",
            "describe-security-groups",
            "--region",
            REGION,
            "--group-ids",
            security_group_id,
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let groups = value["SecurityGroups"]
        .as_array()
        .ok_or_else(|| contract("security group response is malformed"))?;
    if groups.len() != 1
        || groups[0]["GroupId"].as_str() != Some(security_group_id)
        || groups[0]["VpcId"].as_str() != state.vpc_id.as_deref()
        || !tags_match(&groups[0]["Tags"], state)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(groups[0].clone())
}

fn classify_rebind_ingress(actual: &Value, old: &str, new: &str) -> Result<RebindIngress> {
    let old_expected = rebind_permissions(&[old]);
    let new_expected = rebind_permissions(&[new]);
    let both_expected = rebind_permissions(&[old, new]);
    if permissions_match(actual, &old_expected)? {
        Ok(RebindIngress::OldOnly)
    } else if permissions_match(actual, &both_expected)? {
        Ok(RebindIngress::Both)
    } else if permissions_match(actual, &new_expected)? {
        Ok(RebindIngress::NewOnly)
    } else {
        Err(ReleaseError::OperationConflict)
    }
}

fn rebind_permissions(operator_cidrs: &[&str]) -> Value {
    let mut permissions = vec![
        json!({"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk ACME HTTP challenge"}]}),
        json!({"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk public HTTPS"}]}),
        json!({"IpProtocol":"tcp","FromPort":9443,"ToPort":9445,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk Agent Control TLS"}]}),
    ];
    permissions.extend(
        operator_cidrs
            .iter()
            .map(|cidr| operator_ingress_permission(cidr)),
    );
    Value::Array(permissions)
}

fn operator_ingress_permission(cidr: &str) -> Value {
    json!({"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":cidr,"Description":"Dirextalk operator SSH"}]})
}

fn operator_ingress_command(
    id: &str,
    action: &str,
    security_group_id: &str,
    cidr: &str,
) -> Result<FixedCommand> {
    Ok(FixedCommand::new(
        id,
        AWS,
        [
            "ec2".into(),
            action.into(),
            "--region".into(),
            REGION.into(),
            "--group-id".into(),
            security_group_id.into(),
            "--ip-permissions".into(),
            serde_json::to_string(&Value::Array(vec![operator_ingress_permission(cidr)]))?,
        ],
        true,
        45,
    ))
}

fn revoke_old_operator_ingress(
    store: &Store,
    state: &mut Ec2State,
    security_group_id: &str,
    old_cidr: &str,
    new_cidr: &str,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    run_effect(
        store,
        state,
        &operator_ingress_command(
            "rebind-revoke-operator-ssh-cidr",
            "revoke-security-group-ingress",
            security_group_id,
            old_cidr,
        )?,
        executor,
    )?;
    if !matches!(
        classify_rebind_ingress(
            &describe_exact_owned_security_group(state, security_group_id, executor)?["IpPermissions"],
            old_cidr,
            new_cidr,
        )?,
        RebindIngress::NewOnly
    ) {
        return Err(contract(
            "operator SSH ingress did not reconcile after revocation",
        ));
    }
    Ok(())
}

fn load_state(store: &Store, manifest: &AwsEc2Manifest) -> Result<Ec2State> {
    let state = read_verified_state(store)?
        .ok_or_else(|| contract("no owned EC2 lifecycle state exists"))?;
    if state.target != manifest.target
        || state.region != manifest.region
        || state.domain != manifest.domain
        || state.infrastructure != InfrastructureRecord::from_manifest(manifest)
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(state)
}

fn read_verified_state(store: &Store) -> Result<Option<Ec2State>> {
    let Some((mut state, bytes)) = store.read_with_bytes::<Ec2State>()? else {
        return Ok(None);
    };
    if state.verify().is_err() {
        state.verify_legacy_bytes(&bytes)?;
        // The Store lock is already held. Resealing is a local schema migration,
        // occurs before any later effect, and preserves all lifecycle facts.
        persist(store, &mut state)?;
    }
    Ok(Some(state))
}

pub fn destroy(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    purge_volume: bool,
    purge_volume_id: Option<&str>,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let store = Store::lock(state_dir, &manifest.target)?;
    let mut state = load_state(&store, manifest)?;
    if purge_volume {
        let expected = state
            .volume_id
            .clone()
            .ok_or_else(|| contract("purge requires a recorded retained volume"))?;
        if purge_volume_id != Some(expected.as_str()) {
            return Err(contract(
                "purge requires --purge-volume-id matching the recorded volume",
            ));
        }
        if state.phase != LifecyclePhase::InfrastructureRemovedVolumeRetained {
            return Err(contract(
                "volume purge is separately fenced after infrastructure removal",
            ));
        }
        if !execute {
            return Ok(state);
        }
        verify_caller_account(&state, executor)?;
        let volumes = describe_volumes_by_id(&expected, executor)?;
        if volumes.is_empty()
            && state.pending_effect.as_deref() == Some("purge-explicit-retained-volume")
        {
            state.retained_volume = false;
            state.phase = LifecyclePhase::VolumePurged;
            state.pending_effect = None;
            clear_terminal_runtime_evidence(&mut state);
            persist(&store, &mut state)?;
            return Ok(state);
        }
        verify_owned_volume(&state, &expected, true, executor)?;
        let command = FixedCommand::new(
            "purge-explicit-retained-volume",
            AWS,
            [
                "ec2",
                "delete-volume",
                "--region",
                REGION,
                "--volume-id",
                expected.as_str(),
            ],
            true,
            60,
        );
        before_effect(&store, &mut state, &command.id)?;
        executor.run(&command)?;
        state.retained_volume = false;
        state.phase = LifecyclePhase::VolumePurged;
        state.pending_effect = None;
        clear_terminal_runtime_evidence(&mut state);
        persist(&store, &mut state)?;
        return Ok(state);
    }
    if matches!(
        state.phase,
        LifecyclePhase::InfrastructureRemovedVolumeRetained | LifecyclePhase::VolumePurged
    ) {
        return Ok(state);
    }
    if !execute {
        return Ok(state);
    }
    verify_caller_account(&state, executor)?;
    state.phase = LifecyclePhase::Destroying;
    persist(&store, &mut state)?;
    destroy_dns(&store, &mut state, executor)?;
    destroy_eip_association(&store, &mut state, executor)?;
    retain_and_terminate_instance(&store, &mut state, executor)?;
    destroy_eip(&store, &mut state, executor)?;
    destroy_security_group(&store, &mut state, executor)?;
    destroy_cloud_key(&store, &mut state, executor)?;
    store.remove_artifact(PRIVATE_KEY_SUFFIX)?;
    store.remove_artifact(PUBLIC_KEY_SUFFIX)?;
    store.remove_artifact(KNOWN_HOSTS_SUFFIX)?;
    state.retained_volume = true;
    state.phase = LifecyclePhase::InfrastructureRemovedVolumeRetained;
    state.pending_effect = None;
    clear_terminal_runtime_evidence(&mut state);
    persist(&store, &mut state)?;
    Ok(state)
}

pub(super) fn clear_terminal_runtime_evidence(state: &mut Ec2State) {
    state.host_key = None;
    state.current_receipt = None;
    state.previous_receipt = None;
    state.rollback_receipt = None;
    state.host_ready_receipt = None;
}

fn destroy_dns(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let Some(record) = state.dns.clone() else {
        return Ok(());
    };
    let existing = read_record_set(&record.hosted_zone_id, &record.name, executor)?;
    match existing {
        None => {
            state.dns = None;
            persist(store, state)?;
            return Ok(());
        }
        Some(value)
            if value["Type"].as_str() == Some(record.record_type.as_str())
                && value["TTL"].as_u64() == Some(u64::from(record.ttl))
                && value["ResourceRecords"].as_array().is_some_and(|items| {
                    items.len() == 1 && items[0]["Value"].as_str() == Some(record.value.as_str())
                }) => {}
        Some(_) => return Err(ReleaseError::OperationConflict),
    }
    let output = run_effect(
        store,
        state,
        &FixedCommand::new(
            "delete-exact-owned-dns-record",
            AWS,
            [
                "route53".into(),
                "change-resource-record-sets".into(),
                "--hosted-zone-id".into(),
                record.hosted_zone_id.clone(),
                "--change-batch".into(),
                serde_json::to_string(&route53_change("DELETE", &record.name, &record.value))?,
                "--output".into(),
                "json".into(),
            ],
            true,
            45,
        ),
        executor,
    )?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let change = value["ChangeInfo"]["Id"]
        .as_str()
        .ok_or_else(|| contract("Route53 delete change id is missing"))?
        .trim_start_matches("/change/")
        .to_owned();
    run_effect(
        store,
        state,
        &FixedCommand::new(
            "wait-exact-dns-delete",
            AWS,
            [
                "route53".into(),
                "wait".into(),
                "resource-record-sets-changed".into(),
                "--id".into(),
                change,
            ],
            false,
            300,
        ),
        executor,
    )?;
    state.dns = None;
    persist(store, state)
}

fn destroy_eip_association(
    store: &Store,
    state: &mut Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let Some(eip) = state.eip.clone() else {
        return Ok(());
    };
    let addresses = describe_addresses_by_allocation(&eip.allocation_id, executor)?;
    if addresses.is_empty() {
        state.eip = None;
        return persist(store, state);
    }
    if addresses.len() != 1 || !tags_match(&addresses[0]["Tags"], state) {
        return Err(ReleaseError::OperationConflict);
    }
    if let Some(association) = addresses[0]["AssociationId"].as_str() {
        if association != eip.association_id {
            return Err(ReleaseError::OperationConflict);
        }
        run_effect(
            store,
            state,
            &FixedCommand::new(
                "disassociate-exact-owned-eip",
                AWS,
                [
                    "ec2",
                    "disassociate-address",
                    "--region",
                    REGION,
                    "--association-id",
                    association,
                ],
                true,
                45,
            ),
            executor,
        )?;
    }
    Ok(())
}

fn retain_and_terminate_instance(
    store: &Store,
    state: &mut Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let volume_id = state
        .volume_id
        .clone()
        .ok_or_else(|| contract("recorded root volume is missing"))?;
    verify_owned_volume(state, &volume_id, false, executor)?;
    run_effect(
        store,
        state,
        &FixedCommand::new(
            "tag-explicit-retained-volume",
            AWS,
            [
                "ec2".into(),
                "create-tags".into(),
                "--region".into(),
                REGION.into(),
                "--resources".into(),
                volume_id.clone(),
                "--tags".into(),
                "Key=DirextalkRetained,Value=true".into(),
            ],
            true,
            45,
        ),
        executor,
    )?;
    verify_owned_volume(state, &volume_id, true, executor)?;
    if let Some(instance_id) = state.instance_id.clone() {
        let instances = describe_instance_by_id(&instance_id, executor)?;
        if let Some(instance) = instances.first() {
            if instances.len() != 1 || !tags_match(&instance["Tags"], state) {
                return Err(ReleaseError::OperationConflict);
            }
            if instance["State"]["Name"].as_str() != Some("terminated") {
                run_effect(
                    store,
                    state,
                    &FixedCommand::new(
                        "terminate-exact-owned-instance",
                        AWS,
                        [
                            "ec2".into(),
                            "terminate-instances".into(),
                            "--region".into(),
                            REGION.into(),
                            "--instance-ids".into(),
                            instance_id.clone(),
                        ],
                        true,
                        60,
                    ),
                    executor,
                )?;
                run_effect(
                    store,
                    state,
                    &FixedCommand::new(
                        "wait-exact-instance-terminated",
                        AWS,
                        [
                            "ec2".into(),
                            "wait".into(),
                            "instance-terminated".into(),
                            "--region".into(),
                            REGION.into(),
                            "--instance-ids".into(),
                            instance_id,
                        ],
                        false,
                        600,
                    ),
                    executor,
                )?;
            }
        }
    }
    state.instance_id = None;
    state.retained_volume = true;
    persist(store, state)
}

fn destroy_eip(store: &Store, state: &mut Ec2State, executor: &dyn AwsExecutor) -> Result<()> {
    let Some(eip) = state.eip.clone() else {
        return Ok(());
    };
    let addresses = describe_addresses_by_allocation(&eip.allocation_id, executor)?;
    if addresses.is_empty() {
        state.eip = None;
        return persist(store, state);
    }
    if addresses.len() != 1
        || !tags_match(&addresses[0]["Tags"], state)
        || addresses[0]["AssociationId"].as_str().is_some()
    {
        return Err(ReleaseError::OperationConflict);
    }
    run_effect(
        store,
        state,
        &FixedCommand::new(
            "release-exact-owned-eip",
            AWS,
            [
                "ec2".into(),
                "release-address".into(),
                "--region".into(),
                REGION.into(),
                "--allocation-id".into(),
                eip.allocation_id,
            ],
            true,
            45,
        ),
        executor,
    )?;
    state.eip = None;
    persist(store, state)
}

fn destroy_security_group(
    store: &Store,
    state: &mut Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let Some(id) = state.security_group_id.clone() else {
        return Ok(());
    };
    let groups = describe_group_by_id(&id, executor)?;
    if groups.is_empty() {
        state.security_group_id = None;
        return persist(store, state);
    }
    if groups.len() != 1 || !tags_match(&groups[0]["Tags"], state) {
        return Err(ReleaseError::OperationConflict);
    }
    run_effect(
        store,
        state,
        &FixedCommand::new(
            "delete-exact-owned-security-group",
            AWS,
            [
                "ec2".into(),
                "delete-security-group".into(),
                "--region".into(),
                REGION.into(),
                "--group-id".into(),
                id,
            ],
            true,
            60,
        ),
        executor,
    )?;
    state.security_group_id = None;
    persist(store, state)
}

fn destroy_cloud_key(
    store: &Store,
    state: &mut Ec2State,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let Some(key) = state.key.clone() else {
        return Ok(());
    };
    let pairs = describe_key_pairs(&key.key_name, executor)?;
    if pairs.is_empty() {
        state.key = None;
        return persist(store, state);
    }
    if pairs.len() != 1 || validate_key_pair(&pairs[0], state).is_err() {
        return Err(ReleaseError::OperationConflict);
    }
    run_effect(
        store,
        state,
        &FixedCommand::new(
            "delete-exact-owned-cloud-key",
            AWS,
            [
                "ec2".into(),
                "delete-key-pair".into(),
                "--region".into(),
                REGION.into(),
                "--key-name".into(),
                key.key_name,
            ],
            true,
            45,
        ),
        executor,
    )?;
    state.key = None;
    persist(store, state)
}

fn verify_owned_volume(
    state: &Ec2State,
    volume_id: &str,
    retained: bool,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let volumes = describe_volumes_by_id(volume_id, executor)?;
    if volumes.len() != 1
        || volumes[0]["VolumeId"].as_str() != Some(volume_id)
        || !tags_match(&volumes[0]["Tags"], state)
    {
        return Err(ReleaseError::OperationConflict);
    }
    let has_retained = tag_value(&volumes[0]["Tags"], "DirextalkRetained") == Some("true");
    if has_retained != retained {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn describe_volumes_by_id(volume_id: &str, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let output = executor.run(&FixedCommand::new(
        "describe-exact-volume",
        AWS,
        [
            "ec2",
            "describe-volumes",
            "--region",
            REGION,
            "--filters",
            &format!("Name=volume-id,Values={volume_id}"),
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let volumes = value["Volumes"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("volume response is malformed"))?;
    Ok(volumes)
}

fn describe_addresses_by_allocation(
    allocation_id: &str,
    executor: &dyn AwsExecutor,
) -> Result<Vec<Value>> {
    let output = executor.run(&FixedCommand::new(
        "describe-exact-eip",
        AWS,
        [
            "ec2",
            "describe-addresses",
            "--region",
            REGION,
            "--filters",
            &format!("Name=allocation-id,Values={allocation_id}"),
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    value["Addresses"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("EIP response is malformed"))
}

fn describe_instance_by_id(instance_id: &str, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let output = executor.run(&FixedCommand::new(
        "describe-exact-instance",
        AWS,
        [
            "ec2",
            "describe-instances",
            "--region",
            REGION,
            "--filters",
            &format!("Name=instance-id,Values={instance_id}"),
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    let reservations = value["Reservations"]
        .as_array()
        .ok_or_else(|| contract("instance response is malformed"))?;
    Ok(reservations
        .iter()
        .flat_map(|reservation| {
            reservation["Instances"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned()
        })
        .collect())
}

fn describe_group_by_id(group_id: &str, executor: &dyn AwsExecutor) -> Result<Vec<Value>> {
    let output = executor.run(&FixedCommand::new(
        "describe-exact-security-group",
        AWS,
        [
            "ec2",
            "describe-security-groups",
            "--region",
            REGION,
            "--filters",
            &format!("Name=group-id,Values={group_id}"),
            "--output",
            "json",
        ],
        false,
        30,
    ))?;
    let value: Value = serde_json::from_str(&output.stdout)?;
    value["SecurityGroups"]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("security group response is malformed"))
}

fn append_tag_filters(argv: &mut Vec<String>, state: &Ec2State) {
    for (key, value) in expected_tags(state) {
        argv.push(format!("Name=tag:{key},Values={value}"));
    }
}

fn tag_spec(resource_type: &str, state: &Ec2State) -> String {
    let tags = expected_tags(state)
        .into_iter()
        .map(|(key, value)| format!("{{Key={key},Value={value}}}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("ResourceType={resource_type},Tags=[{tags}]")
}

fn tags_match(value: &Value, state: &Ec2State) -> bool {
    expected_tags(state)
        .iter()
        .all(|(key, expected)| tag_value(value, key) == Some(expected.as_str()))
}

fn tag_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_array()?.iter().find_map(|tag| {
        (tag["Key"].as_str() == Some(key))
            .then(|| tag["Value"].as_str())
            .flatten()
    })
}

fn json_string(value: &Value, key: &str) -> Result<String> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .map(str::to_owned)
        .ok_or_else(|| contract(&format!("AWS response field {key} is missing or invalid")))
}

fn normalize_dns_name(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_attestation_binds_instance_token_ami_and_key_digest() {
        let key = STANDARD.encode(b"ed25519-host-key");
        let key_sha = hash(b"ed25519-host-key");
        let token_sha = "a".repeat(64);
        let line = format!("DTXHK01 i-123 {token_sha} ami-456 {key} {key_sha}");
        let parsed =
            parse_console_host_key(&line, "i-123", &token_sha, "ami-456").expect("attestation");
        assert_eq!(parsed.0, key);
        assert_eq!(parsed.1, key_sha);
        assert!(parse_console_host_key(&line, "i-other", &token_sha, "ami-456").is_err());
        assert!(
            parse_console_host_key(&format!("{line}\n{line}"), "i-123", &token_sha, "ami-456")
                .is_err()
        );
    }

    #[test]
    fn scanned_host_key_must_be_one_exact_ed25519_key() {
        let key = STANDARD.encode(b"ed25519-host-key");
        let output = format!("203.0.113.8 ssh-ed25519 {key}\n");
        assert_eq!(
            parse_scanned_host_key(&output, "203.0.113.8")
                .expect("scan")
                .1,
            hash(b"ed25519-host-key")
        );
        assert!(parse_scanned_host_key(&output, "203.0.113.9").is_err());
    }

    #[test]
    fn security_group_comparison_rejects_any_extra_range() {
        let expected = json!([
            {"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk public HTTPS"}]}
        ]);
        assert!(permissions_match(&expected, &expected).expect("permissions"));
        let extra = json!([
            {"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[
                {"CidrIp":"0.0.0.0/0","Description":"Dirextalk public HTTPS"},
                {"CidrIp":"10.0.0.0/8","Description":"extra"}
            ]}
        ]);
        assert!(!permissions_match(&extra, &expected).expect("extra range is not an exact match"));
    }

    #[test]
    fn remote_stage_hash_requires_one_fixed_path_exactly_once() {
        let bundle = "a".repeat(64);
        let output = format!("{bundle}  {REMOTE_BUNDLE}\n");
        verify_single_remote_hash(&output, REMOTE_BUNDLE, &bundle).expect("hash");
        assert!(
            verify_single_remote_hash(
                &format!("{bundle}  {REMOTE_BUNDLE}\n{bundle}  {REMOTE_REQUEST}\n"),
                REMOTE_BUNDLE,
                &bundle,
            )
            .is_err()
        );
    }
}

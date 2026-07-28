//! In-process AWS SDK transport for the new-user deployment path.
//!
//! This module deliberately returns the narrow JSON shapes consumed by the
//! existing durable EC2 state machine. Credentials never enter an argument
//! vector, child environment, log, state file, or error string.

use std::{path::Path, time::Duration};

use aws_config::{BehaviorVersion, SdkConfig};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_ec2::{
    Client as Ec2Client,
    config::Region,
    error::ProvideErrorMetadata,
    types::{
        BlockDeviceMapping, EbsBlockDevice, Filter, InstanceMetadataEndpointState,
        InstanceMetadataOptionsRequest, InstanceMetadataTagsState, InstanceType, IpPermission,
        IpRange, ResourceType, Tag, TagSpecification, VolumeType,
    },
};
use aws_sdk_iam::Client as IamClient;
use aws_sdk_lightsail::Client as LightsailClient;
use aws_sdk_route53::{
    Client as Route53Client,
    types::{Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType},
};
use aws_sdk_sts::Client as StsClient;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tokio::{runtime::Runtime, time::sleep};

use crate::{
    ReleaseError, Result,
    aws_ec2::{ExecOutput, FixedCommand},
    rootkey::AwsRootKey,
};

const REDACTED_AWS_FAILURE: &str = "AWS SDK operation failed";

pub(crate) struct AwsSdkExecutor {
    runtime: Runtime,
    config: SdkConfig,
}

impl AwsSdkExecutor {
    pub(crate) fn new(rootkey: &AwsRootKey) -> Result<Self> {
        let runtime = Runtime::new()
            .map_err(|_| ReleaseError::Deployment("AWS runtime initialization failed".into()))?;
        let credentials = rootkey.expose(|access_key_id, secret_access_key, session_token| {
            Credentials::new(
                access_key_id,
                secret_access_key,
                session_token.map(str::to_owned),
                None,
                "dirextalk-rootkey-csv",
            )
        });
        let config = runtime.block_on(
            aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .credentials_provider(SharedCredentialsProvider::new(credentials))
                .load(),
        );
        Ok(Self { runtime, config })
    }

    pub(crate) fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        if command.program != "aws" {
            return Err(ReleaseError::Deployment(
                "AWS SDK executor received a non-AWS command".into(),
            ));
        }
        let result = self
            .runtime
            .block_on(self.dispatch(&command.argv, Duration::from_secs(command.timeout_seconds)))?;
        Ok(ExecOutput {
            status: 0,
            stdout: result,
            stderr: String::new(),
        })
    }

    async fn dispatch(&self, argv: &[String], timeout: Duration) -> Result<String> {
        match (
            argv.first().map(String::as_str),
            argv.get(1).map(String::as_str),
        ) {
            (Some("sts"), Some("get-caller-identity")) => self.get_caller_identity().await,
            (Some("iam"), Some("list-access-keys")) => self.list_access_keys(argv).await,
            (Some("ec2"), Some(action)) => self.ec2(action, argv, timeout).await,
            (Some("lightsail"), Some(action)) => self.lightsail(action, argv).await,
            (Some("route53"), Some(action)) => self.route53(action, argv, timeout).await,
            _ => Err(contract()),
        }
    }

    async fn get_caller_identity(&self) -> Result<String> {
        let output = StsClient::new(&self.config)
            .get_caller_identity()
            .send()
            .await
            .map_err(|_| contract())?;
        json_text(json!({
            "Account": output.account(),
            "Arn": output.arn(),
            "UserId": output.user_id(),
        }))
    }

    async fn list_access_keys(&self, argv: &[String]) -> Result<String> {
        let mut request = IamClient::new(&self.config).list_access_keys();
        if let Some(user_name) = arg(argv, "--user-name") {
            request = request.user_name(user_name);
        }
        let output = request.send().await.map_err(|_| contract())?;
        json_text(json!({
            "AccessKeyMetadata": output.access_key_metadata().iter().map(|key| json!({
                "UserName": key.user_name(),
                "AccessKeyId": key.access_key_id(),
                "Status": key.status().map(aws_sdk_iam::types::StatusType::as_str),
                "CreateDate": key.create_date().map(ToString::to_string),
            })).collect::<Vec<_>>()
        }))
    }

    async fn ec2(&self, action: &str, argv: &[String], timeout: Duration) -> Result<String> {
        let region = arg(argv, "--region").unwrap_or("us-east-1");
        let config = aws_sdk_ec2::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(self.config.credentials_provider().ok_or_else(contract)?)
            .region(Region::new(region.to_owned()))
            .build();
        let client = Ec2Client::from_conf(config);
        match action {
            "describe-images" => describe_images(&client, argv).await,
            "import-key-pair" => import_key_pair(&client, argv).await,
            "describe-key-pairs" => describe_key_pairs(&client, argv).await,
            "describe-vpcs" => describe_vpcs(&client, argv).await,
            "create-security-group" => create_security_group(&client, argv).await,
            "authorize-security-group-ingress" => {
                change_security_group_ingress(&client, argv, true).await
            }
            "revoke-security-group-ingress" => {
                change_security_group_ingress(&client, argv, false).await
            }
            "describe-security-groups" => describe_security_groups(&client, argv).await,
            "run-instances" => run_instances(&client, argv).await,
            "describe-instances" => describe_instances(&client, argv).await,
            "allocate-address" => allocate_address(&client, argv).await,
            "associate-address" => associate_address(&client, argv).await,
            "describe-addresses" => describe_addresses(&client, argv).await,
            "get-console-output" => get_console_output(&client, argv).await,
            "create-tags" => create_tags(&client, argv).await,
            "terminate-instances" => terminate_instances(&client, argv).await,
            "disassociate-address" => disassociate_address(&client, argv).await,
            "release-address" => release_address(&client, argv).await,
            "delete-security-group" => delete_security_group(&client, argv).await,
            "delete-key-pair" => delete_key_pair(&client, argv).await,
            "describe-volumes" => describe_volumes(&client, argv).await,
            "delete-volume" => delete_volume(&client, argv).await,
            "wait" => wait_ec2(&client, argv, timeout).await,
            _ => Err(contract()),
        }
    }

    async fn route53(&self, action: &str, argv: &[String], timeout: Duration) -> Result<String> {
        let client = Route53Client::new(&self.config);
        match action {
            "list-hosted-zones" => list_hosted_zones(&client).await,
            "list-resource-record-sets" => list_resource_record_sets(&client, argv).await,
            "change-resource-record-sets" => change_resource_record_sets(&client, argv).await,
            "wait" => wait_route53(&client, argv, timeout).await,
            _ => Err(contract()),
        }
    }

    async fn lightsail(&self, action: &str, argv: &[String]) -> Result<String> {
        let region = arg(argv, "--region").unwrap_or("us-east-1");
        let config = aws_sdk_lightsail::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(self.config.credentials_provider().ok_or_else(contract)?)
            .region(Region::new(region.to_owned()))
            .build();
        let client = LightsailClient::from_conf(config);
        match action {
            "get-regions" => lightsail_regions(&client).await,
            "get-blueprints" => lightsail_blueprints(&client).await,
            "get-bundles" => lightsail_bundles(&client).await,
            _ => Err(contract()),
        }
    }
}

fn contract() -> ReleaseError {
    ReleaseError::Deployment(REDACTED_AWS_FAILURE.into())
}

#[allow(clippy::needless_pass_by_value)]
fn json_text(value: Value) -> Result<String> {
    serde_json::to_string(&value).map_err(ReleaseError::from)
}

fn arg<'a>(argv: &'a [String], name: &str) -> Option<&'a str> {
    argv.windows(2)
        .find_map(|pair| (pair[0] == name).then_some(pair[1].as_str()))
}

fn all_after<'a>(argv: &'a [String], name: &str) -> Vec<&'a str> {
    let Some(index) = argv.iter().position(|value| value == name) else {
        return Vec::new();
    };
    argv[index + 1..]
        .iter()
        .take_while(|value| !value.starts_with("--"))
        .map(String::as_str)
        .collect()
}

fn filters(argv: &[String]) -> Result<Vec<Filter>> {
    all_after(argv, "--filters")
        .into_iter()
        .map(|value| {
            let (name, values) = value.split_once(",Values=").ok_or_else(contract)?;
            let name = name.strip_prefix("Name=").ok_or_else(contract)?;
            Ok(Filter::builder()
                .name(name)
                .set_values(Some(values.split(',').map(str::to_owned).collect()))
                .build())
        })
        .collect()
}

fn parse_tags(value: &str) -> Result<Vec<Tag>> {
    let start = value.find("Tags=[").ok_or_else(contract)? + 6;
    let body = value
        .get(start..)
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(contract)?;
    body.split("},{")
        .map(|item| {
            let item = item.trim_matches(['{', '}']);
            let mut key = None;
            let mut value = None;
            for field in item.split(',') {
                if let Some(actual) = field.strip_prefix("Key=") {
                    key = Some(actual);
                } else if let Some(actual) = field.strip_prefix("Value=") {
                    value = Some(actual);
                }
            }
            Ok(Tag::builder()
                .key(key.ok_or_else(contract)?)
                .value(value.ok_or_else(contract)?)
                .build())
        })
        .collect()
}

fn tag_specifications(argv: &[String]) -> Result<Vec<TagSpecification>> {
    all_after(argv, "--tag-specifications")
        .into_iter()
        .map(|value| {
            let resource = value
                .strip_prefix("ResourceType=")
                .and_then(|value| value.split_once(','))
                .ok_or_else(contract)?;
            let resource_type = ResourceType::from(resource.0);
            Ok(TagSpecification::builder()
                .resource_type(resource_type)
                .set_tags(Some(parse_tags(value)?))
                .build())
        })
        .collect()
}

fn tag_json(tags: &[Tag]) -> Vec<Value> {
    tags.iter()
        .map(|tag| json!({"Key": tag.key(), "Value": tag.value()}))
        .collect()
}

fn permission_json(permission: &aws_sdk_ec2::types::IpPermission) -> Value {
    json!({
        "IpProtocol": permission.ip_protocol(),
        "FromPort": permission.from_port(),
        "ToPort": permission.to_port(),
        "IpRanges": permission.ip_ranges().iter().map(|range| json!({
            "CidrIp": range.cidr_ip(),
            "Description": range.description(),
        })).collect::<Vec<_>>(),
        "Ipv6Ranges": [],
        "PrefixListIds": [],
        "UserIdGroupPairs": [],
    })
}

fn parse_permissions(argv: &[String]) -> Result<Vec<IpPermission>> {
    let value: Value = serde_json::from_str(arg(argv, "--ip-permissions").ok_or_else(contract)?)?;
    value
        .as_array()
        .ok_or_else(contract)?
        .iter()
        .map(|permission| {
            let ranges = permission["IpRanges"]
                .as_array()
                .ok_or_else(contract)?
                .iter()
                .map(|range| {
                    Ok(IpRange::builder()
                        .cidr_ip(range["CidrIp"].as_str().ok_or_else(contract)?)
                        .description(range["Description"].as_str().ok_or_else(contract)?)
                        .build())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(IpPermission::builder()
                .ip_protocol(permission["IpProtocol"].as_str().ok_or_else(contract)?)
                .from_port(
                    i32::try_from(permission["FromPort"].as_i64().ok_or_else(contract)?)
                        .map_err(|_| contract())?,
                )
                .to_port(
                    i32::try_from(permission["ToPort"].as_i64().ok_or_else(contract)?)
                        .map_err(|_| contract())?,
                )
                .set_ip_ranges(Some(ranges))
                .build())
        })
        .collect()
}

async fn describe_images(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_images()
        .set_owners(Some(
            all_after(argv, "--owners")
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ))
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"Images": output.images().iter().map(|image| json!({
        "ImageId": image.image_id(),
        "Name": image.name(),
        "CreationDate": image.creation_date(),
        "OwnerId": image.owner_id(),
        "Architecture": image.architecture().map(aws_sdk_ec2::types::ArchitectureValues::as_str),
        "RootDeviceType": image.root_device_type().map(aws_sdk_ec2::types::DeviceType::as_str),
        "VirtualizationType": image.virtualization_type().map(aws_sdk_ec2::types::VirtualizationType::as_str),
    })).collect::<Vec<_>>() }))
}

async fn import_key_pair(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let path = arg(argv, "--public-key-material")
        .and_then(|value| value.strip_prefix("fileb://"))
        .ok_or_else(contract)?;
    let material = std::fs::read(Path::new(path))
        .map_err(|_| ReleaseError::Deployment("SSH public key could not be read".into()))?;
    let output = client
        .import_key_pair()
        .key_name(arg(argv, "--key-name").ok_or_else(contract)?)
        .public_key_material(aws_sdk_ec2::primitives::Blob::new(material))
        .set_tag_specifications(Some(tag_specifications(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"KeyName": output.key_name(), "KeyFingerprint": output.key_fingerprint()}))
}

async fn describe_key_pairs(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_key_pairs()
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(
        json!({"KeyPairs": output.key_pairs().iter().map(|pair| json!({
        "KeyName": pair.key_name(),
        "KeyFingerprint": pair.key_fingerprint(),
        "Tags": tag_json(pair.tags()),
    })).collect::<Vec<_>>() }),
    )
}

async fn describe_vpcs(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_vpcs()
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"Vpcs": output.vpcs().iter().map(|vpc| json!({
        "VpcId": vpc.vpc_id(),
        "IsDefault": vpc.is_default(),
        "Tags": tag_json(vpc.tags()),
    })).collect::<Vec<_>>() }))
}

async fn create_security_group(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .create_security_group()
        .group_name(arg(argv, "--group-name").ok_or_else(contract)?)
        .description(arg(argv, "--description").ok_or_else(contract)?)
        .vpc_id(arg(argv, "--vpc-id").ok_or_else(contract)?)
        .set_tag_specifications(Some(tag_specifications(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"GroupId": output.group_id()}))
}

async fn change_security_group_ingress(
    client: &Ec2Client,
    argv: &[String],
    authorize: bool,
) -> Result<String> {
    let group_id = arg(argv, "--group-id").ok_or_else(contract)?;
    let permissions = parse_permissions(argv)?;
    if authorize {
        client
            .authorize_security_group_ingress()
            .group_id(group_id)
            .set_ip_permissions(Some(permissions))
            .send()
            .await
            .map_err(|_| contract())?;
    } else {
        client
            .revoke_security_group_ingress()
            .group_id(group_id)
            .set_ip_permissions(Some(permissions))
            .send()
            .await
            .map_err(|_| contract())?;
    }
    Ok(String::new())
}

async fn describe_security_groups(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let mut request = client.describe_security_groups();
    let group_ids = all_after(argv, "--group-ids");
    if !group_ids.is_empty() {
        request = request.set_group_ids(Some(group_ids.into_iter().map(str::to_owned).collect()));
    }
    let parsed_filters = filters(argv)?;
    if !parsed_filters.is_empty() {
        request = request.set_filters(Some(parsed_filters));
    }
    let output = request.send().await.map_err(|_| contract())?;
    json_text(
        json!({"SecurityGroups": output.security_groups().iter().map(|group| json!({
        "GroupId": group.group_id(),
        "GroupName": group.group_name(),
        "VpcId": group.vpc_id(),
        "IpPermissions": group.ip_permissions().iter().map(permission_json).collect::<Vec<_>>(),
        "Tags": tag_json(group.tags()),
    })).collect::<Vec<_>>() }),
    )
}

async fn run_instances(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let block = arg(argv, "--block-device-mappings").ok_or_else(contract)?;
    let size = block
        .split("VolumeSize=")
        .nth(1)
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.parse::<i32>().ok())
        .ok_or_else(contract)?;
    let user_data_path = arg(argv, "--user-data")
        .and_then(|value| value.strip_prefix("fileb://"))
        .ok_or_else(contract)?;
    let user_data = STANDARD.encode(
        std::fs::read(user_data_path)
            .map_err(|_| ReleaseError::Deployment("cloud-init input could not be read".into()))?,
    );
    let instance_type = InstanceType::from(arg(argv, "--instance-type").ok_or_else(contract)?);
    let output = client
        .run_instances()
        .client_token(arg(argv, "--client-token").ok_or_else(contract)?)
        .image_id(arg(argv, "--image-id").ok_or_else(contract)?)
        .instance_type(instance_type)
        .key_name(arg(argv, "--key-name").ok_or_else(contract)?)
        .set_security_group_ids(Some(
            all_after(argv, "--security-group-ids")
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ))
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDevice::builder()
                        .volume_type(VolumeType::Gp3)
                        .volume_size(size)
                        .delete_on_termination(false)
                        .encrypted(true)
                        .build(),
                )
                .build(),
        )
        .metadata_options(
            InstanceMetadataOptionsRequest::builder()
                .http_tokens(aws_sdk_ec2::types::HttpTokensState::Required)
                .http_endpoint(InstanceMetadataEndpointState::Enabled)
                .instance_metadata_tags(InstanceMetadataTagsState::Disabled)
                .build(),
        )
        .user_data(user_data)
        .set_tag_specifications(Some(tag_specifications(argv)?))
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .map_err(|error| {
            let code = error
                .as_service_error()
                .and_then(ProvideErrorMetadata::code)
                .unwrap_or("unknown");
            ReleaseError::Deployment(format!("AWS EC2 RunInstances failed ({code})"))
        })?;
    json_text(
        json!({"Instances": output.instances().iter().map(instance_json).collect::<Vec<_>>() }),
    )
}

fn instance_json(instance: &aws_sdk_ec2::types::Instance) -> Value {
    json!({
        "InstanceId": instance.instance_id(),
        "ImageId": instance.image_id(),
        "InstanceType": instance.instance_type().map(aws_sdk_ec2::types::InstanceType::as_str),
        "KeyName": instance.key_name(),
        "ClientToken": instance.client_token(),
        "Architecture": instance.architecture().map(aws_sdk_ec2::types::ArchitectureValues::as_str),
        "PrivateIpAddress": instance.private_ip_address(),
        "State": {"Name": instance.state().and_then(|state| state.name()).map(aws_sdk_ec2::types::InstanceStateName::as_str)},
        "MetadataOptions": {
            "HttpTokens": instance.metadata_options().and_then(|options| options.http_tokens()).map(aws_sdk_ec2::types::HttpTokensState::as_str),
            "HttpEndpoint": instance.metadata_options().and_then(|options| options.http_endpoint()).map(aws_sdk_ec2::types::InstanceMetadataEndpointState::as_str),
        },
        "SecurityGroups": instance.security_groups().iter().map(|group| json!({
            "GroupId": group.group_id(),
            "GroupName": group.group_name(),
        })).collect::<Vec<_>>(),
        "BlockDeviceMappings": instance.block_device_mappings().iter().map(|mapping| json!({
            "DeviceName": mapping.device_name(),
            "Ebs": {
                "VolumeId": mapping.ebs().and_then(|ebs| ebs.volume_id()),
                "DeleteOnTermination": mapping.ebs().and_then(aws_sdk_ec2::types::EbsInstanceBlockDevice::delete_on_termination),
            }
        })).collect::<Vec<_>>(),
        "Tags": tag_json(instance.tags()),
    })
}

async fn describe_instances(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_instances()
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(
        json!({"Reservations": output.reservations().iter().map(|reservation| json!({
        "Instances": reservation.instances().iter().map(instance_json).collect::<Vec<_>>()
    })).collect::<Vec<_>>() }),
    )
}

async fn allocate_address(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .allocate_address()
        .domain(aws_sdk_ec2::types::DomainType::Vpc)
        .set_tag_specifications(Some(tag_specifications(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"AllocationId": output.allocation_id(), "PublicIp": output.public_ip()}))
}

async fn associate_address(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .associate_address()
        .allocation_id(arg(argv, "--allocation-id").ok_or_else(contract)?)
        .instance_id(arg(argv, "--instance-id").ok_or_else(contract)?)
        .allow_reassociation(false)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"AssociationId": output.association_id()}))
}

fn address_json(address: &aws_sdk_ec2::types::Address) -> Value {
    json!({
        "AllocationId": address.allocation_id(),
        "AssociationId": address.association_id(),
        "PublicIp": address.public_ip(),
        "InstanceId": address.instance_id(),
        "Tags": tag_json(address.tags()),
    })
}

async fn describe_addresses(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_addresses()
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(
        json!({"Addresses": output.addresses().iter().map(address_json).collect::<Vec<_>>() }),
    )
}

async fn get_console_output(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .get_console_output()
        .instance_id(arg(argv, "--instance-id").ok_or_else(contract)?)
        .latest(true)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"Output": output.output()}))
}

async fn create_tags(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let tags = all_after(argv, "--tags")
        .into_iter()
        .map(|value| {
            let (key, value) = value
                .strip_prefix("Key=")
                .and_then(|value| value.split_once(",Value="))
                .ok_or_else(contract)?;
            Ok(Tag::builder().key(key).value(value).build())
        })
        .collect::<Result<Vec<_>>>()?;
    client
        .create_tags()
        .set_resources(Some(
            all_after(argv, "--resources")
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ))
        .set_tags(Some(tags))
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn terminate_instances(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .terminate_instances()
        .set_instance_ids(Some(
            all_after(argv, "--instance-ids")
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ))
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn disassociate_address(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .disassociate_address()
        .association_id(arg(argv, "--association-id").ok_or_else(contract)?)
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn release_address(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .release_address()
        .allocation_id(arg(argv, "--allocation-id").ok_or_else(contract)?)
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn delete_security_group(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .delete_security_group()
        .group_id(arg(argv, "--group-id").ok_or_else(contract)?)
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn delete_key_pair(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .delete_key_pair()
        .key_name(arg(argv, "--key-name").ok_or_else(contract)?)
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

fn volume_json(volume: &aws_sdk_ec2::types::Volume) -> Value {
    json!({
        "VolumeId": volume.volume_id(),
        "Size": volume.size(),
        "Encrypted": volume.encrypted(),
        "VolumeType": volume.volume_type().map(aws_sdk_ec2::types::VolumeType::as_str),
        "State": volume.state().map(aws_sdk_ec2::types::VolumeState::as_str),
        "Tags": tag_json(volume.tags()),
    })
}

async fn describe_volumes(client: &Ec2Client, argv: &[String]) -> Result<String> {
    let output = client
        .describe_volumes()
        .set_filters(Some(filters(argv)?))
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({"Volumes": output.volumes().iter().map(volume_json).collect::<Vec<_>>() }))
}

async fn delete_volume(client: &Ec2Client, argv: &[String]) -> Result<String> {
    client
        .delete_volume()
        .volume_id(arg(argv, "--volume-id").ok_or_else(contract)?)
        .send()
        .await
        .map_err(|_| contract())?;
    Ok(String::new())
}

async fn wait_ec2(client: &Ec2Client, argv: &[String], timeout: Duration) -> Result<String> {
    let waiter = argv.get(2).map(String::as_str).ok_or_else(contract)?;
    let instance_ids = all_after(argv, "--instance-ids")
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let started = tokio::time::Instant::now();
    loop {
        let ready = if waiter == "instance-status-ok" {
            let output = client
                .describe_instance_status()
                .set_instance_ids(Some(instance_ids.clone()))
                .include_all_instances(true)
                .send()
                .await
                .map_err(|_| contract())?;
            output.instance_statuses().len() == instance_ids.len()
                && output.instance_statuses().iter().all(|status| {
                    status
                        .instance_state()
                        .and_then(|state| state.name())
                        .is_some_and(|state| state.as_str() == "running")
                        && status
                            .instance_status()
                            .and_then(|summary| summary.status())
                            .is_some_and(|status| status.as_str() == "ok")
                        && status
                            .system_status()
                            .and_then(|summary| summary.status())
                            .is_some_and(|status| status.as_str() == "ok")
                })
        } else {
            let output = client
                .describe_instances()
                .set_instance_ids(Some(instance_ids.clone()))
                .send()
                .await
                .map_err(|_| contract())?;
            let expected = match waiter {
                "instance-running" => "running",
                "instance-terminated" => "terminated",
                _ => return Err(contract()),
            };
            output
                .reservations()
                .iter()
                .flat_map(aws_sdk_ec2::types::Reservation::instances)
                .all(|instance| {
                    instance
                        .state()
                        .and_then(|state| state.name())
                        .is_some_and(|state| state.as_str() == expected)
                })
        };
        if ready {
            return Ok(String::new());
        }
        if started.elapsed() >= timeout {
            return Err(contract());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn list_hosted_zones(client: &Route53Client) -> Result<String> {
    let mut marker = None;
    let mut zones = Vec::new();
    loop {
        let output = client
            .list_hosted_zones()
            .set_marker(marker.clone())
            .send()
            .await
            .map_err(|_| contract())?;
        zones.extend(output.hosted_zones().iter().map(|zone| {
            json!({
                "Id": zone.id(),
                "Name": zone.name(),
                "Config": {"PrivateZone": zone.config().is_some_and(aws_sdk_route53::types::HostedZoneConfig::private_zone)},
            })
        }));
        if !output.is_truncated() {
            break;
        }
        marker = output.next_marker().map(str::to_owned);
    }
    json_text(json!({"HostedZones": zones}))
}

fn record_json(record: &aws_sdk_route53::types::ResourceRecordSet) -> Value {
    json!({
        "Name": record.name(),
        "Type": record.r#type().as_str(),
        "TTL": record.ttl(),
        "ResourceRecords": record.resource_records().iter().map(|value| json!({
            "Value": value.value(),
        })).collect::<Vec<_>>(),
    })
}

async fn list_resource_record_sets(client: &Route53Client, argv: &[String]) -> Result<String> {
    let output = client
        .list_resource_record_sets()
        .hosted_zone_id(arg(argv, "--hosted-zone-id").ok_or_else(contract)?)
        .start_record_name(arg(argv, "--start-record-name").ok_or_else(contract)?)
        .start_record_type(RrType::A)
        .max_items(1)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(
        json!({"ResourceRecordSets": output.resource_record_sets().iter().map(record_json).collect::<Vec<_>>() }),
    )
}

fn parse_change_batch(argv: &[String]) -> Result<ChangeBatch> {
    let value: Value = serde_json::from_str(arg(argv, "--change-batch").ok_or_else(contract)?)?;
    let changes = value["Changes"]
        .as_array()
        .ok_or_else(contract)?
        .iter()
        .map(|change| {
            let record = &change["ResourceRecordSet"];
            let values = record["ResourceRecords"]
                .as_array()
                .ok_or_else(contract)?
                .iter()
                .map(|value| {
                    ResourceRecord::builder()
                        .value(value["Value"].as_str().ok_or_else(contract)?)
                        .build()
                        .map_err(|_| contract())
                })
                .collect::<Result<Vec<_>>>()?;
            let set = ResourceRecordSet::builder()
                .name(record["Name"].as_str().ok_or_else(contract)?)
                .r#type(RrType::A)
                .ttl(record["TTL"].as_i64().ok_or_else(contract)?)
                .set_resource_records(Some(values))
                .build()
                .map_err(|_| contract())?;
            let action = match change["Action"].as_str().ok_or_else(contract)? {
                "CREATE" => ChangeAction::Create,
                "DELETE" => ChangeAction::Delete,
                _ => return Err(contract()),
            };
            Change::builder()
                .action(action)
                .resource_record_set(set)
                .build()
                .map_err(|_| contract())
        })
        .collect::<Result<Vec<_>>>()?;
    ChangeBatch::builder()
        .set_comment(value["Comment"].as_str().map(str::to_owned))
        .set_changes(Some(changes))
        .build()
        .map_err(|_| contract())
}

async fn change_resource_record_sets(client: &Route53Client, argv: &[String]) -> Result<String> {
    let output = client
        .change_resource_record_sets()
        .hosted_zone_id(arg(argv, "--hosted-zone-id").ok_or_else(contract)?)
        .change_batch(parse_change_batch(argv)?)
        .send()
        .await
        .map_err(|_| contract())?;
    let info = output.change_info().ok_or_else(contract)?;
    json_text(json!({"ChangeInfo": {"Id": info.id(), "Status": info.status().as_str()}}))
}

async fn wait_route53(
    client: &Route53Client,
    argv: &[String],
    timeout: Duration,
) -> Result<String> {
    let id = arg(argv, "--id").ok_or_else(contract)?;
    let started = tokio::time::Instant::now();
    loop {
        let output = client
            .get_change()
            .id(id)
            .send()
            .await
            .map_err(|_| contract())?;
        if output
            .change_info()
            .is_some_and(|info| info.status().as_str() == "INSYNC")
        {
            return Ok(String::new());
        }
        if started.elapsed() >= timeout {
            return Err(contract());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn lightsail_regions(client: &LightsailClient) -> Result<String> {
    let output = client
        .get_regions()
        .include_availability_zones(true)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({
        "regions": output.regions().iter().map(|region| json!({
            "name": region.name().map(aws_sdk_lightsail::types::RegionName::as_str),
            "displayName": region.display_name(),
            "description": region.description(),
            "availabilityZones": region.availability_zones().iter().map(|zone| json!({
                "zoneName": zone.zone_name(),
                "state": zone.state(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()
    }))
}

async fn lightsail_blueprints(client: &LightsailClient) -> Result<String> {
    let output = client
        .get_blueprints()
        .include_inactive(false)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({
        "blueprints": output.blueprints().iter().map(|blueprint| json!({
            "blueprintId": blueprint.blueprint_id(),
            "name": blueprint.name(),
            "group": blueprint.group(),
            "type": blueprint.r#type().map(aws_sdk_lightsail::types::BlueprintType::as_str),
            "version": blueprint.version(),
            "versionCode": blueprint.version_code(),
            "productUrl": blueprint.product_url(),
            "licenseUrl": blueprint.license_url(),
            "platform": blueprint.platform().map(aws_sdk_lightsail::types::InstancePlatform::as_str),
            "minPower": blueprint.min_power(),
            "isActive": blueprint.is_active(),
        })).collect::<Vec<_>>()
    }))
}

async fn lightsail_bundles(client: &LightsailClient) -> Result<String> {
    let output = client
        .get_bundles()
        .include_inactive(false)
        .send()
        .await
        .map_err(|_| contract())?;
    json_text(json!({
        "bundles": output.bundles().iter().map(|bundle| json!({
            "bundleId": bundle.bundle_id(),
            "name": bundle.name(),
            "instanceType": bundle.instance_type(),
            "price": bundle.price(),
            "cpuCount": bundle.cpu_count(),
            "ramSizeInGb": bundle.ram_size_in_gb(),
            "diskSizeInGb": bundle.disk_size_in_gb(),
            "transferPerMonthInGb": bundle.transfer_per_month_in_gb(),
            "power": bundle.power(),
            "isActive": bundle.is_active(),
            "supportedPlatforms": bundle.supported_platforms().iter()
                .map(aws_sdk_lightsail::types::InstancePlatform::as_str).collect::<Vec<_>>(),
            "supportedAppCategories": bundle.supported_app_categories().iter()
                .map(aws_sdk_lightsail::types::AppCategory::as_str).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()
    }))
}

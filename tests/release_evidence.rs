#![cfg(unix)]

use std::fs;

use dirextalk_vnext_deployer::release_evidence::ReleaseEvidenceV1;

#[test]
fn canonical_release_evidence_fixture_is_accepted_without_file_io() {
    let bytes = fs::read("tests/fixtures/release-evidence-v1-canonical.json").expect("fixture");
    ReleaseEvidenceV1::from_bytes(&bytes).expect("canonical release evidence");
    ReleaseEvidenceV1::load(std::path::Path::new(
        "tests/fixtures/release-evidence-v1-canonical.json",
    ))
    .expect("local evidence files");
}

#[test]
fn pretty_or_unknown_release_evidence_is_rejected() {
    let bytes = fs::read("tests/fixtures/release-evidence-v1-canonical.json").expect("fixture");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture json");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty json");
    assert!(ReleaseEvidenceV1::from_bytes(&pretty).is_err());
    let mut unknown = value;
    unknown["unknown"] = serde_json::Value::Bool(true);
    let unknown = serde_json::to_vec(&unknown).expect("unknown json");
    assert!(ReleaseEvidenceV1::from_bytes(&unknown).is_err());
}

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=DTX_RELEASE_VERSION");
    println!("cargo:rerun-if-env-changed=DTX_SOURCE_COMMIT");
    let version = env::var("DTX_RELEASE_VERSION")
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").expect("Cargo package version"));
    let commit = env::var("DTX_SOURCE_COMMIT").unwrap_or_else(|_| "unresolved".to_owned());
    assert!(
        valid_value(&version, 128),
        "DTX_RELEASE_VERSION must be a bounded graphic value"
    );
    assert!(
        commit == "unresolved"
            || matches!(commit.len(), 40 | 64)
                && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "DTX_SOURCE_COMMIT must be a full Git object id"
    );
    println!("cargo:rustc-env=DTX_RELEASE_VERSION={version}");
    println!("cargo:rustc-env=DTX_SOURCE_COMMIT={commit}");
}

fn valid_value(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

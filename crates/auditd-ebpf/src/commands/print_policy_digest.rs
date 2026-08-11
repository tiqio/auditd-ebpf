use crate::policy::digest::{default_policy, policy_digest};

pub fn run(value_only: bool) -> Result<(), String> {
    let digest = policy_digest(&default_policy()).map_err(|error| error.to_string())?;
    if value_only {
        println!("{digest}");
    } else {
        println!("policy_digest_version=1 policy_digest={digest}");
    }
    Ok(())
}

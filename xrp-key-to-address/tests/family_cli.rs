use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};

fn encoded_seed(entropy: &[u8]) -> String {
    let mut payload = vec![0x21];
    payload.extend_from_slice(entropy);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

fn run(seed: &str, args: &[&str]) -> (String, String) {
    // Synthetic data goes through stdin, covering the existing CLI input path.
    let mut child = Command::new(env!("CARGO_BIN_EXE_xrp_key_to_address"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{seed}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn family_cli_uses_standard_addresses_and_legacy_is_explicit() {
    for row in include_str!("../src/family_vectors.csv").lines() {
        let fields: Vec<_> = row.split(',').collect();
        if fields[1] != "0" {
            continue;
        }
        let seed = encoded_seed(&hex::decode(fields[0]).unwrap());
        let (family, notice) = run(&seed, &["--mode", "family"]);
        assert!(family.lines().any(|line| line == fields[2]));
        assert!(notice.contains("legacy-family"));
        let (legacy, warning) = run(&seed, &["--mode", "legacy-family"]);
        assert!(legacy.lines().any(|line| line == fields[3]));
        assert!(warning.contains("nonstandard"));
        for (mode, expected) in [("family", fields[2]), ("legacy-family", fields[3])] {
            assert!(run(&seed, &["--mode", mode, "--both"]).0.contains(expected));
        }
        assert_eq!(run(&seed, &[]), run(&seed, &["--mode", "root"]));
    }
}

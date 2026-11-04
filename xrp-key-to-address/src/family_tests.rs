use super::*;

// Synthetic entropy only. Frozen address expectations were calculated from the
// XRPL 41-byte formula with Python hashlib + coincurve. Account-zero public and
// private keys were also checked against xrpl-py 5.2.0 (ECPy backend).
// All 12 standard addresses match official ripple-keypairs 3.1.0; account-zero
// historical addresses match the pre-fix executable. No real wallet data is used.
// Columns: entropy hex, account index, standard address, historical address.
const VECTORS: &str = include_str!("family_vectors.csv");

#[test]
fn family_and_legacy_match_independent_synthetic_vectors() {
    for row in VECTORS.lines() {
        let fields: Vec<_> = row.split(',').collect();
        let seed = hex::decode(fields[0]).unwrap();
        let index = fields[1].parse().unwrap();
        let standard = derive_secp256k1_family_account_key(&seed, index).unwrap();
        let legacy = derive_secp256k1_family_account_key_with_format(&seed, index, true).unwrap();
        assert_eq!(
            secp256k1_address_from_private_key(&standard).unwrap(),
            fields[2]
        );
        assert_eq!(
            secp256k1_address_from_private_key(&legacy).unwrap(),
            fields[3]
        );
        assert_ne!(standard, legacy);
    }
}

#[test]
fn cli_mode_names_and_default_remain_compatible() {
    assert_eq!(
        Args::try_parse_from(["xrp_key_to_address"]).unwrap().mode,
        DerivationMode::Root
    );
    for (name, mode) in [
        ("root", DerivationMode::Root),
        ("family", DerivationMode::Family),
        ("legacy-family", DerivationMode::LegacyFamily),
        ("xrpl", DerivationMode::Xrpl),
        ("all", DerivationMode::All),
    ] {
        assert_eq!(
            Args::try_parse_from(["xrp_key_to_address", "--mode", name])
                .unwrap()
                .mode,
            mode
        );
    }
}

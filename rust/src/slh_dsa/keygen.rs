//! SLH-DSA Key Generation — FIPS 205 Algorithm 17 (slh_keygen)
//!
//! Generates a public key (PK) and secret key (SK) for SLH-DSA.
//!
//! SK = (SK.seed || SK.prf || PK.seed || PK.root)
//! PK = (PK.seed || PK.root)
//!
//! PK.root is the root of the top XMSS tree (layer d-1).

use crate::slh_dsa::address::Adrs;
use crate::slh_dsa::params::SlhDsaParams;
use crate::slh_dsa::xmss;
use crate::primitives::random::random_bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLH-DSA key pair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaKeyPair {
    /// Public key: PK.seed || PK.root (2n bytes)
    pub pk: Vec<u8>,
    /// Secret key: SK.seed || SK.prf || PK.seed || PK.root (4n bytes)
    pub sk: Vec<u8>,
}

/// FIPS 205 Algorithm 17: SLH-DSA Key Generation.
///
/// If a seed is provided (3n bytes), it is used deterministically:
///   seed = SK.seed || SK.prf || PK.seed
/// Otherwise, 3n random bytes are generated.
pub fn slh_dsa_keygen(
    seed: Option<&[u8]>,
    params: &SlhDsaParams,
) -> Result<SlhDsaKeyPair, String> {
    let n = params.n;

    // Generate or accept 3n bytes of key material
    let mut key_material = vec![0u8; 3 * n];
    match seed {
        Some(s) if s.len() >= 3 * n => key_material.copy_from_slice(&s[..3 * n]),
        Some(s) => {
            return Err(format!(
                "Seed must be at least {} bytes, got {}",
                3 * n,
                s.len()
            ));
        }
        None => {
            random_bytes(&mut key_material)
                .map_err(|_| "Failed to generate random bytes".to_string())?;
        }
    }

    let sk_seed = &key_material[..n];
    let sk_prf = &key_material[n..2 * n];
    let pk_seed = &key_material[2 * n..3 * n];

    // Compute PK.root = root of the top XMSS tree (layer d-1, tree 0)
    let mut adrs = Adrs::new();
    adrs.set_layer_address((params.d - 1) as u32);
    adrs.set_tree_address(0);

    // The root is the node at height hp, index 0
    let pk_root = xmss::xmss_node(sk_seed, pk_seed, 0, params.hp as u32, &mut adrs, params);

    // PK = PK.seed || PK.root
    let mut pk = Vec::with_capacity(2 * n);
    pk.extend_from_slice(pk_seed);
    pk.extend_from_slice(&pk_root);

    // SK = SK.seed || SK.prf || PK.seed || PK.root
    let mut sk = Vec::with_capacity(4 * n);
    sk.extend_from_slice(sk_seed);
    sk.extend_from_slice(sk_prf);
    sk.extend_from_slice(pk_seed);
    sk.extend_from_slice(&pk_root);

    // Zeroize intermediate key material
    key_material.zeroize();

    Ok(SlhDsaKeyPair { pk, sk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::*;

    #[test]
    fn test_keygen_shake_128f_sizes() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        assert_eq!(kp.pk.len(), SLH_DSA_SHAKE_128F.pk_bytes);
        assert_eq!(kp.sk.len(), SLH_DSA_SHAKE_128F.sk_bytes);
    }

    #[test]
    fn test_keygen_deterministic() {
        let seed = vec![42u8; 3 * SLH_DSA_SHAKE_128F.n];
        let kp1 = slh_dsa_keygen(Some(&seed), &SLH_DSA_SHAKE_128F).unwrap();
        let kp2 = slh_dsa_keygen(Some(&seed), &SLH_DSA_SHAKE_128F).unwrap();
        assert_eq!(kp1.pk, kp2.pk);
        assert_eq!(kp1.sk, kp2.sk);
    }

    #[test]
    fn test_keygen_pk_embedded_in_sk() {
        let kp = slh_dsa_keygen(None, &SLH_DSA_SHAKE_128F).unwrap();
        let n = SLH_DSA_SHAKE_128F.n;
        // SK = SK.seed || SK.prf || PK.seed || PK.root
        // PK = PK.seed || PK.root
        assert_eq!(&kp.sk[2 * n..], &kp.pk[..]);
    }

    #[test]
    fn test_keygen_invalid_seed() {
        let short_seed = vec![0u8; 10];
        let result = slh_dsa_keygen(Some(&short_seed), &SLH_DSA_SHAKE_128F);
        assert!(result.is_err());
    }
}

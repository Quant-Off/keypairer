use pqcrypto::kem::{
    hqc128, hqc192, hqc256, mceliece348864, mceliece348864f, mceliece460896, mceliece460896f,
    mceliece6688128, mceliece6688128f, mceliece6960119, mceliece6960119f, mceliece8192128,
    mceliece8192128f, mlkem512, mlkem768, mlkem1024,
};
use pqcrypto::sign::{
    falcon512, falcon1024, falconpadded512, falconpadded1024, mldsa44, mldsa65, mldsa87,
    sphincssha2128fsimple as sphincs_sha2_128f_simple,
    sphincssha2128ssimple as sphincs_sha2_128s_simple,
    sphincssha2192fsimple as sphincs_sha2_192f_simple,
    sphincssha2192ssimple as sphincs_sha2_192s_simple,
    sphincssha2256fsimple as sphincs_sha2_256f_simple,
    sphincssha2256ssimple as sphincs_sha2_256s_simple,
    sphincsshake128fsimple as sphincs_shake_128f_simple,
    sphincsshake128ssimple as sphincs_shake_128s_simple,
    sphincsshake192fsimple as sphincs_shake_192f_simple,
    sphincsshake192ssimple as sphincs_shake_192s_simple,
    sphincsshake256fsimple as sphincs_shake_256f_simple,
    sphincsshake256ssimple as sphincs_shake_256s_simple,
};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    MLKEM,
    HQC,
    McEliece,
    FALCON,
    MLDSA,
    SPHINCSPlus,

    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Variant {
    // MlKem
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    // Hqc
    HQC128,
    HQC192,
    HQC256,
    // McEliece
    McEliece348864,
    McEliece348864f,
    McEliece460896,
    McEliece460896f,
    McEliece6688128,
    McEliece6688128f,
    McEliece6960119,
    McEliece6960119f,
    McEliece8192128,
    McEliece8192128f,
    // Falcon
    FALCONNoPad512,
    FALCONNoPad1024,
    FALCONPadded512,
    FALCONPadded1024,
    // MlDsa
    MLDSA44,
    MLDSA65,
    MLDSA87,
    // SphincsPlus (간략히, 전체 추가 가능)
    SPHINCSsha2128fsimple,
    SPHINCSsha2128ssimple,
    SPHINCSsha2192fsimple,
    SPHINCSsha2192ssimple,
    SPHINCSsha2256fsimple,
    SPHINCSsha2256ssimple,
    SPHINCSshake128fsimple,
    SPHINCSshake128ssimple,
    SPHINCSshake192fsimple,
    SPHINCSshake192ssimple,
    SPHINCSshake256fsimple,
    SPHINCSshake256ssimple,

    Unknown,
}

pub type KeyGenResult = Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>>;

pub fn generate_keys(algorithm: Algorithm, variant: Variant) -> KeyGenResult {
    // 알고리즘별 HashMap으로 키 생성 클로저 매핑 (중복 제거)
    let kem_generators: HashMap<Variant, Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>> = {
        let mut map = HashMap::new();
        map.insert(
            Variant::MLKEM512,
            Box::new(|| {
                let (pk, sk) = mlkem512::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::MLKEM768,
            Box::new(|| {
                let (pk, sk) = mlkem768::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::MLKEM1024,
            Box::new(|| {
                let (pk, sk) = mlkem1024::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );

        map.insert(
            Variant::HQC128,
            Box::new(|| {
                let (pk, sk) = hqc128::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::HQC192,
            Box::new(|| {
                let (pk, sk) = hqc192::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::HQC256,
            Box::new(|| {
                let (pk, sk) = hqc256::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );

        map.insert(
            Variant::McEliece348864,
            Box::new(|| {
                let (pk, sk) = mceliece348864::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece348864f,
            Box::new(|| {
                let (pk, sk) = mceliece348864f::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece460896,
            Box::new(|| {
                let (pk, sk) = mceliece460896::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece460896f,
            Box::new(|| {
                let (pk, sk) = mceliece460896f::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece6688128,
            Box::new(|| {
                let (pk, sk) = mceliece6688128::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece6688128f,
            Box::new(|| {
                let (pk, sk) = mceliece6688128f::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece6960119,
            Box::new(|| {
                let (pk, sk) = mceliece6960119::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece6960119f,
            Box::new(|| {
                let (pk, sk) = mceliece6960119f::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece8192128,
            Box::new(|| {
                let (pk, sk) = mceliece8192128::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::McEliece8192128f,
            Box::new(|| {
                let (pk, sk) = mceliece8192128f::keypair();
                (
                    KemPublicKey::as_bytes(&pk).to_vec(),
                    KemSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map
    };

    let sign_generators: HashMap<Variant, Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>> = {
        let mut map = HashMap::new();
        map.insert(
            Variant::FALCONNoPad512,
            Box::new(|| {
                let (pk, sk) = falcon512::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::FALCONNoPad1024,
            Box::new(|| {
                let (pk, sk) = falcon1024::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::FALCONPadded512,
            Box::new(|| {
                let (pk, sk) = falconpadded512::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::FALCONPadded1024,
            Box::new(|| {
                let (pk, sk) = falconpadded1024::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );

        map.insert(
            Variant::MLDSA44,
            Box::new(|| {
                let (pk, sk) = mldsa44::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::MLDSA65,
            Box::new(|| {
                let (pk, sk) = mldsa65::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::MLDSA87,
            Box::new(|| {
                let (pk, sk) = mldsa87::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );

        map.insert(
            Variant::SPHINCSsha2128fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_128f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSsha2128ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_128s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSsha2192fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_192f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSsha2192ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_192s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSsha2256fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_256f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSsha2256ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_sha2_256s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake128fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_128f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake128ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_128s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake192fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_192f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake192ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_192s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake256fsimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_256f_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map.insert(
            Variant::SPHINCSshake256ssimple,
            Box::new(|| {
                let (pk, sk) = sphincs_shake_256s_simple::keypair();
                (
                    SignPublicKey::as_bytes(&pk).to_vec(),
                    SignSecretKey::as_bytes(&sk).to_vec(),
                )
            }) as Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
        );
        map
    };

    match algorithm {
        Algorithm::MLKEM | Algorithm::HQC | Algorithm::McEliece => {
            kem_generators.get(&variant).map_or_else(
                || {
                    Err(format!(
                        "Invalid variant {:?} for KEM algorithm {:?}",
                        variant, algorithm
                    )
                    .into())
                },
                |keygen| Ok(keygen()),
            )
        }
        Algorithm::FALCON | Algorithm::MLDSA | Algorithm::SPHINCSPlus => {
            sign_generators.get(&variant).map_or_else(
                || {
                    Err(format!(
                        "Invalid variant {:?} for Sign algorithm {:?}",
                        variant, algorithm
                    )
                    .into())
                },
                |keygen| Ok(keygen()),
            )
        }
        _ => Err(format!("Invalid algorithm {:?}", algorithm).into()),
    }
}

pub fn parse_algorithm(input: &str) -> Option<Algorithm> {
    match input.to_lowercase().as_str() {
        "mlkem" | "ml-kem" => Some(Algorithm::MLKEM),
        "hqc" => Some(Algorithm::HQC),
        "mce" | "mceliece" => Some(Algorithm::McEliece),
        "falcon" => Some(Algorithm::FALCON),
        "mldsa" | "ml-dsa" => Some(Algorithm::MLDSA),
        "sph" | "sphincs" | "sphincs+" => Some(Algorithm::SPHINCSPlus),
        _ => Some(Algorithm::Unknown),
    }
}

// 비슷하게 Variant 파싱 함수 추가

pub fn minimal_variant_for_algorithm(algo: Algorithm) -> Variant {
    match algo {
        Algorithm::MLKEM => Variant::MLKEM512,
        Algorithm::HQC => Variant::HQC128,
        Algorithm::McEliece => Variant::McEliece348864,
        Algorithm::FALCON => Variant::FALCONNoPad512,
        Algorithm::MLDSA => Variant::MLDSA44,
        Algorithm::SPHINCSPlus => Variant::SPHINCSsha2128fsimple,
        _ => Variant::Unknown,
    }
}

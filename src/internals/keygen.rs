use pqcrypto::kem::hqc128::keypair as hqc128_keypair;
use pqcrypto::kem::hqc192::keypair as hqc192_keypair;
use pqcrypto::kem::hqc256::keypair as hqc256_keypair;
use pqcrypto::kem::mceliece348864::keypair as mceliece348864_keypair;
use pqcrypto::kem::mceliece348864f::keypair as mceliece348864f_keypair;
use pqcrypto::kem::mceliece460896::keypair as mceliece460896_keypair;
use pqcrypto::kem::mceliece460896f::keypair as mceliece460896f_keypair;
use pqcrypto::kem::mceliece6688128::keypair as mceliece6688128_keypair;
use pqcrypto::kem::mceliece6688128f::keypair as mceliece6688128f_keypair;
use pqcrypto::kem::mceliece6960119::keypair as mceliece6960119_keypair;
use pqcrypto::kem::mceliece6960119f::keypair as mceliece6960119f_keypair;
use pqcrypto::kem::mceliece8192128::keypair as mceliece8192128_keypair;
use pqcrypto::kem::mceliece8192128f::keypair as mceliece8192128f_keypair;
use pqcrypto::kem::mlkem512::keypair as mlkem512_keypair;
use pqcrypto::kem::mlkem768::keypair as mlkem768_keypair;
use pqcrypto::kem::mlkem1024::keypair as mlkem1024_keypair;
use pqcrypto::sign::falcon512::keypair as falcon512_keypair;
use pqcrypto::sign::falcon1024::keypair as falcon1024_keypair;
use pqcrypto::sign::falconpadded512::keypair as falconpadded512_keypair;
use pqcrypto::sign::falconpadded1024::keypair as falconpadded1024_keypair;
use pqcrypto::sign::mldsa44::keypair as mldsa44_keypair;
use pqcrypto::sign::mldsa65::keypair as mldsa65_keypair;
use pqcrypto::sign::mldsa87::keypair as mldsa87_keypair;
use pqcrypto::sign::sphincssha2128fsimple::keypair as sphincs_sha2_128f_simple_keypair;
use pqcrypto::sign::sphincssha2128ssimple::keypair as sphincs_sha2_128s_simple_keypair;
use pqcrypto::sign::sphincssha2192fsimple::keypair as sphincs_sha2_192f_simple_keypair;
use pqcrypto::sign::sphincssha2192ssimple::keypair as sphincs_sha2_192s_simple_keypair;
use pqcrypto::sign::sphincssha2256fsimple::keypair as sphincs_sha2_256f_simple_keypair;
use pqcrypto::sign::sphincssha2256ssimple::keypair as sphincs_sha2_256s_simple_keypair;
use pqcrypto::sign::sphincsshake128fsimple::keypair as sphincs_shake_128f_simple_keypair;
use pqcrypto::sign::sphincsshake128ssimple::keypair as sphincs_shake_128s_simple_keypair;
use pqcrypto::sign::sphincsshake192fsimple::keypair as sphincs_shake_192f_simple_keypair;
use pqcrypto::sign::sphincsshake192ssimple::keypair as sphincs_shake_192s_simple_keypair;
use pqcrypto::sign::sphincsshake256fsimple::keypair as sphincs_shake_256f_simple_keypair;
use pqcrypto::sign::sphincsshake256ssimple::keypair as sphincs_shake_256s_simple_keypair;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};

pub fn generate_keys(algorithm: &str, variant: &str) -> (Vec<u8>, Vec<u8>) {
    match algorithm {
        "mlkem" | "ml-kem" => {
            let (pk_bytes, sk_bytes) = match variant {
                "512" => {
                    let (pk, sk) = mlkem512_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "768" => {
                    let (pk, sk) = mlkem768_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "1024" => {
                    let (pk, sk) = mlkem1024_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) ML-KEM 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        "hqc" => {
            let (pk_bytes, sk_bytes) = match variant {
                "128" => {
                    let (pk, sk) = hqc128_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "192" => {
                    let (pk, sk) = hqc192_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "256" => {
                    let (pk, sk) = hqc256_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) HQC 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        "mce" | "mceliece" => {
            let (pk_bytes, sk_bytes) = match variant {
                "mceliece348864" => {
                    let (pk, sk) = mceliece348864_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece460896" => {
                    let (pk, sk) = mceliece460896_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece348864f" => {
                    let (pk, sk) = mceliece348864f_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece460896f" => {
                    let (pk, sk) = mceliece460896f_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece6688128" => {
                    let (pk, sk) = mceliece6688128_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece6960119" => {
                    let (pk, sk) = mceliece6960119_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece8192128" => {
                    let (pk, sk) = mceliece8192128_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece6688128f" => {
                    let (pk, sk) = mceliece6688128f_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece6960119f" => {
                    let (pk, sk) = mceliece6960119f_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "mceliece8192128f" => {
                    let (pk, sk) = mceliece8192128f_keypair();
                    (
                        KemPublicKey::as_bytes(&pk).to_vec(),
                        KemSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) McEliece 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        "falcon" => {
            let (pk_bytes, sk_bytes) = match variant {
                "nopad512" => {
                    let (pk, sk) = falcon512_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "nopad1024" => {
                    let (pk, sk) = falcon1024_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "padded512" => {
                    let (pk, sk) = falconpadded512_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "padded1024" => {
                    let (pk, sk) = falconpadded1024_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) FALCON 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        "mldsa" | "ml-dsa" => {
            let (pk_bytes, sk_bytes) = match variant {
                "44" => {
                    let (pk, sk) = mldsa44_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "65" => {
                    let (pk, sk) = mldsa65_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                "87" => {
                    let (pk, sk) = mldsa87_keypair();
                    (
                        SignPublicKey::as_bytes(&pk).to_vec(),
                        SignSecretKey::as_bytes(&sk).to_vec(),
                    )
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) ML-DSA 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        "sph" | "sphincs" | "sphincs+" => {
            let (pk_bytes, sk_bytes) = match variant {
                "sha2_128f_simple" => {
                    let (pk, sk) = sphincs_sha2_128f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "sha2_128s_simple" => {
                    let (pk, sk) = sphincs_sha2_128s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "sha2_192f_simple" => {
                    let (pk, sk) = sphincs_sha2_192f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "sha2_192s_simple" => {
                    let (pk, sk) = sphincs_sha2_192s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "sha2_256f_simple" => {
                    let (pk, sk) = sphincs_sha2_256f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "sha2_256s_simple" => {
                    let (pk, sk) = sphincs_sha2_256s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_128f_simple" => {
                    let (pk, sk) = sphincs_shake_128f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_128s_simple" => {
                    let (pk, sk) = sphincs_shake_128s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_192f_simple" => {
                    let (pk, sk) = sphincs_shake_192f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_192s_simple" => {
                    let (pk, sk) = sphincs_shake_192s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_256f_simple" => {
                    let (pk, sk) = sphincs_shake_256f_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                "shake_256s_simple" => {
                    let (pk, sk) = sphincs_shake_256s_simple_keypair();
                    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
                }
                _ => {
                    eprintln!(
                        "'{}'은(는) SPHINCS+ 알고리즘에서 가능한 배리언트가 아닙니다!",
                        variant
                    );
                    std::process::exit(1);
                }
            };
            (pk_bytes, sk_bytes)
        }
        _ => {
            eprintln!("알 수 없는 알고리즘: {}", algorithm);
            std::process::exit(1);
        }
    }
}

pub fn minimal_variant_for_algorithm(algo: &str) -> &'static str {
    match algo {
        "mlkem" | "ml-kem" => "512",
        "hqc" => "128",
        "mce" | "mceliece" => "mceliece348864",
        "falcon" => "nopad512",
        "mldsa" | "ml-dsa" => "44",
        "sph" | "sphincs" | "sphincs+" => "sha2_128f_simple",
        _ => "",
    }
}

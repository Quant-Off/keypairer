use std::path::Path;

pub fn finalize_paths(
    pk_opt: &Option<String>,
    sk_opt: &Option<String>,
    algorithm: &str,
) -> (String, String) {
    let default_pk = format!("{}.pub", algorithm);
    let default_sk = format!("{}.sk", algorithm);

    let pk_path = match pk_opt {
        Some(p) => {
            if Path::new(p).extension().is_none() {
                format!("{}.pub", p)
            } else {
                p.clone()
            }
        }
        None => default_pk,
    };

    let sk_path = match sk_opt {
        Some(p) => {
            if Path::new(p).extension().is_none() {
                format!("{}.sk", p)
            } else {
                p.clone()
            }
        }
        None => default_sk,
    };

    (pk_path, sk_path)
}

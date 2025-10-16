use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process;

use base64::Engine as _;
use base64::engine::general_purpose;

pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {}-----\n", label));
    let mut i = 0usize;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        out.push_str(&b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

pub fn save_keys(
    pk_bytes: &[u8],
    sk_bytes: &[u8],
    pk_path: &str,
    sk_path: &str,
    algorithm: &str,
    variant: &str,
    pk_text: bool,
    sk_text: bool,
    lang: &str,
) {
    let mut pk_file = match File::create(pk_path) {
        Ok(file) => file,
        Err(e) => {
            let tr = super::i18n::load_translations(lang);
            let msg = tr.get("error.file.create_pk").cloned().unwrap_or_else(|| {
                "공개키 파일을 생성하는 도중 오류가 발생했습니다: {err}".to_string()
            });
            eprintln!("{}", msg.replace("{err}", &e.to_string()));
            process::exit(1);
        }
    };

    if pk_text {
        let pem = to_pem("PUBLIC KEY", pk_bytes);
        if let Err(e) = pk_file.write_all(pem.as_bytes()) {
            let tr = super::i18n::load_translations(lang);
            let msg = tr.get("error.file.write_pk").cloned().unwrap_or_else(|| {
                "공개키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string()
            });
            eprintln!("{}", msg.replace("{err}", &e.to_string()));
            process::exit(1);
        }
    } else if let Err(e) = pk_file.write_all(pk_bytes) {
        let tr = super::i18n::load_translations(lang);
        let msg = tr
            .get("error.file.write_pk")
            .cloned()
            .unwrap_or_else(|| "공개키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string());
        eprintln!("{}", msg.replace("{err}", &e.to_string()));
        process::exit(1);
    }

    // 비밀키 파일은 원자적으로 0o600 권한으로 생성
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut sk_file = match {
        #[cfg(unix)]
        {
            let mut opts = OpenOptions::new();
            opts.write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(sk_path)
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(sk_path)
        }
    } {
        Ok(file) => file,
        Err(e) => {
            let tr = super::i18n::load_translations(lang);
            let msg = tr.get("error.file.create_sk").cloned().unwrap_or_else(|| {
                "비밀키 파일을 생성하는 도중 오류가 발생했습니다: {err}".to_string()
            });
            eprintln!("{}", msg.replace("{err}", &e.to_string()));
            process::exit(1);
        }
    };

    if sk_text {
        let pem = to_pem("SECRET KEY", sk_bytes);
        if let Err(e) = sk_file.write_all(pem.as_bytes()) {
            let tr = super::i18n::load_translations(lang);
            let msg = tr.get("error.file.write_sk").cloned().unwrap_or_else(|| {
                "비밀키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string()
            });
            eprintln!("{}", msg.replace("{err}", &e.to_string()));
            process::exit(1);
        }
    } else if let Err(e) = sk_file.write_all(sk_bytes) {
        let tr = super::i18n::load_translations(lang);
        let msg = tr
            .get("error.file.write_sk")
            .cloned()
            .unwrap_or_else(|| "비밀키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string());
        eprintln!("{}", msg.replace("{err}", &e.to_string()));
        process::exit(1);
    }

    // 로그 출력
    let tr = super::i18n::load_translations(lang);
    println!(
        "{}",
        tr.get("info.generated")
            .cloned()
            .unwrap_or_else(|| "키 페어 생성 완료".to_string())
            .replace("{alg}", &algorithm.to_uppercase())
            .replace("{var}", &variant)
    );

    println!(
        "{}",
        tr.get("info.pk_saved")
            .cloned()
            .unwrap_or_else(|| "공개키 저장: {path}".to_string())
            .replace("{path}", pk_path)
    );

    println!(
        "{}",
        tr.get("info.sk_saved")
            .cloned()
            .unwrap_or_else(|| "비밀키 저장: {path}".to_string())
            .replace("{path}", sk_path)
    );

    println!(
        "{} {}",
        tr.get("info.pk_preview")
            .cloned()
            .unwrap_or_else(|| "공개키(base64) 미리보기:".to_string()),
        general_purpose::STANDARD.encode(&pk_bytes[0..32.min(pk_bytes.len())])
    );
}

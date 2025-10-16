use std::process;
use std::thread;
use std::collections::HashMap;

pub mod internals {
    pub mod i18n;
    pub mod key_io;
    pub mod keygen;
}

/// 대용량 스택에서 함수를 실행합니다 (언어 인자 포함).
/// 
/// # Arguments
/// * `f` - 실행할 함수
/// * `lang` - 언어 코드 (예: "ko", "en")
/// 
/// # Returns
/// 함수의 실행 결과를 반환합니다.
/// 
/// # Panics
/// 스레드 생성 실패 시 프로세스를 종료합니다.
pub fn run_with_large_stack<F, R>(f: F, lang: &str) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let builder = thread::Builder::new().stack_size(64 * 1024 * 1024); // 64 MiB
    let handle = builder.spawn(f).unwrap_or_else(|e| {
        let tr = internals::i18n::load_translations(lang);
        let msg = tr
            .get("error.large_stack_create")
            .cloned()
            .unwrap_or_else(|| {
                "대용량 스택 스레드를 생성하는 도중 오류가 발생했습니다: {err}".to_string()
            });
        eprintln!("{}", msg.replace("{err}", &e.to_string()));
        process::exit(1);
    });

    match handle.join() {
        Ok(result) => result,
        Err(_) => {
            let tr = internals::i18n::load_translations(lang);
            let msg = tr
                .get("error.large_stack_panic")
                .cloned()
                .unwrap_or_else(|| {
                    "대용량 스택 스레드에서 알 수 없는 패닉이 발생했습니다.".to_string()
                });
            eprintln!("{}", msg);
            process::exit(1);
        }
    }
}

/// 대용량 스택에서 함수를 실행합니다 (언어 인자 없음).
/// 
/// # Arguments
/// * `f` - 실행할 함수
/// 
/// # Returns
/// 함수의 실행 결과를 반환합니다.
/// 
/// # Panics
/// 스레드 생성 실패 시 패닉을 발생시킵니다.
pub fn run_with_large_stack_default<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let builder = thread::Builder::new().stack_size(64 * 1024 * 1024); // 64 MiB
    let handle = builder.spawn(f).expect("대용량 스택 스레드 생성 실패");

    handle.join().expect("대용량 스택 스레드 실행 실패")
}

/// 번역을 로드합니다 (언어 인자 포함).
/// 
/// # Arguments
/// * `lang` - 언어 코드 (예: "ko", "en")
/// 
/// # Returns
/// 번역 맵을 반환합니다.
pub fn load_translations(lang: &str) -> HashMap<String, String> {
    internals::i18n::load_translations(lang)
}

/// 번역을 로드합니다 (기본 언어 "ko" 사용).
/// 
/// # Returns
/// 한국어 번역 맵을 반환합니다.
pub fn load_translations_default() -> HashMap<String, String> {
    internals::i18n::load_translations("ko")
}

/// 키 페어를 파일에 저장합니다 (언어 인자 포함).
/// 
/// # Arguments
/// * `pk_bytes` - 공개키 바이트
/// * `sk_bytes` - 비밀키 바이트
/// * `pk_path` - 공개키 파일 경로
/// * `sk_path` - 비밀키 파일 경로
/// * `algorithm` - 알고리즘 이름
/// * `variant` - 알고리즘 배리언트
/// * `pk_text` - 공개키를 텍스트 형태로 저장할지 여부
/// * `sk_text` - 비밀키를 텍스트 형태로 저장할지 여부
/// * `lang` - 언어 코드
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
    internals::key_io::save_keys(
        pk_bytes, sk_bytes, pk_path, sk_path, algorithm, variant, pk_text, sk_text, lang,
    );
}

/// 키 페어를 파일에 저장합니다 (기본 언어 "ko" 사용).
/// 
/// # Arguments
/// * `pk_bytes` - 공개키 바이트
/// * `sk_bytes` - 비밀키 바이트
/// * `pk_path` - 공개키 파일 경로
/// * `sk_path` - 비밀키 파일 경로
/// * `algorithm` - 알고리즘 이름
/// * `variant` - 알고리즘 배리언트
/// * `pk_text` - 공개키를 텍스트 형태로 저장할지 여부
/// * `sk_text` - 비밀키를 텍스트 형태로 저장할지 여부
pub fn save_keys_default(
    pk_bytes: &[u8],
    sk_bytes: &[u8],
    pk_path: &str,
    sk_path: &str,
    algorithm: &str,
    variant: &str,
    pk_text: bool,
    sk_text: bool,
) {
    internals::key_io::save_keys(
        pk_bytes, sk_bytes, pk_path, sk_path, algorithm, variant, pk_text, sk_text, "ko",
    );
}

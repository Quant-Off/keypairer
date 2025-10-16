// 표준 프렐류드
use std::env;
use std::process;
use std::thread;
use zeroize::Zeroize;

// 모듈 선언
mod internals;
mod util;

// 모듈 사용
use internals::i18n::load_translations;
use internals::key_io::save_keys;
use internals::keygen::{generate_keys, minimal_variant_for_algorithm};
use util::finalize_paths;

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args
        .get(0)
        .cloned()
        .unwrap_or_else(|| "keypairer".to_string());

    // 플래그 기반 파싱
    let mut alg_opt: Option<String> = None;
    let mut variant_opt: Option<String> = None;
    let mut pk_path_opt: Option<String> = None;
    let mut sk_path_opt: Option<String> = None;
    let mut pk_text: bool = false;
    let mut sk_text: bool = false;
    let mut lang: String = "ko".to_string();

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-alg" | "-algorithm" => {
                i += 1;
                if i >= args.len() {
                    return usage_and_exit(&prog, &lang);
                }
                alg_opt = Some(args[i].to_lowercase());
            }
            "-var" | "-variant" => {
                i += 1;
                if i >= args.len() {
                    return usage_and_exit(&prog, &lang);
                }
                variant_opt = Some(args[i].to_lowercase());
            }
            "-pkpath" => {
                i += 1;
                if i >= args.len() {
                    return usage_and_exit(&prog, &lang);
                }
                pk_path_opt = Some(args[i].clone());
            }
            "-skpath" => {
                i += 1;
                if i >= args.len() {
                    return usage_and_exit(&prog, &lang);
                }
                sk_path_opt = Some(args[i].clone());
            }
            "-pkt" | "-pktext" => {
                pk_text = true;
            }
            "-skt" | "-sktext" => {
                sk_text = true;
            }
            "-l" | "-lang" => {
                i += 1;
                if i >= args.len() {
                    return usage_and_exit(&prog, &lang);
                }
                lang = args[i].to_lowercase();
            }
            "-h" | "--help" => {
                return usage_and_exit(&prog, &lang);
            }
            other => {
                let tr = load_translations(&lang);
                let msg = tr
                    .get("error.unknown_arg")
                    .cloned()
                    .unwrap_or_else(|| "알 수 없는 인자: {arg}".to_string());
                eprintln!("{}", msg.replace("{arg}", other));
                return usage_and_exit(&prog, &lang);
            }
        }
        i += 1;
    }

    // 필수 인자 검증
    let algorithm = match alg_opt {
        Some(a) => a,
        None => {
            let tr = load_translations(&lang);
            eprintln!(
                "{}",
                tr.get("error.missing_alg")
                    .map(String::as_str)
                    .unwrap_or("필수 인자 누락: -alg <알고리즘>")
            );
            return usage_and_exit(&prog, &lang);
        }
    };

    // 배리언트 결정 (기본값 또는 사용자 지정)
    let variant =
        variant_opt.unwrap_or_else(|| minimal_variant_for_algorithm(&algorithm).to_string());

    if variant.is_empty() {
        let tr = load_translations(&lang);
        let msg = tr
            .get("error.unknown_algorithm")
            .cloned()
            .unwrap_or_else(|| "알 수 없는 알고리즘: {alg}".to_string());
        eprintln!("{}", msg.replace("{alg}", &algorithm));
        return usage_and_exit(&prog, &lang);
    }

    // 파일 경로 결정
    let (pk_path, sk_path) = finalize_paths(&pk_path_opt, &sk_path_opt, &algorithm);

    // 대용량 스택에서 키 생성 실행
    let alg_clone = algorithm.clone();
    let var_clone = variant.clone();
    let (mut pk_bytes, mut sk_bytes) =
        run_with_large_stack(move || generate_keys(&alg_clone, &var_clone), &lang);

    // 키 저장 (비밀키는 0o600 권한으로 생성)
    save_keys(
        &pk_bytes, &sk_bytes, &pk_path, &sk_path, &algorithm, &variant, pk_text, sk_text, &lang,
    );

    // 비밀키 메모리 안전 삭제
    sk_bytes.zeroize();
    pk_bytes.zeroize();
}

fn usage_and_exit(prog: &str, lang: &str) {
    let tr = load_translations(lang);

    eprintln!("{}", tr.get("usage").cloned()
        .unwrap_or_else(|| "사용법: {prog} -alg <알고리즘> [-var | -variant <배리언트>] [-pkpath <공개키 경로>] [-skpath <비밀키 경로>] [-pkt | -pktext] [-skt | -sktext] [-lang <i18n 언어팩>]".to_string())
        .replace("{prog}", prog));

    eprintln!(
        "{}",
        tr.get("usage.supported").cloned().unwrap_or_else(|| {
            "지원되는 알고리즘: mlkem, hqc, mceliece, falcon, mldsa, sphincs+".to_string()
        })
    );

    eprintln!(
        "{}",
        tr.get("usage.req").cloned().unwrap_or_else(|| {
            "- 알고리즘은 필수로 명시해야 합니다. 배리언트는 알고리즘별 최소값이 기본입니다."
                .to_string()
        })
    );

    eprintln!("{}", tr.get("usage.paths").cloned()
        .unwrap_or_else(|| "- 경로를 생략하면 현재 디렉토리에 '<알고리즘>.pub' / '<알고리즘>.sk'로 저장되며, 선택적으로 확장자를 명시할 수 있습니다.".to_string()));

    eprintln!("{}", tr.get("usage.text").cloned()
        .unwrap_or_else(|| "- [-pktext] 또는 [-sktext] 옵션을 추가하여 각 공개키/비밀키의 PEM 유사하게 저장하여 확인할 수 있게 합니다. 단, 권장하지 않습니다.".to_string()));

    eprintln!(
        "{}",
        tr.get("usage.lang").cloned().unwrap_or_else(|| {
            "- [-lang]로 출력 로케일을 설정합니다. 기본값은 ko, en 지원.".to_string()
        })
    );

    print_help_variants();
    process::exit(1);
}

fn run_with_large_stack<F, R>(f: F, lang: &str) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let builder = thread::Builder::new().stack_size(64 * 1024 * 1024); // 64 MiB
    let handle = builder.spawn(f).unwrap_or_else(|e| {
        let tr = load_translations(lang);
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
            let tr = load_translations(lang);
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

fn print_help_variants() {
    // 구성 가능한 섹션 데이터
    struct Section<'a> {
        label: &'a str,
        items: &'a [&'a str],
    }

    let sections = [
        Section {
            label: "mlkem",
            items: &["512", "768", "1024"],
        },
        Section {
            label: "hqc",
            items: &["128", "192", "256"],
        },
        Section {
            label: "mceliece",
            items: &[
                "348864", "348864", "460896", "460896", "348864f", "348864f", "460896f", "460896f",
                "6688128", "6688128", "6960119", "6960119", "8192128", "8192128", "6688128f",
                "6688128f", "6960119f", "6960119f", "8192128f", "8192128f",
            ],
        },
        Section {
            label: "falcon",
            items: &["nopad512", "nopad1024", "padded512", "padded1024"],
        },
        Section {
            label: "mldsa",
            items: &["44", "65", "87"],
        },
        Section {
            label: "sphincs+",
            items: &[
                "sha2_128f_simple",
                "sha2_128s_simple",
                "sha2_192f_simple",
                "sha2_192s_simple",
                "sha2_256f_simple",
                "sha2_256s_simple",
                "shake_128f_simple",
                "shake_128s_simple",
                "shake_192f_simple",
                "shake_192s_simple",
                "shake_256f_simple",
                "shake_256s_simple",
            ],
        },
    ];

    eprintln!("    배리언트:");
    for section in &sections {
        eprintln!("        {}:", section.label);
        for item in section.items {
            eprintln!("            {},", item);
        }
        eprintln!("");
    }
}

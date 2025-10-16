use std::collections::HashMap;

pub fn load_translations(lang: &str) -> HashMap<String, String> {
    // 기본 ko 메시지
    let mut ko: HashMap<String, String> = HashMap::new();
    ko.insert(
        "error.missing_alg".to_string(),
        "필수 인자 누락: -alg <알고리즘>".to_string(),
    );
    ko.insert(
        "error.unknown_algorithm".to_string(),
        "알 수 없는 알고리즘: {alg}".to_string(),
    );
    ko.insert(
        "error.unknown_arg".to_string(),
        "알 수 없는 인자: {arg}".to_string(),
    );
    ko.insert(
        "error.file.create_pk".to_string(),
        "공개키 파일을 생성하는 도중 오류가 발생했습니다: {err}".to_string(),
    );
    ko.insert(
        "error.file.write_pk".to_string(),
        "공개키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string(),
    );
    ko.insert(
        "error.file.create_sk".to_string(),
        "비밀키 파일을 생성하는 도중 오류가 발생했습니다: {err}".to_string(),
    );
    ko.insert(
        "error.file.write_sk".to_string(),
        "비밀키 파일에 쓰는 도중 오류가 발생했습니다: {err}".to_string(),
    );
    ko.insert(
        "error.large_stack_create".to_string(),
        "대용량 스택 스레드를 생성하는 도중 오류가 발생했습니다: {err}".to_string(),
    );
    ko.insert(
        "error.large_stack_panic".to_string(),
        "대용량 스택 스레드에서 알 수 없는 패닉이 발생했습니다.".to_string(),
    );
    ko.insert(
        "info.generated".to_string(),
        "'{alg}' 알고리즘 키 페어 생성 완료(배리언트: {var}).".to_string(),
    );
    ko.insert(
        "info.pk_saved".to_string(),
        "공개키 저장: {path}".to_string(),
    );
    ko.insert(
        "info.sk_saved".to_string(),
        "비밀키 저장: {path}".to_string(),
    );
    ko.insert(
        "info.pk_preview".to_string(),
        "공개키(base64) 미리보기:".to_string(),
    );
    ko.insert("usage".to_string(), "사용법: {prog} -alg <알고리즘> [-var | -variant <배리언트>] [-pkpath <공개키 경로>] [-skpath <비밀키 경로>] [-pkt | -pktext] [-skt | -sktext] [-lang <ko|en>]".to_string());
    ko.insert(
        "usage.supported".to_string(),
        "지원되는 알고리즘: mlkem, hqc, mceliece, falcon, mldsa, sphincs+".to_string(),
    );
    ko.insert(
        "usage.req".to_string(),
        "- 알고리즘은 필수로 명시해야 합니다. 배리언트는 알고리즘별 최소값이 기본입니다."
            .to_string(),
    );
    ko.insert("usage.paths".to_string(), "- 경로를 생략하면 현재 디렉토리에 '<알고리즘>.pub' / '<알고리즘>.sk'로 저장되며, 선택적으로 확장자를 명시할 수 있습니다.".to_string());
    ko.insert("usage.text".to_string(), "- [-pktext] 또는 [-sktext] 옵션을 추가하여 각 공개키/비밀키의 PEM 유사하게 저장하여 확인할 수 있게 합니다. 단, 권장하지 않습니다.".to_string());
    ko.insert(
        "usage.lang".to_string(),
        "- [-lang]로 출력 로케일을 설정합니다. 기본값은 ko, en 지원.".to_string(),
    );

    if lang == "en" {
        if let Ok(text) = std::fs::read_to_string("i18n/en.json") {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&text) {
                return map;
            }
        }
        // 내장 en 폴백
        let mut en: HashMap<String, String> = HashMap::new();
        en.insert(
            "error.missing_alg".to_string(),
            "Missing required argument: -alg <algorithm>".to_string(),
        );
        en.insert(
            "error.unknown_algorithm".to_string(),
            "Unknown algorithm: {alg}".to_string(),
        );
        en.insert(
            "error.unknown_arg".to_string(),
            "Unknown argument: {arg}".to_string(),
        );
        en.insert(
            "error.file.create_pk".to_string(),
            "Error while creating public key file: {err}".to_string(),
        );
        en.insert(
            "error.file.write_pk".to_string(),
            "Error while writing to public key file: {err}".to_string(),
        );
        en.insert(
            "error.file.create_sk".to_string(),
            "Error while creating secret key file: {err}".to_string(),
        );
        en.insert(
            "error.file.write_sk".to_string(),
            "Error while writing to secret key file: {err}".to_string(),
        );
        en.insert(
            "error.large_stack_create".to_string(),
            "An error occurred while creating a large stack thread: {err}".to_string(),
        );
        en.insert(
            "error.large_stack_panic".to_string(),
            "Unknown panic occurred in large-stack thread.".to_string(),
        );
        en.insert(
            "info.generated".to_string(),
            "Generated key pair for '{alg}' (variant: {var}).".to_string(),
        );
        en.insert(
            "info.pk_saved".to_string(),
            "Public key saved: {path}".to_string(),
        );
        en.insert(
            "info.sk_saved".to_string(),
            "Secret key saved: {path}".to_string(),
        );
        en.insert(
            "info.pk_preview".to_string(),
            "Public key (base64) preview:".to_string(),
        );
        en.insert("usage".to_string(), "Usage: {prog} -alg <algorithm> [-var | -variant <variant>] [-pkpath <public key path>] [-skpath <secret key path>] [-pkt | -pktext] [-skt | -sktext] [-lang <ko|en>]".to_string());
        en.insert(
            "usage.supported".to_string(),
            "Supported algorithms: mlkem, hqc, mceliece, falcon, mldsa, sphincs+".to_string(),
        );
        en.insert(
            "usage.req".to_string(),
            "- Algorithm is required. Variant defaults to the minimum per algorithm.".to_string(),
        );
        en.insert("usage.paths".to_string(), "- If paths are omitted, files are saved to the current directory as '<algorithm>.pub' / '<algorithm>.sk'. You may optionally specify extensions.".to_string());
        en.insert(
            "usage.text".to_string(),
            "- Add [-pktext] or [-sktext] to save public/secret keys in a PEM-like text format."
                .to_string(),
        );
        en.insert(
            "usage.lang".to_string(),
            "- Set output locale with [-lang]. Default is ko; en supported.".to_string(),
        );
        return en;
    }
    ko
}

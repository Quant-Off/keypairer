# Keypairer

`Keypairer`는 다양한 양자 내성 알고리즘(Post-Quantum Cryptography, PQC)을 지원하는 키 페어(keypair) 생성 도구입니다. 스택 오버플로우를 방지하고 보안을 고려한 설계로, 안전하게 PQC 키 페어를 생성할 수 있습니다.

## 주요 기능

- **다양한 PQC 알고리즘 지원**: `ML-KEM`, `HQC`, `McEliece`, `FALCON`, `ML-DSA`, `SPHINCS+`
- **스택 오버플로우 방지**: 대용량 스택 스레드에서 키 생성
- **보안 강화**: `zeroize`를 사용한 비밀키 메모리 안전 삭제, 파일 권한 제어(`0o600`)
- **다국어 지원**: 한국어(기본; ko), 영어(en)
- **유연한 출력 형식**: 바이너리 또는 `PEM` 유사 텍스트 형식 IO 지원
- **자동 경로 처리**: 확장자 자동 추가, 기본 경로 설정

## 상세: 지원 알고리즘

다음은 알고리즘에 대해 지원되는 배리언트(variants)를 열거한 것입니다.

### KEM (Key Encapsulation Mechanism)

- **ML-KEM**: `512`, `768`, `1024`
- **HQC**: `128`, `192`, `256`
- **McEliece**: `348864`, `460896`, `6688128`, `6960119`, `8192128` (f 변형 포함; 예로, `348864f`)

### 서명 (Digital Signature)

- **FALCON**: `nopad512`, `nopad1024`, `padded512`, `padded1024`
- **ML-DSA**: `44`, `65`, `87`
- **SPHINCS+**: `SHA2`/`SHAKE` 기반 `128`/`192`/`256`비트 (f/s 변형 포함; 예로, `shake_256s_simple`)

## 설치 및 빌드

### 요구사항

포크(fork) 맟 변경 시 다음의 요구사항을 충족하세요.

- Rust (Rustup 1.28+, Rustc 1.90+)
- Cargo (1.90+)

### 빌드

```bash
# 저장소 복제
$ git clone https://github.com/Quant-Off/keypairer.git
$ cd keypairer
$ cargo build --release
```

### 개발 빌드

```bash
cargo build
```

## 사용법

### 기본 사용법

```bash
# ML-KEM 512 키 페어 생성 (기본 배리언트)
$ cargo run -- -alg ml-kem

# 특정 배리언트 지정
$ cargo run -- -alg ml-kem -variant 1024

# 사용자 정의 파일 경로
$ cargo run -- -alg falcon -variant padded512 -pkpath my_public.key -skpath my_secret.key

# PEM 형식으로 저장
$ cargo run -- -alg hqc -variant 256 -pktext -sktext

# 영어로 출력
$ cargo run -- -alg mceliece -variant mceliece8192128 -lang en
```

### 명령행 옵션

| 옵션 | 설명 | 필수 | 기본값 |
|------|------|------|--------|
| `-alg <algorithm>` | 알고리즘 선택 | O | - |
| `-variant <variant>` | 배리언트 선택 | X | 알고리즘별 최소값 |
| `-pkpath <path>` | 공개키 파일 경로 | X | `<algorithm>.pub` |
| `-skpath <path>` | 비밀키 파일 경로 | X | `<algorithm>.sk` |
| `-pktext` | 공개키를 텍스트 형식으로 저장 | X | false |
| `-sktext` | 비밀키를 텍스트 형식으로 저장 | X | false |
| `-lang <locale>` | 출력 언어 (ko/en) | X | ko |
| `-h, --help` | 도움말 표시 | X | - |

### 알고리즘별 기본 배리언트

- **ML-KEM**: `512`
- **HQC**: `128`
- **McEliece**: `mceliece348864`
- **FALCON**: `nopad512`
- **ML-DSA**: `44`
- **SPHINCS+**: `sha2_128f_simple`

## 고급 사용법

### 파일 경로 자동 확장

```bash
# 확장자가 없으면 자동으로 .pub, .sk 추가
$ cargo run -- -alg ml-kem -pkpath pubkey -skpath privkey
# 결과: pubkey.pub, pubkey.sk

# 확장자가 있으면 그대로 사용
$ cargo run -- -alg ml-kem -pkpath pubkey.pem -skpath privkey.key
# 결과: pubkey.pem, privkey.key
```

### 다국어 지원

```bash
# 한국어 (기본)
$ cargo run -- -alg ml-kem

# 영어
$ cargo run -- -alg ml-kem -lang en
```

### 텍스트 형식 출력

```bash
# PEM 유사 형식으로 저장 (읽기 가능)
$ cargo run -- -alg falcon -pktext -sktext
```

## 프로젝트 구조

```plain
src/
   ├── main.rs       # 메인 로직 및 인자 파싱
   ├── i18n.rs       # 다국어 지원
   ├── keygen.rs     # 키 생성 로직
   ├── key_io.rs     # 파일 I/O 및 PEM 변환
   └── util.rs       # 유틸리티 함수

i18n/
   └── en.json       # 영어 번역 파일
```

## 보안 고려사항

### 메모리 보안

- **Zeroize**: 비밀키 메모리 자동 삭제
- **대용량 스택**: `64MB` 스택으로 스택 오버플로우 방지
- **안전한 파일 권한**: `Unix`에서 비밀키 파일 `0o600` 권한

### 권장사항

다음의 권장사항을 참고하세요.

- 비밀키는 안전한 위치에 보관
- 텍스트 형식(`-pktext`, `-sktext`) 사용 시 주의
- 프로덕션 환경에서는 릴리즈 빌드 사용

## 예시

### 다양한 알고리즘 테스트

```bash
# ML-KEM 1024
$ cargo run -- -alg ml-kem -variant 1024

# McEliece 8192128 (대용량)
$ cargo run -- -alg mceliece -variant mceliece8192128

# FALCON Padded 1024
$ cargo run -- -alg falcon -variant padded1024

# SPHINCS+ SHAKE 256
$ cargo run -- -alg sphincs+ -variant shake_256f_simple
```

### 개발 및 테스트

```bash
# 도움말 확인
$ cargo run -- -h

# 영어 도움말
$ cargo run -- -h -lang en

# 빌드 및 테스트
$ cargo build
$ cargo test
```

## 의존성

- **pqcrypto**: PQC 알고리즘 구현
- **pqcrypto-traits**: PQC 트레이트(traits) 정의
- **base64**: Base64 인코딩/디코딩
- **zeroize**: 메모리 안전 삭제
- **serde/serde_json**: JSON 파싱 (i18n)

## 기여

1. 이슈 생성 또는 기존 이슈 확인
2. 포크 및 브랜치 생성
3. 변경사항 구현
4. 테스트 실행
5. 풀 리퀘스트 생성

자세한 사항은 [기여 문서](CONTRIBUTION.md)를 참고하세요.

## 라이선스

이 프로젝트는 `MIT 라이선스` 하에 배포됩니다.

## 관련 링크

- [NIST PQC 표준화](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST PQC 효준화(위키피디아)](https://en.wikipedia.org/wiki/NIST_Post-Quantum_Cryptography_Standardization)
- [pqcrypto 크레이트](https://crates.io/crates/pqcrypto)
- [Rust 공식 문서](https://doc.rust-lang.org/)

---

**주의**: 이 도구는 교육 및 연구 목적으로 제작되었습니다. 프로덕션 환경에서 사용하기 전에 보안 검토를 수행하세요.

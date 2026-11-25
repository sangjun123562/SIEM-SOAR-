# 대시보드 글꼴 (자체 제공)

대시보드가 외부 CDN을 부르지 않도록 글꼴 파일을 저장소에 포함한다.

| 항목 | 내용 |
|---|---|
| 글꼴 | Pretendard Variable (`PretendardVariable.woff2`, 굵기 45~920) |
| 출처 | https://github.com/orioncactus/pretendard 태그 `v1.3.9` (`packages/pretendard/dist/web/variable/woff2/`) |
| 받은 경로 | `https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/packages/pretendard/dist/web/variable/woff2/PretendardVariable.woff2` |
| 라이선스 | SIL Open Font License 1.1 (`PRETENDARD-LICENSE-OFL.txt`). 재배포·포함 가능, 글꼴 이름 판매 금지 등 조건은 라이선스 참고 |
| sha256 | `9599f12fd42fc0bce1cd50b47a0c022e108d7aa64dd0d1bb0ed44f3282d900b4` |
| 받은 날 | 2026-11-25 |

- 서버는 `/static/fonts/PretendardVariable.woff2` 한 경로만 제공한다(`src/soc/dashboard.py`). 다른 정적 파일은 제공하지 않는다.
- 파일을 바꿀 때는 위 표의 버전·해시를 함께 갱신하고, woff2 형식(앞 4바이트 `wOF2`)을 확인한다.

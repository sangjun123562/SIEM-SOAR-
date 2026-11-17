# 출처 기록

| 항목 | 내용 |
|---|---|
| 원본 저장소 | https://github.com/eldi96/choi-bujang-secret-vault (공개, 팀원 A 본인 계정) |
| 원본 커밋 | `246e00a4a850651fb9a367712f93c514dcea4bfd` (2026-11-16, "보너스 xdr-06 저장점") |
| 가져온 파일 | `public/index.html` → `erp/static/index.html` (화면 구조와 CSS) |
| 라이선스 | 저장소에 라이선스 파일 없음. 본인 저장소의 학습 자료를 본인 캡스톤에 사용 |
| 목적 | 「나만의 자료실」 화면을 캡스톤 ERP(구매 요청) 화면의 출발점으로 사용 |

## 가져오지 않은 것
- `api/*.js`(Supabase·Node.js 서버): Flask(`erp/app.py`)로 새로 작성
- `.env`, 키·토큰, 실제 데이터, `.git`, 캐시, `data.json`, 서비스 워커·매니페스트·아이콘, 기기 승인(`/api/device`) 기능

원본 저장소는 읽기만 했고 수정하지 않았다.

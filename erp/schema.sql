-- ERP 전용 DB 구조 (관제용 DB와는 별개의 PostgreSQL 컨테이너/계정/볼륨)
-- 테이블은 2개뿐이다: 사용자(users), 구매 요청(purchase_requests)

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                       -- 비밀번호 원문은 저장하지 않는다(해시만)
    department    TEXT NOT NULL,                       -- 부서: 영업, 개발
    role          TEXT NOT NULL CHECK (role IN ('member', 'manager'))  -- 직급: 사원, 팀장
);

CREATE TABLE IF NOT EXISTS purchase_requests (
    id           BIGSERIAL PRIMARY KEY,
    public_id    UUID UNIQUE NOT NULL,                 -- 화면·로그에서 쓰는 번호(추측하기 어렵게 UUID)
    requester_id INT NOT NULL REFERENCES users(id),    -- 요청자
    department   TEXT NOT NULL,                        -- 요청자의 부서(권한 판단에 사용)
    title        TEXT NOT NULL,                        -- 품목
    amount       BIGINT NOT NULL CHECK (amount > 0),   -- 금액(원)
    reason       TEXT NOT NULL,                        -- 사유
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by   INT REFERENCES users(id),             -- 승인·반려한 사람
    decided_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_requests_department ON purchase_requests (department);
CREATE INDEX IF NOT EXISTS idx_requests_requester ON purchase_requests (requester_id);

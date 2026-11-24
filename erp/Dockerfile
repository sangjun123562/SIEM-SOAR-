# ERP 이미지: Python + Flask(웹) + gunicorn(실행기) + psycopg(PostgreSQL 연결).
# 패키지 설치는 준비 단계이며 시험 트래픽과 분리된다.
FROM python:3.12-alpine
RUN pip install --no-cache-dir "Flask==3.1.*" "gunicorn==23.*" "psycopg[binary]==3.2.*"
WORKDIR /app
COPY app.py /app/app.py
COPY documents.py /app/documents.py
COPY login_access.py /app/login_access.py
COPY account_lock.py /app/account_lock.py
COPY static /app/static
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-tmp-dir", "/tmp", "app:app"]

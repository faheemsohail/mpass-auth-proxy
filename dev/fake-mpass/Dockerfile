FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY fake_mpass.py users.json ./
RUN adduser --system --no-create-home appuser
USER appuser
# Tokens travel in /users/login/as redirects; keep them out of access logs.
CMD ["uvicorn", "--factory", "fake_mpass:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY fake_mpass.py users.json ./
RUN adduser --system --no-create-home appuser
USER appuser
# Tokens travel in /users/login/as redirects; keep them out of access logs.
CMD ["uvicorn", "--factory", "fake_mpass:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM python:3.12-slim
WORKDIR /sentinel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/download_data.py
ENV SENTINEL_DB_PATH=/history/sentinel.db
RUN mkdir -p /history && useradd --create-home sentinel && chown -R sentinel:sentinel /sentinel /history
USER sentinel
EXPOSE 8501
CMD ["python", "-m", "streamlit", "run", "app/main.py", "--server.address=0.0.0.0", "--server.headless=true"]

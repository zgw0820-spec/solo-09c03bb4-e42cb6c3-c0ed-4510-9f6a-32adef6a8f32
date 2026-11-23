FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mock_upstream.py .
EXPOSE 5353/udp
CMD ["python", "mock_upstream.py"]

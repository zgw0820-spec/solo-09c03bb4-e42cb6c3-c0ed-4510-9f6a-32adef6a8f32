FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dns64_server.py .
EXPOSE 5354/udp
CMD ["python", "dns64_server.py"]

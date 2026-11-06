FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY app.py .
USER 10001
EXPOSE 5000
CMD ["python", "app.py"]

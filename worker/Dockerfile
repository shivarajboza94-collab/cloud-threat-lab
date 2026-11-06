FROM python:3.11-slim
WORKDIR /home/workerapp

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash workeruser

COPY parser.py .
RUN chown -R workeruser:appgroup /home/workerapp

USER 10001
CMD ["python", "parser.py"]

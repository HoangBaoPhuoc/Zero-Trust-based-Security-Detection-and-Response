FROM python:3.11-slim
WORKDIR /app
ARG SERVICE_NAME
COPY shared/ ./shared/
COPY services/${SERVICE_NAME}/ ./
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080 9090
CMD ["python", "main.py"]

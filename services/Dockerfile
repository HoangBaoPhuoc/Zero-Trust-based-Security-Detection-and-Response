FROM python:3.11-slim
WORKDIR /app
ARG SERVICE_NAME
COPY services/${SERVICE_NAME}/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ ./shared/
COPY services/${SERVICE_NAME}/ ./
EXPOSE 8080 9090
CMD ["python", "main.py"]

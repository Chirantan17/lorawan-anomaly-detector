FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-generate dataset and train ML models during build
RUN python generate_data_2.py && python train_2.py

EXPOSE 8000 9999/udp

CMD ["python", "server_2.py"]
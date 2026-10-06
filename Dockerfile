FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl make && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN make opa && useradd -m amanah && chown -R amanah /app
USER amanah
EXPOSE 8080
CMD ["sh", "-c", "python -m amanah demo && python -m http.server 8080 --directory var/reports"]

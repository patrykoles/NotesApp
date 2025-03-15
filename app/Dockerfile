FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential 

RUN pip install --no-cache-dir -r requirements.txt

COPY ./uwsgi.ini /app/uwsgi.ini

CMD ["uwsgi", "--ini", "uwsgi.ini"]

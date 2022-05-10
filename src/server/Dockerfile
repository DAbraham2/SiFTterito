
FROM python:3.10.4-slim-buster

EXPOSE 5150

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

RUN python3 -m Crypto.SelfTest

#RUN python3 -m Cryptodome.SelfTest

COPY . .

CMD ["python3", "./SiFTServer.py", "--port=5150"]

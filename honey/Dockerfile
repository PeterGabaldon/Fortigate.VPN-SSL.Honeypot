FROM python:3.8-slim-buster

WORKDIR /honey

COPY . .

RUN pip3 install -r requirements.txt

ENV FLASK_APP=honey.py
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]

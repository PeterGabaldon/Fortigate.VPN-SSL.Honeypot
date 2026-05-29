FROM python:3.14-slim-trixie

WORKDIR /honey

COPY . .

RUN pip3 install -r requirements.txt

ENV FLASK_APP=honey.py
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]

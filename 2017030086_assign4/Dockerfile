FROM python:alpine3.17

COPY . /app
WORKDIR /app
ENV FLASK_DEBUG=0
RUN pip install -r requirements.txt
EXPOSE 8080

CMD ["python", "./app/app.py"]

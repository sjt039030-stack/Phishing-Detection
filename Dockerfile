FROM python:3.10

WORKDIR /app

COPY . .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN playwright install

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
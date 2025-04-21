  FROM python:3.10-slim

  COPY . /app
  WORKDIR /app

  RUN pip install -r requirements.txt

  CMD ["python", "mvsa.py", "--code=app.py", "--report=report.json"]

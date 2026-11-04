FROM python:3.12-slim

WORKDIR /app

COPY docker/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system app && adduser --system --ingroup app --no-create-home app

COPY --chown=app:app src/boundarycheck ./boundarycheck

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER app:app

CMD ["uvicorn", "boundarycheck.api:app", "--host", "0.0.0.0", "--port", "8000"]

# NoteVault image. Part of the project is to harden this Dockerfile
# (base pinning, non-root user, no baked secrets, minimal layers).
FROM python:3.12

ENV APP_SECRET=notevault-dev-secret

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 8080
CMD ["python", "app.py"]

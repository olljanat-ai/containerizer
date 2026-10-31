# containerizer results image: the read-only web UI, `db init` and `assess --sql` (static analysis only;
# build-and-run verification needs Docker and runs from a normal checkout instead).
# Build from the repository root:  docker build -f results/Dockerfile -t containerizer-results .
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt requirements-sql.txt ./
RUN pip install --no-compile -r requirements.txt -r requirements-sql.txt
COPY containerizer/ containerizer/
COPY rules/ rules/

# dev database backups uploaded on the admin pages (CONTAINERIZER_DEV_DB_DIR, a volume in compose.yaml):
# owned by the runtime user so a new named volume inherits it
RUN mkdir -p /var/lib/containerizer/dev-databases && chown 10001:10001 /var/lib/containerizer/dev-databases \
    && chmod 700 /var/lib/containerizer/dev-databases

# Non-root, no shell needed at run time; the compose file adds read_only, cap_drop ALL and no-new-privileges.
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "containerizer"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]

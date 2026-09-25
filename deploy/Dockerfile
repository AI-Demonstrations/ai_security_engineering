# Hardened image for the ticket service.   Build from the repo root:
#   docker build -f deploy/Dockerfile -t ticketbot:dev .
#
# Practices:
#   * multi-stage: build tools and pip caches never reach the runtime image
#   * slim base, pinned by version; in CI pin by digest (FROM python:3.12-slim@sha256:...)
#   * non-root numeric UID, so Kubernetes can verify runAsNonRoot
#   * no secrets in the image: identity comes from Azure workload identity at runtime
#   * only the code the service needs is copied (see .dockerignore)
#   * listens on 8080 (unprivileged); the Service/Ingress maps 443 to it

FROM python:3.12-slim AS build
WORKDIR /src
COPY deploy/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /srv
COPY --chown=root:root ticketbot/ ticketbot/
COPY --chown=root:root deploy/app/ deploy/app/
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1
ENTRYPOINT ["python", "deploy/app/server.py"]

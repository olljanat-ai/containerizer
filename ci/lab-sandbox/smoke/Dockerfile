# Lab sandbox smoke test image: built locally (`docker build -t localhost/lab/smoke:1`), never pushed; k3s runs
# it from Docker's image store. Runs as any non-root user with a read-only root file system (/tmp writable).
ARG BASE=nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
FROM ${BASE}
COPY default.conf /etc/nginx/conf.d/default.conf
ENTRYPOINT []
CMD ["nginx", "-g", "daemon off;"]

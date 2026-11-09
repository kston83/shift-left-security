# Intentionally insecure Dockerfile used by slsec tests.
FROM ubuntu:latest
ADD https://example.com/install.sh /tmp/install.sh
RUN apt-get update && apt-get install -y curl
EXPOSE 22

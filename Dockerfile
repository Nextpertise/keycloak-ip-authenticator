FROM registry.nextpertise.tools/nextpertise-proxy/library/alpine:latest
COPY ./target/keycloak-ip-authenticator.jar .

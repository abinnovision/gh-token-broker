FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/gh-token-broker /usr/local/bin/gh-token-broker
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gh-token-broker"]
CMD ["-config", "/etc/gh-token-broker/config.yaml"]

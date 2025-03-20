FROM public.ecr.aws/docker/library/rust:1.85-alpine AS builder
COPY . /opt/app
WORKDIR /opt/app
RUN apk add --no-cache musl-dev && cargo build --release

FROM scratch
COPY --from=builder /opt/app/target/release/femtoldap /femtoldap
ENTRYPOINT [ "/femtoldap" ]

LABEL org.opencontainers.image.authors="Giacomo Longo" 
LABEL org.opencontainers.image.source="https://github.com/gabibbo97/femtoldap"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.title="femtoLDAP"
LABEL org.opencontainers.image.description="A microscopic stateless LDAP directory simulator"
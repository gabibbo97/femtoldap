FROM public.ecr.aws/docker/library/rust:1.85-alpine AS builder
COPY . /opt/app
WORKDIR /opt/app
RUN apk add --no-cache musl-dev && cargo build --release

FROM scratch
COPY --from=builder /opt/app/target/release/femtoldap /femtoldap
ENTRYPOINT [ "/femtoldap" ]

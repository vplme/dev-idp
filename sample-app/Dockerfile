FROM rust:1.98-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY templates templates
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/sample-app /sample-app
ENV SAMPLE_LISTEN=0.0.0.0:4000
EXPOSE 4000
ENTRYPOINT ["/sample-app"]

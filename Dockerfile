FROM rust:1.98-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY templates templates
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/dev-idp /dev-idp
# Reads /config/dev-idp.yaml if mounted, else runs on the built-in defaults.
WORKDIR /config
ENV DEV_IDP_LISTEN=0.0.0.0:5556
EXPOSE 5556
ENTRYPOINT ["/dev-idp"]

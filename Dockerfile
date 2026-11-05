# The build stage runs on the builder's own platform and cross-compiles a static
# musl binary for the target one: no QEMU, so arm64 builds as fast as amd64.
# That works without a C cross toolchain because no dependency compiles C code;
# rust-lld links against the musl target's bundled libc. Only the cross target
# gets rust-lld: proc-macros build for the host and need its own linker (musl-dev).
FROM --platform=$BUILDPLATFORM rust:1.98-alpine AS build
ARG TARGETARCH
RUN apk add --no-cache musl-dev
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust-target \
    && target=$(cat /rust-target) \
    && rustup target add "$target" \
    && if [ "$target" != "$(rustc -vV | sed -n 's/^host: //p')" ]; then \
         printf '[target.%s]\nlinker = "rust-lld"\n' "$target" >> "$CARGO_HOME/config.toml"; \
       fi
WORKDIR /src

# Build the dependencies against stub sources first, so this layer stays cached
# until Cargo.toml or Cargo.lock changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked --target "$(cat /rust-target)" \
    && rm -rf src

COPY src src
COPY templates templates
# touch: COPY keeps the files' mtimes, which can be older than the stub build,
# and cargo would then skip rebuilding dev-idp itself.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --target "$(cat /rust-target)" \
    && cp "target/$(cat /rust-target)/release/dev-idp" /dev-idp

FROM scratch
COPY --from=build /dev-idp /dev-idp
# Reads /config/dev-idp.yaml if mounted, else runs on the built-in defaults.
WORKDIR /config
ENV DEV_IDP_LISTEN=0.0.0.0:5556
EXPOSE 5556
ENTRYPOINT ["/dev-idp"]

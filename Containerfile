# syntax=docker/dockerfile:latest

# Torrust Index

## Builder Image
FROM rust:bookworm AS chef
WORKDIR /tmp
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
RUN cargo binstall --no-confirm cargo-chef cargo-nextest

## Tester Image (removed nextest usage)
# No separate tester stage needed since tests are disabled

## Su Exe Compile
FROM docker.io/library/gcc:bookworm AS gcc
COPY ./contrib/dev-tools/su-exec/ /usr/local/src/su-exec/
RUN cc -Wall -Werror -g /usr/local/src/su-exec/su-exec.c -o /usr/local/bin/su-exec; chmod +x /usr/local/bin/su-exec


## Chef Prepare (look at project and see wat we need)
FROM chef AS recipe
WORKDIR /build/src
COPY . /build/src
RUN cargo chef prepare --recipe-path /build/recipe.json


## Cook (debug)
FROM chef AS dependencies_debug
WORKDIR /build/src
COPY --from=recipe /build/recipe.json /build/recipe.json
RUN cargo chef cook --tests --benches --examples --workspace --all-targets --all-features --recipe-path /build/recipe.json
RUN true

## Cook (release)
FROM chef AS dependencies
WORKDIR /build/src
COPY --from=recipe /build/recipe.json /build/recipe.json
RUN cargo chef cook --tests --benches --examples --workspace --all-targets --all-features --recipe-path /build/recipe.json --release
RUN true


## Build (debug)
FROM dependencies_debug AS build_debug
WORKDIR /build/src
COPY . /build/src
RUN cargo build --workspace --all-features

## Build (release)
FROM dependencies AS build
WORKDIR /build/src
COPY . /build/src
RUN cargo build --workspace --all-features --release


## Debug artifacts (no tests)
FROM build_debug AS debug_artifacts
WORKDIR /build/src

## Release artifacts (no tests)
FROM build AS release_artifacts
WORKDIR /build/src


## Runtime
FROM gcr.io/distroless/cc-debian12:debug AS runtime
RUN ["/busybox/cp", "-sp", "/busybox/sh","/busybox/cat","/busybox/ls","/busybox/env", "/bin/"]
COPY --from=gcc --chmod=0555 /usr/local/bin/su-exec /bin/su-exec

ARG TORRUST_INDEX_CONFIG_TOML_PATH="/etc/torrust/index/index.toml"
ARG TORRUST_INDEX_DATABASE_DRIVER="sqlite3"
ARG USER_ID=1000
ARG API_PORT=3001
ARG IMPORTER_API_PORT=3002

ENV TORRUST_INDEX_CONFIG_TOML_PATH=${TORRUST_INDEX_CONFIG_TOML_PATH}
ENV TORRUST_INDEX_DATABASE_DRIVER=${TORRUST_INDEX_DATABASE_DRIVER}
ENV USER_ID=${USER_ID}
ENV API_PORT=${API_PORT}
ENV IMPORTER_API_PORT=${IMPORTER_API_PORT}
ENV TZ=Etc/UTC

EXPOSE ${API_PORT}/tcp

RUN mkdir -p /var/lib/torrust/index /var/log/torrust/index /etc/torrust/index

ENV ENV=/etc/profile
COPY --chmod=0555 ./share/container/entry_script_sh /usr/local/bin/entry.sh

VOLUME ["/var/lib/torrust/index","/var/log/torrust/index","/etc/torrust/index"]

ENV RUNTIME="runtime"
ENTRYPOINT ["/usr/local/bin/entry.sh"]


## Torrust-Index (debug)
FROM runtime AS debug
ENV RUNTIME="debug"
COPY --from=build_debug /build/src/target/debug/torrust-index /usr/bin/torrust-index
COPY --from=build_debug /build/src/target/debug/health_check /usr/bin/torrust_healthcheck
RUN env
CMD ["sh"]

## Torrust-Index (release) (default)
FROM runtime AS release
ENV RUNTIME="release"
COPY --from=build /build/src/target/release/torrust-index /usr/bin/torrust-index
COPY --from=build /build/src/target/release/health_check /usr/bin/torrust_healthcheck
HEALTHCHECK --interval=5s --timeout=5s --start-period=3s --retries=3 \  
  CMD /usr/bin/torrust_healthcheck http://localhost:${API_PORT}/health_check && /usr/bin/torrust_healthcheck http://localhost:${IMPORTER_API_PORT}/health_check || exit 1
CMD ["/usr/bin/torrust-index"]

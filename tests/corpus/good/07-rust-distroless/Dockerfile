FROM rust:1.83-slim AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/svc /usr/local/bin/svc
USER nonroot:nonroot
EXPOSE 9000
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/svc"]

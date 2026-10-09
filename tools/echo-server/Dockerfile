# Built from source inside the image, so the binary never lands in the
# Voidwall build context.
FROM rust:1.90-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=build /src/target/release/echo-server /usr/local/bin/echo-server
ENTRYPOINT ["echo-server"]

FROM rust:1.93-alpine AS build

WORKDIR /src
ENV CARGO_PROFILE_RELEASE_STRIP=symbols

COPY . .
RUN cargo build --release --locked --workspace --bins

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build \
    /src/target/release/globacl-agent \
    /src/target/release/globacl-bench \
    /src/target/release/globacl-commitd \
    /src/target/release/globacl-control \
    /src/target/release/globacl-demo-app \
    /src/target/release/globacl-relay \
    /usr/local/bin/
CMD ["/usr/local/bin/globacl-control"]

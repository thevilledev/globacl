FROM rust:1.93-slim AS build

WORKDIR /src
COPY . .
RUN cargo build --release --locked
RUN mkdir -p /out \
    && cp target/release/globacl-agent /out/ \
    && cp target/release/globacl-bench /out/ \
    && cp target/release/globacl-commitd /out/ \
    && cp target/release/globacl-control /out/ \
    && cp target/release/globacl-demo-app /out/ \
    && cp target/release/globacl-relay /out/

FROM debian:bookworm-slim

COPY --from=build /out/* /usr/local/bin/
USER 65532:65532

CMD ["/usr/local/bin/globacl-control"]

FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p nolog-dashboard

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home nolog
COPY --from=build /src/target/release/nolog-dashboard /usr/local/bin/nolog-dashboard
USER nolog
ENV NOLOG_DASHBOARD_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nolog-dashboard"]

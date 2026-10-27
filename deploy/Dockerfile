FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile /src/Makefile
COPY common /src/common
COPY server /src/server
RUN make server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin spooky

COPY --from=build /src/spooky-server /usr/local/bin/spooky-server
COPY data/runtime /opt/spooky/runtime

USER 10001:10001
EXPOSE 19160
ENTRYPOINT ["/usr/local/bin/spooky-server"]
CMD ["--host", "0.0.0.0", "--port", "19160", "--data", "/opt/spooky/runtime"]

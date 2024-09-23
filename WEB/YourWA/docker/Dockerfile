FROM oven/bun:1.1.20-slim AS builder

RUN apt-get update && apt-get install -y build-essential
RUN mkdir -p /temp/build
COPY ./Makefile ./mkflag.* ./rmflag.* /temp/build/
WORKDIR /temp/build

RUN make compile

# frontend
FROM node:20.11.0-slim AS frontend

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

RUN mkdir -p /temp/
COPY ./web /temp/web
WORKDIR /temp/web

RUN pnpm install --frozen-lockfile
ENV NODE_ENV=production
RUN NODE_OPTIONS="--max_old_space_size=2048" pnpm build

# backend
FROM oven/bun:1.1.20-slim

ENV FLAG="flag{test_flag}"

RUN useradd -m ctf
COPY --from=denoland/deno:bin-1.45.3 /deno /usr/local/bin/deno

RUN apt-get update && \
    apt-get install -y file unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app
COPY . /app
RUN rm -rf /app/web
COPY --from=frontend /temp/web/dist/. /app/static/
WORKDIR /app

COPY --from=builder /temp/build/mkflag /temp/build/rmflag /app/
RUN chmod u+s mkflag rmflag
RUN bun install --frozen-lockfile --production

USER ctf

EXPOSE 3031
ENV NODE_ENV=production
CMD [ "bun", "start" ]
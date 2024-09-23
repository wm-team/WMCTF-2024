FROM node:20.11.0-slim

ENV FLAG="flag{test_flag}"
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

RUN apt-get update && \
    DEPS=$(apt-get install --no-install-recommends -s chromium | grep "Inst" | awk '{print $2}' | grep -v "chromium") && \
    apt-get install -y --no-install-recommends $DEPS && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
RUN mkdir -p /app $PNPM_HOME
COPY . /app
WORKDIR /app

RUN HOME=/home/ctf pnpm install --frozen-lockfile
RUN pnpm build && rm -rf public-src

USER ctf

EXPOSE 3000
ENV NODE_ENV=production
# restart automatically
CMD [ "timeout", "--signal=SIGKILL", "10m", "pnpm", "start" ]

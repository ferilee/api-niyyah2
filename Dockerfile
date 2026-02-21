FROM oven/bun:1 AS base
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

COPY src ./src
COPY api ./api
COPY tsconfig.json ./tsconfig.json

ENV NODE_ENV=production
EXPOSE 3000

CMD ["bun", "run", "start"]

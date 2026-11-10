FROM node:26.13.0-alpine@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216 AS base
WORKDIR /app

RUN apk update && apk add --no-cache protoc protobuf-dev

COPY package.json package-lock.json ./
RUN npm ci

# Copy sources
COPY tsconfig.json ./
COPY proto ./proto
COPY src ./src

# Build
RUN npm run build


FROM node:26.13.0-alpine@sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216
WORKDIR /app
ENV NODE_ENV=production
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/dist ./dist
COPY --from=base /app/proto ./proto
ENV FETCH_LOCALHOST_REPLACEMENT=host.docker.internal

EXPOSE 50050
CMD ["node", "dist/server.js"]

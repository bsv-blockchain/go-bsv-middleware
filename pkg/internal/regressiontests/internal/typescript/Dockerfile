FROM node:24.11.0-alpine@sha256:f36fed0b2129a8492535e2853c64fbdbd2d29dc1219ee3217023ca48aebd3787 AS base
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


FROM node:24.11.0-alpine@sha256:f36fed0b2129a8492535e2853c64fbdbd2d29dc1219ee3217023ca48aebd3787
WORKDIR /app
ENV NODE_ENV=production
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/dist ./dist
COPY --from=base /app/proto ./proto
ENV FETCH_LOCALHOST_REPLACEMENT=host.docker.internal

EXPOSE 50050
CMD ["node", "dist/server.js"]

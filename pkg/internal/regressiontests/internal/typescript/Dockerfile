FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS base
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


FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
WORKDIR /app
ENV NODE_ENV=production
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/dist ./dist
COPY --from=base /app/proto ./proto
ENV FETCH_LOCALHOST_REPLACEMENT=host.docker.internal

EXPOSE 50050
CMD ["node", "dist/server.js"]

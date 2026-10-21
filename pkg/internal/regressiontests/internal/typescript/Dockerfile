FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS base
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


FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5
WORKDIR /app
ENV NODE_ENV=production
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/dist ./dist
COPY --from=base /app/proto ./proto
ENV FETCH_LOCALHOST_REPLACEMENT=host.docker.internal

EXPOSE 50050
CMD ["node", "dist/server.js"]

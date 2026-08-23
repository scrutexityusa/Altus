# Multi-stage build for the control plane.
#
# The runtime stage carries production dependencies and compiled output only:
# no source, no toolchain, no test fixtures, and no root.
FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json tsconfig.json tsconfig.build.json ./
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY services/api/package.json services/api/
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY packages ./packages
COPY services ./services
RUN pnpm exec tsc -b services/api

FROM node:22-alpine AS runtime
WORKDIR /app
RUN corepack enable && addgroup -g 10001 -S app && adduser -u 10001 -S app -G app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY services/api/package.json services/api/
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/services/api/dist services/api/dist
# No `packages/sdk/dist`. The SDK is a client library for callers; the control
# plane imports nothing from it, `tsc -b services/api` therefore never builds
# it, and `--prod` skips it (it is a root devDependency) so it is not even
# linked into node_modules here. Copying it failed the build outright once the
# image job started running at all -- the layer referred to a directory the
# build stage had no reason to produce.
# Migrations travel with the image so the migration Job and the service can
# never disagree about which schema version they expect.
COPY db ./db
COPY policies ./policies

USER app
EXPOSE 8080
ENV NODE_ENV=production
# No shell in the entrypoint: PID 1 is node, so SIGTERM reaches the drain
# handler and in-flight decisions finish before the process exits.
ENTRYPOINT ["node", "services/api/dist/server.js"]

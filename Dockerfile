FROM node:22-alpine

WORKDIR /app

# Copy application source
COPY package.json ./
COPY server.js ./
COPY lib/ ./lib/
COPY public/ ./public/
COPY scripts/ ./scripts/

# Data directory (ephemeral - wiped on redeploy)
RUN mkdir -p /data && chmod 700 /data

# Railway injects PORT at runtime; HOST must be 0.0.0.0 to accept external traffic
ENV HOST=0.0.0.0
ENV PORT=3210
ENV COCKPIT_DATA_DIR=/data
ENV COCKPIT_DISABLE_ACQUISITION=0

EXPOSE 3210

# node:sqlite requires --experimental-sqlite on Node <22.5 or Alpine builds
CMD ["node", "--experimental-sqlite", "server.js"]

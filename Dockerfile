FROM node:22.5-alpine

WORKDIR /app

# Verify node:sqlite is available
RUN node -e "require('node:sqlite')" || (echo 'node:sqlite not available' && exit 1)

# Copy package files
COPY package.json ./

# No external npm deps - pure Node.js built-ins only
RUN node -e "console.log('Node', process.version)"

# Copy application source
COPY server.js ./
COPY lib/ ./lib/
COPY public/ ./public/
COPY scripts/ ./scripts/

# Data directory (ephemeral - wiped on redeploy)
RUN mkdir -p /data && chmod 700 /data

# Railway injects PORT at runtime
ENV HOST=0.0.0.0
ENV PORT=3210
ENV COCKPIT_DATA_DIR=/data
ENV COCKPIT_DISABLE_ACQUISITION=0

EXPOSE 3210

CMD ["node", "server.js"]

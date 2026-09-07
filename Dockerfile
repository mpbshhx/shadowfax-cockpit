FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package.json ./

# Install production deps only (no devDependencies)
RUN npm install --omit=dev 2>/dev/null || npm install

# Copy application source
COPY server.js ./
COPY lib/ ./lib/
COPY public/ ./public/
COPY scripts/ ./scripts/

# Data directory (Railway volume or ephemeral)
RUN mkdir -p /data

# Railway sets PORT; cockpit must bind 0.0.0.0 on Railway (not 127.0.0.1)
ENV HOST=0.0.0.0
ENV PORT=3210
ENV COCKPIT_DATA_DIR=/data
ENV COCKPIT_DISABLE_ACQUISITION=0

# Railway injects PORT at runtime — EXPOSE is a hint only
EXPOSE 3210

CMD ["node", "server.js"]

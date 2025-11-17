FROM node:20.18.0-bookworm-slim

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./
COPY *.ts ./

RUN npm ci && npm run build

USER node

CMD ["node", "dist/index.js"]

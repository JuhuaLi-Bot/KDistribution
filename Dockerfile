FROM node:24-alpine

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY scripts ./scripts
COPY README.md DEPLOYMENT.md ./

ENV HOST=0.0.0.0
ENV PORT=3456
ENV DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 3456

CMD ["node", "src/server.js"]
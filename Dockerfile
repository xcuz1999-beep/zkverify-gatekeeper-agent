FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.mjs checks.mjs prove.mjs ./
COPY circuits/ ./circuits/
ENV PORT=7860
EXPOSE 7860
CMD ["node", "server.mjs"]

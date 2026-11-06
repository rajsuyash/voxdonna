FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.mjs session.mjs tools.mjs tickets.mjs plan.mjs pdf.mjs mail.mjs catalogue.json instructions.md ./
COPY fonts ./fonts
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]

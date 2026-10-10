FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_ENV=production DATA_DIR=/data PORT=3000 TRUST_PROXY=1
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]

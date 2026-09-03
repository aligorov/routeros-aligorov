# store-combine: бот/комбайн добавления Docker-образов в app-store RouterOS.
# Запуск (нужен доступ к репо стора и токены):
#   docker run -d --name store-combine \
#     -v /path/to/routeros-aligorov:/repo \
#     -e REPO_DIR=/repo -e STORE_BASE_URL=https://aligorov.github.io/routeros-aligorov \
#     -e TELEGRAM_BOT_TOKEN=... -e TELEGRAM_ALLOWED_IDS=... \
#     aligorov/store-combine:latest
# Для git push из контейнера см. service/README.md (Docker).
FROM node:20-alpine

WORKDIR /app
RUN apk add --no-cache git

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY tsconfig.json ./
COPY src ./src

# внутри контейнера репо стора по умолчанию ожидается в /repo (том)
ENV REPO_DIR=/repo
CMD ["npx", "tsx", "src/bot.ts"]

FROM node:11.15.0-alpine

WORKDIR /hackmd
EXPOSE 3000
ENV NODE_ENV="production"

RUN apk add --no-cache ca-certificates

COPY . .
RUN apk add --no-cache --virtual .dep build-base python git bash && \
    yarn install --pure-lockfile && \
    yarn install --production=false --pure-lockfile && \
    npm run build && \
    yarn cache clean && \
    apk del .dep

ENTRYPOINT ["npm", "run", "start"]

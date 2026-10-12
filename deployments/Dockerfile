ARG RUNTIME

FROM hackmdio/buildpack:node-10-0baafb79 as BUILD

COPY --chown=hackmd:hackmd . .

RUN set -xe && \
    git reset --hard && \
    git clean -fx && \
    npm install && \
    npm run build && \
    cp ./deployments/docker-entrypoint.sh ./ && \
    cp .sequelizerc.example .sequelizerc && \
    rm -rf .git .gitignore .travis.yml .dockerignore .editorconfig .babelrc .mailmap .sequelizerc.example \
        test docs contribute \
        package-lock.json webpack.prod.js webpack.htmlexport.js webpack.dev.js webpack.common.js \
        config.json.example README.md CONTRIBUTING.md AUTHORS node_modules

FROM $RUNTIME
USER hackmd
WORKDIR /home/hackmd/app
COPY --chown=1500:1500 --from=BUILD /home/hackmd/app .
# Node.js 10 の組み込み CA と runtime イメージの OS の CA ストアはどちらも GlobalSign Root R46 を含まず、
# この CA で発行された ConoHa の証明書を検証できない
COPY deployments/certs/GlobalSign_Root_R46.pem /usr/local/share/ca-certificates/GlobalSign_Root_R46.pem
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/GlobalSign_Root_R46.pem
RUN npm install --production && npm cache clean --force && rm -rf /tmp/{core-js-banners,phantomjs}
EXPOSE 3000
ENTRYPOINT ["/home/hackmd/app/docker-entrypoint.sh"]

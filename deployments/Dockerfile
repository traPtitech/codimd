FROM hackmdio/buildpack:1.0.2 as BUILD

WORKDIR /hackmd
COPY . .


RUN  git reset --hard && \
        git clean -fx && \
        yarn install && \
        yarn build && \
        yarn install --production=true && \
        cp ./deployments/docker-entrypoint.sh ./ && \
        cp .sequelizerc.example .sequelizerc && \
        rm -rf deployments .babelrc .dockerignore \
            .editorconfig .git .gitignore .travis.yml \
            CONTRIBUTING.md README.md config.json.example \
            webpack.* yarn.lock .sequelizerc.example

FROM hackmdio/runtime:1.0.2
USER hackmd
WORKDIR /home/hackmd/app
ENV PATH="/home/hackmd/.npm-global/bin:${PATH}"

COPY --from=BUILD --chown=hackmd:hackmd /hackmd /home/hackmd/app/

EXPOSE 3000
ENTRYPOINT ["/home/hackmd/app/docker-entrypoint.sh"]

'use strict'

const jwt = require('jsonwebtoken')
const express = require('express')
const passport = require('passport')

const config = require('../../config')
const models = require('../../models')
const logger = require('../../logger')

const AUTH_PROVIDER_IDENTIFIER = 'trap'
const REDIRECT_COOKIE = AUTH_PROVIDER_IDENTIFIER + '_auth_redirect'

passport.use({
  name: AUTH_PROVIDER_IDENTIFIER,
  authenticate (req) {
    try {
      const rawToken = req.cookies[config.trap.cookieName]
      if (!rawToken) {
        throw new Error('No token')
      }

      if (config.trap.invalidateTokens.includes(rawToken)) {
        throw new Error('Invalid token')
      }

      const info = jwt.verify(rawToken, config.trap.pubkey, {algorithms: 'RS256'})
      if (info.id === undefined) {
        throw new Error('Invalid token')
      }

      info.profile = JSON.stringify({
        id: info.id,
        provider: AUTH_PROVIDER_IDENTIFIER,
        displayName: info.firstName + ' ' + info.lastName
      })

      models.User.findOrCreate({
        where: {
          profileid: info.id
        },
        defaults: {
          email: info.email,
          profile: info.profile
        }
      }).spread((user, created) => {
        if (user) {
          let needSave = false
          if (user.email !== info.email) {
            user.email = info.email
            needSave = true
          }
          if (user.profile !== info.profile) {
            user.profile = info.profile
            needSave = true
          }
          (needSave ? user.save() : Promise.resolve()).then(_ => {
            if (config.debug) {
              logger.info('user login: ' + user.id)
            }
            this.success(user)
          })
        }
      }).catch((err) => {
        throw err
      })
    } catch (err) {
      logger.error('auth callback failed: ' + err)
      this.fail()
    }
  }
})

const router = express.Router()
router.get('/auth/' + AUTH_PROVIDER_IDENTIFIER, function (req, res, next) {
  const redirect = config.serverURL + (req.cookies[REDIRECT_COOKIE] || '/')
  res.clearCookie(REDIRECT_COOKIE)
  passport.authenticate(AUTH_PROVIDER_IDENTIFIER, {
    successReturnToOrRedirect: redirect,
    failureRedirect: 'https://q.trap.jp/login?redirect=' + encodeURIComponent(redirect)
  })(req, res, next)
})

const redir = (req, res) => {
  res.cookie(REDIRECT_COOKIE, req.path)
  res.redirect('/auth/trap')
}
const _auth = passthruCond => (req, res, next) => {
  if (passthruCond(req)) {
    return next()
  }
  redir(req, res)
}
const greedyAuth = _auth(req => req.isAuthenticated())
const generousAuth = _auth(req => req.isAuthenticated() || !req.cookies[config.trap.cookieName])

module.exports = {router, greedyAuth, generousAuth, redir}

'use strict'
var Sequelize = require('sequelize')
const Op = Sequelize.Op

var config = require('./config')
var logger = require('./logger')
var response = require('./response')
var models = require('./models')

function getNotes (userid, callback) {
  models.Note.findAll({
    where: {
      [Op.or]: [{ ownerId: userid }, { permission: { [Op.ne]: 'private' } }]
    },
    order: [['updatedAt', 'DESC']]
  }).then(notes => {
    if (config.debug) {
      logger.info('read notes success: ' + userid)
    }
    return callback(null, notes.map(note => {
      return {
        id: models.Note.encodeNoteId(note.id),
        text: note.title,
        timestamp: Date.parse(note.updatedAt)
      }
    }))
  }).catch(err => {
    logger.error('read notes failed: ' + err)
    return callback(err, null)
  })
}

function notesGet (req, res) {
  if (req.isAuthenticated()) {
    getNotes(req.user.id, function (err, notes) {
      if (err) return response.errorInternalError(res)
      if (!notes) return response.errorNotFound(res)
      res.send({notes})
    })
  } else {
    return response.errorForbidden(res)
  }
}

module.exports = {notesGet}

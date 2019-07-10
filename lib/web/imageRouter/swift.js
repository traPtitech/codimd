'use strict'
const fs = require('fs')
const path = require('path')

const config = require('../../config')
const { getImageMimeType } = require('../../utils')
const logger = require('../../logger')

const pkgcloud = require('pkgcloud')

const swift = pkgcloud.storage.createClient({
  provider: 'openstack',
  username: config.swift.username,
  password: config.swift.password,
  authUrl: config.swift.authUrl,
  region: config.swift.region,
  tenantId: config.swift.tenantId,
  container: config.swift.container
})

exports.uploadImage = function (imagePath, callback) {
  if (!imagePath || typeof imagePath !== 'string') {
    callback(new Error('Image path is missing or wrong'), null)
    return
  }

  if (!callback || typeof callback !== 'function') {
    logger.error('Callback has to be a function')
    return
  }

  let params = {
    container: config.swift.container,
    remote: path.basename(imagePath)
  }

  const mimeType = getImageMimeType(imagePath)
  if (mimeType) { params.contentType = mimeType }

  try {
    const src = fs.createReadStream(imagePath)
    const dst = swift.upload(params)

    dst.on('error', function (err) {
      callback(new Error(err), null)
    })
    dst.on('success', function (file) {
      // 保守性のためオブジェクトストレージへはリバースプロキシでリダイレクト
      callback(null, (new URL(path.basename(imagePath), config.serverURL + '/uploads/')).href)
    })

    src.pipe(dst)
  } catch (err) {
    callback(new Error(err), null)
  }
}

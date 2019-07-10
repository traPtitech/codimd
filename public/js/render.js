/* eslint-env browser, jquery */

var DOMPurify = require('dompurify')
var filterXSS = require('xss')

function preventXSS (html) {
  return DOMPurify.sanitize(html)
}
window.preventXSS = preventXSS

module.exports = {
  preventXSS: preventXSS,
  escapeAttrValue: filterXSS.escapeAttrValue
}

/* eslint-env browser, jquery */
// allow some attributes

var DOMPurify = require('dompurify')
var filterXSS = require('xss')

// https://dev.to/patarapolw/securely-embed-youtube-and-other-iframe-elements-in-markdown-2hoc
DOMPurify.addHook('uponSanitizeElement', function (node, data) {
  if (data.tagName === 'iframe') {
    var src = node.getAttribute('src') || ''
    try {
      var url = new URL(src)
      if (!url.hostname.endsWith('trap.jp')) {
        return node.remove()
      }
    } catch (e) {
      return node.remove()
    }
  }
})

function preventXSS (html) {
  return DOMPurify.sanitize(html, {
    ADD_TAGS: ["iframe"],
    ADD_ATTR: ["scrolling", "frameborder"]
  })
}
window.preventXSS = preventXSS

module.exports = {
  preventXSS: preventXSS,
  escapeAttrValue: filterXSS.escapeAttrValue
}

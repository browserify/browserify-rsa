var crypto = require('crypto')
var constants = require('constants')
var parseKey = require('parse-asn1')
var BN = require('bn.js')
var tape = require('tape')
var crt = require('../')

require('./fixtures').forEach(function (fixture, i) {
  var key = new Buffer(fixture, 'hex')
  var priv = parseKey(key)

  for (var j1 = 1; j1 < 31; ++j1) {
    tape.test('r is coprime with n ' + (i + 1) + ' run ' + j1, function (t) {
      var r = crt.getr(priv)
      t.equals(r.gcd(priv.modulus).toString(), '1', 'are coprime')
      t.end()
    })
  }

  var len = priv.modulus.byteLength()
  for (var j2 = 1; j2 < 41; ++j2) {
    tape.test('round trip key ' + (i + 1) + ' run ' + j2, function (t) {
      var r
      do {
        r = new BN(crypto.randomBytes(len))
      } while (r.cmp(priv.modulus) >= 0)
      var buf = r.toArrayLike(Buffer, 'be')
      if (buf.byteLength < priv.modulus.byteLength()) {
        var tmp = new Buffer(priv.modulus.byteLength() - buf.byteLength)
        tmp.fill(0)
        buf = Buffer.concat([tmp, buf])
      }
      var nodeEncrypt = crypto.privateDecrypt({
        padding: constants.RSA_NO_PADDING,
        key: key
      }, buf).toString('hex')
      t.equals(crt(buf, priv).toString('hex'), nodeEncrypt, 'equal encrypts')
      t.end()
    })
  }
})

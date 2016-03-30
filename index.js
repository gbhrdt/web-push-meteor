const webPush = require('web-push');
const crypto = require('crypto');
const createEcdh = require('create-ecdh');
const aes = require('browserify-aes');

// add missing buffer functions (taken from node source)
function checkInt(buffer, value, offset, ext, max, min) {
  if (!(buffer instanceof Buffer))
    throw new TypeError('"buffer" argument must be a Buffer instance');
  if (value > max || value < min)
    throw new TypeError('"value" argument is out of bounds');
  if (offset + ext > buffer.length)
    throw new RangeError('Index out of range');
}
function checkOffset(offset, ext, length) {
  if (offset + ext > length)
    throw new RangeError('Index out of range');
}
Buffer.prototype.writeUInt16BE = function(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert)
    checkInt(this, value, offset, 2, 0xffff, 0);
  this[offset] = (value >>> 8);
  this[offset + 1] = value;
  return offset + 2;
};
Buffer.prototype.writeUIntBE = function(value, offset, byteLength, noAssert) {
  value = +value;
  offset = offset >>> 0;
  byteLength = byteLength >>> 0;
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1;
    checkInt(this, value, offset, byteLength, maxBytes, 0);
  }

  var i = byteLength - 1;
  var mul = 1;
  this[offset + i] = value;
  while (--i >= 0 && (mul *= 0x100))
    this[offset + i] = (value / mul) >>> 0;

  return offset + byteLength;
};
Buffer.prototype.readUIntBE = function(offset, byteLength, noAssert) {
  offset = offset >>> 0;
  byteLength = byteLength >>> 0;
  if (!noAssert)
    checkOffset(offset, byteLength, this.length);

  var val = this[offset + --byteLength];
  var mul = 1;
  while (byteLength > 0 && (mul *= 0x100))
    val += this[offset + --byteLength] * mul;

  return val;
};

// add missing crypto functions (browserify version)
crypto.createECDH = createEcdh;
crypto.createCipheriv = aes.createCipheriv;
crypto.createDecipheriv = aes.createDecipheriv;

module.exports = webPush;

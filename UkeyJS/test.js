function toBase64(str) {
  return Buffer.from(str.normalize('NFC'), 'utf8').toString('base64');
}

function fromBase64(base64Str) {
  return Buffer.from(base64Str, 'base64').toString('utf8').normalize('NFC');
}
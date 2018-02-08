const privateDecrypt = require('crypto').privateDecrypt
const publicEncrypt = require('crypto').publicEncrypt
const constants = require('crypto').constants
const { publicKey1024, privateKey1024, publicKey2048, privateKey2048 } = require('./config/keys')

const baseLength = 512
const encryptPerLength = 128 - 11

const blockDecrypt = (privateKey) => (block) => {
  try {
    const decrypted = privateDecrypt({
      key: privateKey,
      padding: constants.RSA_PKCS1_PADDING
    }, block)
    return decrypted
  } catch (err) {
    if (block.length === 128) {
      return blockDecrypt(privateKey)(block.slice(0, 127))
    }

    throw err
  }
}

const decrypt = (privateKey, keyLength) => cipher => {
  if (!cipher) {
    throw new Error('ciper cannot be null')
  }

  let rtn = ''

  const blockDecryptFn = blockDecrypt(privateKey)
  const bufferLength = 64 * (keyLength / baseLength)
  const buffer = Buffer.from(cipher, 'base64')
  const blocks = Math.ceil(buffer.length / bufferLength)

  for (let i = 0; i < blocks; i++) {
    rtn += blockDecryptFn(buffer.slice(i * bufferLength, (i + 1) * bufferLength))
  }

  try {
    rtn = decodeURI(rtn)
    const parsedRes = JSON.parse(rtn)
    // 防止数字字符串 parse 后丢失精度
    if (typeof parsedRes === 'object') {
      rtn = parsedRes
    }
  } catch (e) {}

  return rtn
}

const encrypt = (publicKey, keyLength) => origin => {
  const bufferLength = 64 * (keyLength / baseLength)
  const buffer = Buffer.from(JSON.stringify(origin))
  const blocks = Math.ceil(buffer.length / encryptPerLength)
  const rtn = Buffer.alloc(blocks * bufferLength)
  for (let i = 0; i < blocks; i++) {
    const currentBlock = buffer.slice(encryptPerLength * i, encryptPerLength * (i + 1))
    const encryptBlock = publicEncrypt({
      key: publicKey,
      padding: constants.RSA_PKCS1_PADDING
    }, currentBlock)
    encryptBlock.copy(rtn, i * bufferLength)
  }
  return rtn.toString('base64')
}

// const text = '6230580000125073489'
const text = {"callBackType":"01","profitDate":"jdhdhd","flowNo":"hfjfkfd","outAmount":"10000","userCode":"1234567","transferTime":""}
const encryptText1024 = encrypt(publicKey1024, 1024)(text)
console.log('-----------encrypt 1024 res', encryptText1024)

const decryptText1024 = decrypt(privateKey1024, 1024)(encryptText1024)
console.log('-----------decrypt 1024 res', decryptText1024)

const encryptText2048 = encrypt(publicKey2048, 2048)(text)
console.log('-----------encrypt 2048 res', encryptText2048)

const decryptText2048 = decrypt(privateKey2048, 2048)(encryptText2048)
console.log('-----------decrypt 2048 res', decryptText2048)

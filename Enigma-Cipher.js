const crypto = require('crypto')
const base62chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

/**
 * Encode Buffer To Base62
 * Params: InputBuffer
 */
function base62EncodeBuffer(inputBuffer) {
  let numericValue = 0n
  for (const eachByte of inputBuffer) {
    numericValue = (numericValue << 8n) | BigInt(eachByte)
  }
  let outputString = ''
  if (numericValue === 0n) {
    return '0'
  } else {
    while (numericValue > 0n) {
      outputString = base62chars[numericValue % 62n] + outputString
      numericValue = numericValue / 62n
    }
  }
  return outputString.padStart(Math.ceil(inputBuffer.length * 1.37), '0')
}

/**
 * Decode Base62 To Buffer
 * Params: InputString
 */
function base62DecodeString(inputString) {
  let numericValue = 0n
  for (const eachChar of inputString) {
    numericValue = numericValue * 62n + BigInt(base62chars.indexOf(eachChar))
  }
  let outputBuffer = []
  let bufferLength = Math.floor(inputString.length / 1.37)
  while (numericValue > 0n && outputBuffer.length < 64) {
    outputBuffer.unshift(Number(numericValue & 0xFFn))
    numericValue >>= 8n
  }
  while (outputBuffer.length < bufferLength) {
    outputBuffer.unshift(0)
  }
  return Buffer.from(outputBuffer)
}

/**
 * Convert Number To Base62 String
 * Params: InputNumber
 */
function toBase62String(inputNumber) {
  let outputString = ''
  do {
    outputString = base62chars[inputNumber % 62] + outputString
    inputNumber = Math.floor(inputNumber / 62)
  } while (inputNumber > 0)
  return outputString.padStart(2, '0')
}

/**
 * Convert Base62 String To Number
 * Params: InputString
 */
function fromBase62String(inputString) {
  let resultNumber = 0
  for (const eachChar of inputString) {
    resultNumber = resultNumber * 62 + base62chars.indexOf(eachChar)
  }
  return resultNumber
}

/**
 * Shuffle Array By Seed
 * Params: InputArray, SeedArray
 */
function shuffleArrayBySeed(inputArray, seedArray) {
  let resultArray = inputArray.slice()
  let numericArray
  if (Buffer.isBuffer(seedArray)) {
    numericArray = Array.from(seedArray)
  } else if (typeof seedArray === 'bigint') {
    let tempSeed = seedArray
    numericArray = []
    while (tempSeed > 0n) {
      numericArray.unshift(Number(tempSeed & 0xFFn))
      tempSeed >>= 8n
    }
  } else {
    numericArray = Array.from(seedArray)
  }
  for (let index = resultArray.length - 1; index > 0; index--) {
    let swapIndex = numericArray[index % numericArray.length] % (index + 1)
    let tempValue = resultArray[index]
    resultArray[index] = resultArray[swapIndex]
    resultArray[swapIndex] = tempValue
  }
  return resultArray
}

/**
 * Generate Random Buffer
 * Params: Length
 */
function generateRandomBuffer(length) {
  return crypto.randomBytes(length)
}

/**
 * Generate Random Integer
 * Params: MaxNumber
 */
function generateRandomInteger(maxNumber) {
  return generateRandomBuffer(2).readUInt16BE(0) % maxNumber
}

/**
 * Derive Key By Passphrase And Purpose
 * Params: Passphrase, Purpose, Length
 */
function deriveKeyFromPassphrase(passedPhrase, passedPurpose, passedLength = 32) {
  return crypto.createHash('sha256').update(passedPhrase + ':' + passedPurpose).digest().slice(0, passedLength)
}

/**
 * Plugboard Class
 * Params: MappingPairs
 */
class Plugboard {
  constructor(mappingPairs) {
    this.mappingObject = {}
    for (const eachPair of mappingPairs) {
      if (eachPair.length === 2) {
        this.mappingObject[eachPair[0]] = eachPair[1]
        this.mappingObject[eachPair[1]] = eachPair[0]
      }
    }
  }
  swap(character) {
    return this.mappingObject[character] || character
  }
  static randomPairs(pairCount = 6) {
    const alphabetArray = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')
    const shuffledArray = shuffleArrayBySeed(alphabetArray, generateRandomBuffer(alphabetArray.length))
    let pairsArray = []
    for (let index = 0; index < pairCount * 2; index += 2) {
      if (shuffledArray[index + 1]) {
        pairsArray.push(shuffledArray[index] + shuffledArray[index + 1])
      }
    }
    return pairsArray
  }
  static serialize(pairsArray) {
    return pairsArray.join('')
  }
  static deserialize(pairString) {
    let resultPairs = []
    for (let index = 0; index < pairString.length - 1; index += 2) {
      resultPairs.push(pairString[index] + pairString[index + 1])
    }
    return resultPairs
  }
}

/**
 * Rotor Class
 * Params: WiringString, NotchIndex, RotorPosition
 */
class Rotor {
  constructor(wiringString, notchIndex, rotorPosition) {
    this.forward = wiringString
    this.backward = Array(26)
    for (let index = 0; index < 26; index++) {
      this.backward[this.forward.charCodeAt(index) - 65] = String.fromCharCode(65 + index)
    }
    this.notch = notchIndex
    this.position = rotorPosition
  }
  step() {
    this.position = (this.position + 1) % 26
  }
  encodeForward(character) {
    let characterIndex = (character.charCodeAt(0) - 65 + this.position) % 26
    return this.forward[characterIndex]
  }
  encodeBackward(character) {
    let characterIndex = (this.forward.indexOf(character) - this.position + 26) % 26
    return String.fromCharCode(65 + characterIndex)
  }
}

/**
 * Enigma Cipher Super Class
 * Params: OptionsObject
 */
class EnigmaCipherSuper {
  constructor(optionsObject = {}) {
    this.rotorWiringArray = [
      'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
      'AJDKSIRUXBLHWTMCQGZNPYFVOE',
      'BDFHJLCPRTXVZNYEIWGAKMUSQO'
    ]
    this.rotorNotchArray = [16, 4, 21]
    this.reflectorString = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
    this.hashAlgorithm = 'sha256'
    this.macLength = 8
    this.defaultSaltLength = 3
    this.plugboardPairCount = 6
    this.passphrase = optionsObject.passphrase || optionsObject.pass || null
    this.saltLengthChar = 3
    this.plugboardLengthChar = this.plugboardPairCount * 2
    this.positionLengthChar = 6
    this.orderLengthChar = 3
    this.parameterLength = this.saltLengthChar + this.plugboardLengthChar + this.positionLengthChar + this.orderLengthChar
    this.shuffleKeyLength = 11
    this.stealthMode = optionsObject.stealth || false
    this.pass = optionsObject.pass || null
  }
  /**
   * Get Rotors
   * Params: RotorPositions, WiringOrderArray
   */
  getRotors(rotorPositions, wiringOrderArray) {
    return [
      new Rotor(this.rotorWiringArray[wiringOrderArray[0]], this.rotorNotchArray[wiringOrderArray[0]], rotorPositions[0]),
      new Rotor(this.rotorWiringArray[wiringOrderArray[1]], this.rotorNotchArray[wiringOrderArray[1]], rotorPositions[1]),
      new Rotor(this.rotorWiringArray[wiringOrderArray[2]], this.rotorNotchArray[wiringOrderArray[2]], rotorPositions[2])
    ]
  }
  /**
   * Get Salt Buffer
   * Params: None
   */
  getSaltBuffer() {
    if (this.passphrase || this.pass) {
      const derivedHash = deriveKeyFromPassphrase(this.passphrase || this.pass, 'salt', 32)
      return derivedHash.slice(0, this.defaultSaltLength)
    } else {
      return generateRandomBuffer(this.defaultSaltLength)
    }
  }
  /**
   * Get Plugboard Pairs
   * Params: None
   */
  getPlugboardPairs() {
    if (this.passphrase || this.pass) {
      const derivedHash = deriveKeyFromPassphrase(this.passphrase || this.pass, 'plugboard', 32)
      const alphabetArray = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')
      const shuffledArray = shuffleArrayBySeed(alphabetArray, derivedHash)
      let pairsArray = []
      for (let index = 0; index < this.plugboardPairCount * 2; index += 2) {
        if (shuffledArray[index + 1]) {
          pairsArray.push(shuffledArray[index] + shuffledArray[index + 1])
        }
      }
      return pairsArray
    }
    return Plugboard.randomPairs(this.plugboardPairCount)
  }
  /**
   * Get Random Rotor Positions
   * Params: None
   */
  getRandomRotorPositions() {
    if (this.passphrase || this.pass) {
      const derivedHash = deriveKeyFromPassphrase(this.passphrase || this.pass, 'rotor', 32)
      return [derivedHash[0] % 26, derivedHash[1] % 26, derivedHash[2] % 26]
    }
    return [generateRandomInteger(26), generateRandomInteger(26), generateRandomInteger(26)]
  }
  /**
   * Get Random Wiring Order
   * Params: None
   */
  getRandomWiringOrder() {
    if (this.passphrase || this.pass) {
      const derivedHash = deriveKeyFromPassphrase(this.passphrase || this.pass, 'order', 32)
      return shuffleArrayBySeed([0, 1, 2], derivedHash)
    }
    return shuffleArrayBySeed([0, 1, 2], generateRandomBuffer(8))
  }
  /**
   * Clean Output String
   * Params: InputString
   */
  cleanOutputString(inputString) {
    return (inputString.match(/[0-9A-Za-z]+/g) || []).join('')
  }
  /**
   * Encrypt Plain Text
   * Params: PlainText
   */
  encrypt(plainText) {
    const saltBuffer = this.getSaltBuffer()
    const plugboardPairs = this.getPlugboardPairs()
    const rotorPositions = this.getRandomRotorPositions()
    const wiringOrder = this.getRandomWiringOrder()
    const plugboard = new Plugboard(plugboardPairs)
    const saltString = base62EncodeBuffer(saltBuffer).padEnd(this.saltLengthChar, '0').slice(0, this.saltLengthChar)
    const plugboardString = Plugboard.serialize(plugboardPairs).padEnd(this.plugboardLengthChar, 'A').slice(0, this.plugboardLengthChar)
    const positionString = rotorPositions.map(toBase62String).join('').padEnd(this.positionLengthChar, '0').slice(0, this.positionLengthChar)
    const orderString = wiringOrder.map(String).join('').padEnd(this.orderLengthChar, '0').slice(0, this.orderLengthChar)
    const parameterString = saltString + plugboardString + positionString + orderString
    const shuffleSeed = generateRandomBuffer(8)
    const shuffleKey = base62EncodeBuffer(shuffleSeed).slice(0, this.shuffleKeyLength)
    const parameterArray = parameterString.split('')
    const obfuscatedParameterArray = shuffleArrayBySeed(parameterArray, shuffleSeed)
    const obfuscatedParameterString = obfuscatedParameterArray.join('')
    let swappedPlainText = ''
    for (const character of plainText.toUpperCase()) {
      swappedPlainText += plugboard.swap(character)
    }
    const rotors = this.getRotors(rotorPositions, wiringOrder)
    let cipherText = ''
    for (const character of swappedPlainText) {
      if (!( /[A-Z]/.test(character))) {
        cipherText += character
      } else {
        rotors[2].step()
        if (rotors[2].position === rotors[2].notch) {
          rotors[1].step()
          if (rotors[1].position === rotors[1].notch) {
            rotors[0].step()
          }
        }
        let codeChar = character
        for (let index = 2; index >= 0; index--) {
          codeChar = rotors[index].encodeForward(codeChar)
        }
        codeChar = this.reflectorString[codeChar.charCodeAt(0) - 65]
        for (let index = 0; index < 3; index++) {
          codeChar = rotors[index].encodeBackward(codeChar)
        }
        cipherText += codeChar
      }
    }
    let swappedCipherText = ''
    for (const character of cipherText) {
      swappedCipherText += plugboard.swap(character)
    }
    const cipherLength = swappedCipherText.length
    const cipherEncoded = base62EncodeBuffer(Buffer.from(swappedCipherText, 'ascii'))
    const cipherLengthString = toBase62String(cipherLength).padStart(2, '0')
    let hmacKey
    if (this.passphrase) {
      hmacKey = deriveKeyFromPassphrase(this.passphrase, 'mac', 32)
    } else if (this.pass) {
      hmacKey = deriveKeyFromPassphrase(this.pass, 'mac', 32)
    } else {
      hmacKey = saltBuffer
    }
    let macString = crypto.createHmac('sha256', hmacKey)
      .update(cipherEncoded + cipherLengthString + obfuscatedParameterString + shuffleKey)
      .digest('base64').slice(0, this.macLength)
    let mainBodyString = shuffleKey + obfuscatedParameterString + cipherEncoded + cipherLengthString + macString
    if (this.stealthMode) {
      let padBuffer = generateRandomBuffer(mainBodyString.length)
      let padString = base62EncodeBuffer(padBuffer).slice(0, mainBodyString.length)
      let stealthBodyString = ''
      for (let index = 0; index < mainBodyString.length; index++) {
        stealthBodyString += base62chars[(base62chars.indexOf(mainBodyString[index]) + base62chars.indexOf(padString[index])) % 62]
      }
      mainBodyString = stealthBodyString + padString
    }
    return this.cleanOutputString(mainBodyString)
  }
  /**
   * Decrypt Cipher Text
   * Params: CipherText
   */
  decrypt(cipherText) {
    cipherText = this.cleanOutputString(cipherText)
    let mainBodyString = cipherText
    if (this.stealthMode) {
      let n = mainBodyString.length / 2
      let stealthBodyString = mainBodyString.slice(0, n)
      let padString = mainBodyString.slice(n)
      let originalString = ''
      for (let index = 0; index < n; index++) {
        let resultIndex = (base62chars.indexOf(stealthBodyString[index]) - base62chars.indexOf(padString[index]) + 62) % 62
        originalString += base62chars[resultIndex]
      }
      mainBodyString = originalString
    }
    const shuffleKey = mainBodyString.slice(0, 11)
    const shuffleSeed = base62DecodeString(shuffleKey)
    const obfuscatedParameterString = mainBodyString.slice(11, 35)
    const cipherLengthString = mainBodyString.slice(-10, -8)
    const cipherLength = fromBase62String(cipherLengthString)
    const cipherEncoded = mainBodyString.slice(35, -10)
    const macString = mainBodyString.slice(-8)
    let parameterArray = obfuscatedParameterString.split('')
    let sortedIndexArray = Array(parameterArray.length).fill(0).map((_, index) => index)
    let indexOrderArray = shuffleArrayBySeed(sortedIndexArray, shuffleSeed)
    let parameterResultArray = Array(obfuscatedParameterString.length)
    for (let index = 0; index < indexOrderArray.length; index++) {
      parameterResultArray[indexOrderArray[index]] = obfuscatedParameterString[index]
    }
    const parameterString = parameterResultArray.join('')
    let plugboardString = parameterString.slice(3, 15)
    let positionString = parameterString.slice(15, 21)
    let orderString = parameterString.slice(21, 24)
    const plugboardPairs = Plugboard.deserialize(plugboardString)
    const rotorPositions = [fromBase62String(positionString.slice(0, 2)), fromBase62String(positionString.slice(2, 4)), fromBase62String(positionString.slice(4, 6))]
    const wiringOrder = orderString.split('').map(Number)
    const plugboard = new Plugboard(plugboardPairs)
    let hmacKey
    if (this.passphrase) {
      hmacKey = deriveKeyFromPassphrase(this.passphrase, 'mac', 32)
    } else if (this.pass) {
      hmacKey = deriveKeyFromPassphrase(this.pass, 'mac', 32)
    } else {
      hmacKey = base62DecodeString(parameterString.slice(0, 3))
    }
    let macCheckString = crypto.createHmac('sha256', hmacKey)
      .update(cipherEncoded + cipherLengthString + obfuscatedParameterString + shuffleKey)
      .digest('base64').slice(0, this.macLength)
    if (macString !== macCheckString) {
      throw new Error('MAC integrity check failed!')
    }
    const decodedString = base62DecodeString(cipherEncoded).slice(0, cipherLength).toString('ascii').replace(/\0+$/, '')
    let afterPlugString = ''
    for (const character of decodedString) {
      afterPlugString += plugboard.swap(character)
    }
    const rotors = this.getRotors(rotorPositions, wiringOrder)
    let outputString = ''
    for (const character of afterPlugString) {
      if (!( /[A-Z]/.test(character))) {
        outputString += character
      } else {
        rotors[2].step()
        if (rotors[2].position === rotors[2].notch) {
          rotors[1].step()
          if (rotors[1].position === rotors[1].notch) {
            rotors[0].step()
          }
        }
        let codeChar = character
        for (let index = 2; index >= 0; index--) {
          codeChar = rotors[index].encodeForward(codeChar)
        }
        codeChar = this.reflectorString[codeChar.charCodeAt(0) - 65]
        for (let index = 0; index < 3; index++) {
          codeChar = rotors[index].encodeBackward(codeChar)
        }
        outputString += codeChar
      }
    }
    let plainString = ''
    for (const character of outputString) {
      plainString += plugboard.swap(character)
    }
    return plainString
  }
}

if (require.main === module) {
  const argumentList = process.argv.slice(2)
  let commandMode = argumentList[0]
  let stealthOption = argumentList.includes('--stealth')
  let passOptionIndex = argumentList.findIndex(eachArgument => eachArgument === '--pass')
  let passOption = passOptionIndex !== -1 ? argumentList[passOptionIndex + 1] : null
  let inputText = argumentList.slice(1).filter(argumentValue => !(argumentValue.startsWith('--')) && argumentValue !== passOption).join(' ')
  const enigmaCipher = new EnigmaCipherSuper({ pass: passOption, stealth: stealthOption })
  if (commandMode === 'encrypt') {
    console.log(enigmaCipher.encrypt(inputText))
  } else if (commandMode === 'decrypt') {
    try {
      console.log(enigmaCipher.decrypt(inputText))
    } catch (errorObject) {
      console.log('FAILED: MAC integrity check failed!')
    }
  }
}
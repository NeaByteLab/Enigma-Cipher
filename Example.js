const { execSync } = require('child_process')

/**
 * Run Shell Command And Return Output
 * Params: CommandString
 */
function runShellCommand(commandString) {
  try {
    const outputBuffer = execSync(commandString, { encoding: 'utf8' })
    return outputBuffer.trim()
  } catch (error) {
    return 'Command Failed'
  }
}

/**
 * Main Execution Example
 */
function mainExample() {
  const plainText = 'Hello Enigma - by NeaByteLab'
  const password = 'SuperSecret'
  const stealthMode = true
  console.log('Original Text:', plainText)

  // Encrypt
  const encryptCommand = `node Enigma-Cipher.js encrypt "${plainText}" --pass ${password} ${stealthMode ? '--stealth' : ''}`
  const encryptedText = runShellCommand(encryptCommand)
  console.log('Encrypted Text:', encryptedText)

  // Decrypt
  const decryptCommand = `node Enigma-Cipher.js decrypt "${encryptedText}" --pass ${password} ${stealthMode ? '--stealth' : ''}`
  const decryptedText = runShellCommand(decryptCommand)
  console.log('Decrypted Text:', decryptedText)
}

mainExample()
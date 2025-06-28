# Enigma Cipher

Advanced Enigma-style cipher engine with strong modern cryptography, fully stateless, ciphertext-only, supporting password, stealth, plugboard randomization, and MAC (message authentication code) integrity check. No meta/header required — everything is encoded in the ciphertext.

---

## Algorithm Details

- **Rotor Machine:** Uses three configurable rotors with custom wiring, position, notch, and ring setting logic inspired by the classical Enigma, but all rotor state is encoded in ciphertext (randomized each message unless using password/seed).
- **Plugboard:** Random or password-derived pairs provide extra permutation before/after the rotor chain (A-Z only).
- **Reflector:** Classic Enigma-style fixed mapping, creates a non-invertible chain for each pass.
- **MAC Integrity:** After all transformations, an HMAC-SHA256 is computed over ciphertext + encoded param to ensure tamper-proof security (using password or random salt as key).
- **Base62 Encoding:** All output is encoded using custom base62 to maximize density and printable output.
- **Stealth Mode:** If enabled, ciphertext is xored with random base62 pad, output is double-length and looks like random data.
- **Self-Contained Param:** All param (rotor position, plugboard, salt, order) is hidden inside the ciphertext, can be parsed back without any header/meta.

---

## Function/Flow

1. **Encryption**
    - Input is uppercased and swapped by the plugboard
    - Passed through 3 rotors (forward and backward), stepped on each char
    - Reflected
    - Reswapped by plugboard
    - Encoded to base62, length recorded
    - All settings (salt, plug, rotor position/order) obfuscated and encoded into ciphertext
    - MAC is computed over all relevant fields (no header)
    - In stealth mode: result is xored by random pad and output is double-length
    - Output: pure base62 string (no meta)

2. **Decryption**
    - If stealth: xor-pad decoding
    - Parse all settings from ciphertext (rotor, plug, salt, order)
    - Validate MAC over decoded fields (reject on mismatch)
    - Decode base62 to plaintext, plugboard swap
    - Reverse through rotors and plugboard
    - Output: fully reconstructed uppercase plaintext (A-Z and symbols)

---

## Code Comparison: Classic Enigma vs Enigma Cipher

| Aspect            | Classic Enigma                          | Enigma Cipher                                            |
|-------------------|-----------------------------------------|----------------------------------------------------------|
| Hardware          | Electromechanical, fixed rotors         | Pure software, stateless, random or passworded           |
| Plugboard         | Manual, fixed                           | Random or password-derived, encoded in ciphertext        |
| Rotor Selection   | Manual                                  | Random/password, embedded and recoverable from cipher    |
| Security          | Weak by modern standards                | Modern HMAC, brute-force resistant, password, MAC        |
| Key/State Storage | Physical, operator memory               | All state embedded and hidden in ciphertext              |
| Output            | Letters (A-Z) only                      | Letters/numbers, printable base62, supports symbols      |
| Integrity         | No built-in integrity                   | Tamper-proof, MAC checked before output                  |
| Mode/Replay       | Deterministic by rotor start            | Randomized each run (unless password/seed used)          |
| Meta/Header       | Not used, physical record               | No header needed—ciphertext only, all param self-coded   |
| Stealth           | Not possible                            | Output xored with random pad for deniability             |

---

## Brute-Force Security Statistic

| Attack Vector            | Parameter           | Value / Entropy                |
|--------------------------|---------------------|-------------------------------|
| Plugboard                | 6 pairs, 12 letters | 100+ billion combinations     |
| Rotor Positions          | 26 × 26 × 26        | 17,576                        |
| Rotor Wiring Order       | 3!                  | 6                             |
| Salt (random)            | 3 chars (base62)    | 238,328 possible salts        |
| Password (user set)      | 8+ chars, strong    | 62^8 = 218 trillion+          |
| Stealth Pad (if used)    | N chars random      | 62^N (very high, per char)    |
| HMAC Integrity           | 8 chars (base64)    | 2^48                          |
| Total Combined Entropy   | Plug × Rotor × ...  | >10^20 (if password strong)   |

- Brute-force attack is practically impossible with modern computing if a strong password is used.
- All security parameters are randomized and encoded for every message (unless seeded/password).

---

## Use Cases

1. **Message Encryption (Stateless)**
   ```sh
   node Enigma-Cipher.js encrypt 'Attack At Dawn'
   # Output: <base62-ciphertext>

   node Enigma-Cipher.js decrypt <base62-ciphertext>
   # Output: ATTACK AT DAWN
   ```

2. **Password-Protected Secure Channel**
   ```sh
   node Enigma-Cipher.js encrypt 'NeaByteLab Secret' --pass mySuperSecret
   # Output: <ciphertext>

   node Enigma-Cipher.js decrypt <ciphertext> --pass mySuperSecret
   # Output: NEABYTELAB SECRET
   ```

3. **Stealth Mode For Obfuscated Messages**
   ```sh
   node Enigma-Cipher.js encrypt 'Top Secret Order #123' --pass sniper --stealth
   # Output: <stealth base62>

   node Enigma-Cipher.js decrypt <stealth base62> --pass sniper --stealth
   # Output: TOP SECRET ORDER #123
   ```

4. **Integrity Fail On Wrong Password**
   ```sh
   node Enigma-Cipher.js decrypt <anycipher> --pass wrong
   # Output: FAILED: MAC integrity check failed!
   ```
---

## Research Use Guidance

- Fully open-source and transparent for cryptanalysis and academic study  
- Modular design allows easy modification of rotors, plugboard, and MAC parameters  
- Suitable for experiments on rotor-based ciphers combined with modern integrity checks  
- Not intended for production commercial use without license compliance  
- Cite NeaByteLab for any academic publication or presentation  

---

## License

Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)

- Free to use, modify, fork, study for any personal, academic, or open-source purpose
- Commercial use of any kind (selling, SaaS, company internal) is strictly **prohibited**
- Include credit to NeaByteLab if redistributed or published
- https://creativecommons.org/licenses/by-nc/4.0/
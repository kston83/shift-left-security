package demo

import java.security.MessageDigest
import javax.crypto.Cipher

// Secure counterpart of insecure.kt: must produce no findings.
fun strongCrypto() {
    val sha256 = MessageDigest.getInstance("SHA-256")
    val gcm = Cipher.getInstance("AES/GCM/NoPadding")
    println(sha256.algorithm + gcm.algorithm)
}

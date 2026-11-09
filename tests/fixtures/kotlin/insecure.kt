package demo

import java.security.MessageDigest
import javax.crypto.Cipher

// Intentionally weak crypto, test data for slsec-sast. Do not use.
fun weakCrypto() {
    val md5 = MessageDigest.getInstance("MD5")
    val sha1 = MessageDigest.getInstance("SHA-1")
    val ecb = Cipher.getInstance("AES/ECB/PKCS5Padding")
    val none = Cipher.getInstance("NULL")
}

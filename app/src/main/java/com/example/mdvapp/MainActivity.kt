package com.example.mdvapp

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow


class MainActivity : AppCompatActivity() {
    private val dataEncrypt =
        "682c56de-9b1d-4e73-a240-3887872face2 "
    private var keyStart: Int? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        //Hash : MD5
        val textMD5 = encryptMD5("Miichisoft")
        Log.d("encrypMD5", textMD5)


        val textEncrypt = "Miichisoft-mobile"
        val dataEncryptAES = encryptAES(textEncrypt, "MOBILE")
        Log.d("encryptAES", dataEncryptAES)

        val dataDeEncrypt = deCryptAES(dataEncryptAES, "MOBILE")
        Log.d("dataDeEncryptAES", dataDeEncrypt)

        val dataEncryptDES = encryptDES(textEncrypt, "MOBILE")
        Log.d("dataEncryptDES", dataEncryptDES)

        val dataDeEncryptDES = deCryptDES(dataEncryptDES, "MOBILE")
        Log.d("dataDeEncryptDES", dataDeEncryptDES)




        Log.d("eEncryptRSA", testRSA())
        Log.d("edecryptRSA", testDeCryptRSA(testRSA()))
    }

    private fun initTest() {

//        valueTest = "phuc"
//        Handler().postDelayed({
//            valueTest = "phuc sau"
//            Log.d("valueTest1:", "$valueTest")
//        }, 2000)


        val key = 9
        var text = ""
        for (i in dataEncrypt.indices) {
            val chars = dataEncrypt[i].toInt()
            var y = chars - key % 26
            when (chars) {
                in 65..90 -> {
                    keyStart = 0
                }
                in 97..122 -> {
                    keyStart = 32
                }
                else -> {
                    y = chars
                }
            }

            keyStart?.let {
                if (y > (90 + it)) {
                    y -= 26
                }
                if (y < (65 + it)) {
                    y += 26
                }
            }
            keyStart = null
            text += y.toChar()

        }
        Log.d("data", text)


    }

//    private fun encrypt(key: Int): Int {
//        //Todo : chọn p =5,q=7 => n =35 ,2(n) = 24
//        //Chọn e =5 vì UCLN(5,24)=1
//        //e*d-1 chia het cho 24 , tìm d=29
//        val result = key.toDouble().pow(5) % 35
//        return result.toInt()
//    }
//
//    private fun deEncrypt(key: Int): Int {
//        val result = key.toDouble().pow(29) % 35
//        return result.toInt()
//    }


    private fun encryptMD5(textEncrypt: String): String {
        val md5 = MessageDigest.getInstance("MD5")//SHA-256
        var sb = StringBuilder()

        val byteArray: ByteArray = md5.digest(textEncrypt.toByteArray(StandardCharsets.UTF_8))

        for (item in byteArray) {
            sb.append(String.format("%02x", item))//%02x
        }

        return sb.toString()
    }

    private fun encryptAES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-1")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
        key = sha.digest(key)
        key = key.copyOf(16)
        val secretKey = SecretKeySpec(key, "AES")//Create key
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")//Create Cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.getEncoder().encodeToString(cipher.doFinal(textEncrypt.toByteArray()))//ma hoa hay giai ma đeu thuc hien tren byte

        //chuyen byte sang dang base 64 de hien thi

//        DES = Data Encryption Standard.
//        ECB = Electronic Codebook mode.
//        PKCS5Padding = PKCS #5-style paddi
    }

    private fun deCryptAES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-1")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
        Log.d("showMyKey","${key}")
        key = sha.digest(key)
        key = key.copyOf(16)
        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(textEncrypt)
            )
        )
    }

    private fun encryptDES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-1")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
        key = sha.digest(key)
        key = key.copyOf(8)
        val secretKey = SecretKeySpec(key, "DES")//Create key
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")//Create Cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.getEncoder().encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
    }

    private fun deCryptDES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-1")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
        key = sha.digest(key)
        key = key.copyOf(8)
        val secretKey = SecretKeySpec(key, "DES")
        val cipher = Cipher.getInstance("DES/ECB/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(textEncrypt)
            )
        )
    }

    private fun testRSA(): String {
        // val spec = X509EncodedKeySpec("phucsau".toByteArray())
//        val factory = KeyFactory.getInstance("RSA")
//
//        val pubKey = factory.generatePublic(spec)
//        Log.d("pubKey","${pubKey}")
//

        val sr = SecureRandom()
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024, sr)
        val kp = kpg.genKeyPair()
        val plKey = kp.public
        val privateKey = kp.private
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, plKey)
        val textByte = cipher.doFinal("phuc".toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }

    private fun testDeCryptRSA(text: String): String {
//       val spec = RSAPrivateKeySpec()
//        val factory = KeyFactory.getInstance("RSA")
//        val prikey = factory.generatePrivate(spec)
//        val cipher = Cipher.getInstance("RSA")
//        cipher.init(Cipher.DECRYPT_MODE,prikey)
//        return String(
//            cipher.doFinal(
//                Base64.getDecoder().decode(text)))

        return ""
    }
}
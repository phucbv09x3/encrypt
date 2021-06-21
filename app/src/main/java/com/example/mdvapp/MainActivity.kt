package com.example.mdvapp

import android.os.Bundle
import android.os.Handler
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow


class MainActivity : AppCompatActivity() {
    private val dataEncrypt =
        "682c56de-9b1d-4e73-a240-3887872face2 "//682c56de-9b1d-4e73-a240-3887872face2
    private val dataEncrypt1 = "682lOPmnGSkKmGNnQMGjLNJGMRRQRQLojlnL"
    private val dataEncrypt2 = "273966486965867"
    private val dataEncrypt3 = "yarejcn odw mnNwlahyc(tnh: Rwc): Rwc {\n" +
            "            eju anbduc = tnh.cxMxdkun().yxf(29) % 35\n" +
            "            ancdaw anbduc.cxRwc()\n" +
            "        }"

    private var keyStart: Int? = null

    lateinit var valueTest: String
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val textEncrypt = "Miichisoft-mobile"
        val dataEncryptAES = encryptAES(textEncrypt, "MOBILE")
        Log.d("encryptAES", dataEncryptAES)

        val dataDeEncrypt = deEncryptAES(dataEncryptAES, "MOBILE")
        Log.d("dataDeEncryptAES", dataDeEncrypt)

        val dataEncryptDES = encryptDES(textEncrypt, "MOBILE")
        Log.d("dataEncryptDES", dataEncryptDES)

        val dataDeEncryptDES = deEncryptDES(dataEncryptDES, "MOBILE")
        Log.d("dataDeEncryptDES", dataDeEncryptDES)

    }

    private fun initTest() {
        var textMD5 = encryptMD5("phuc")
        Log.d("encrypMD5", "${textMD5}")
        valueTest = "phuc"
        Log.d("valueTest:", "$valueTest")
        Handler().postDelayed({
            valueTest = "phuc sau"
            Log.d("valueTest1:", "$valueTest")
        }, 2000)

        setContentView(R.layout.activity_main)
        val key = 9
        var text = ""
        for (i in dataEncrypt.indices) {
            val chars = dataEncrypt[i].toInt()
            var y = chars - key % 26
            when (chars) {
                in 65..90 -> {
                    Log.d("when", "when")
                    keyStart = 0
                }
                in 97..122 -> {
                    Log.d("when1", "when1")
                    keyStart = 32
                }
                else -> {
                    Log.d("when2", "when2")
                    y = chars
                }
            }

            keyStart?.let {
                if (y > (90 + it)) {
                    Log.d("when3", "when3")
                    y -= 26
                }
                if (y < (65 + it)) {
                    Log.d("when4", "when4")
                    y += 26
                }
            }
            keyStart = null
            text += y.toChar()

        }
        Log.d("when7", text)
        Log.d("whenwhen", "${(4.0.pow(29.0) % 35)}")

        Log.d("encrypt", "${encrypt(9)}")
        Log.d("encrypt1", "${deEncrypt(4)}")
        Log.d("encrypt12", "${4.0.pow(215)}")
    }

    private fun encrypt(key: Int): Int {
        //Todo : chọn p =5,q=7 => n =35 ,2(n) = 24
        //Chọn e =5 vì UCLN(5,24)=1
        //e*d-1 chia het cho 24 , tìm d=29
        val result = key.toDouble().pow(5) % 35
        return result.toInt()
    }

    private fun deEncrypt(key: Int): Int {
        val result = key.toDouble().pow(29) % 35
        return result.toInt()
    }


    private fun encryptMD5(textEncrypt: String): String {
        val md5 = MessageDigest.getInstance("SHA-256")
        var sb = StringBuilder()

        val hash: ByteArray = md5.digest(textEncrypt.toByteArray(StandardCharsets.UTF_8))

        for (byte in hash) {
            sb.append(String.format("%02x", byte))
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
        return Base64.getEncoder().encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
    }

    private fun deEncryptAES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-1")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
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
    private fun deEncryptDES(textEncrypt: String, myKey: String): String {
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
}
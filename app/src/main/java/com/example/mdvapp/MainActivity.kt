package com.example.mdvapp

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {
    private var keyNumber: Int? = null
    private val textEncrypt = "Miichisoft-mobile-present"
    private val myKey = "MOBILE"
    private val keyStoreAliasRsa = "android"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)


        val dataAfterEncryptDV = roundTranslation(textEncrypt, 0)
        Log.d("encryptDV", dataAfterEncryptDV)
        Log.d("decryptDV", roundTranslation(dataAfterEncryptDV, 1))

        //Hash
        val hashFunc = hashFunc(textEncrypt)
        Log.d("hashFunc", hashFunc)


        //AES
        val dataAfterEncryptAES = enCryptAES(textEncrypt, myKey)
        Log.d("encryptAES", dataAfterEncryptAES)
        Log.d("deEncryptAES", deCryptAES(dataAfterEncryptAES, myKey))


        //AES
//        val dataEncryptAES = encryptAES(textEncrypt, myKey)
//        Log.d("encryptAES", dataEncryptAES)
//
//        val dataDeEncrypt = deCryptAES(dataEncryptAES, myKey)
//        Log.d("dataDeEncryptAES", dataDeEncrypt)

        //DES
//        val dataEncryptDES = encryptDES(textEncrypt, myKey)
//        Log.d("dataEncryptDES", dataEncryptDES)
//
//        val dataDeEncryptDES = deCryptDES(dataEncryptDES, myKey)
//        Log.d("dataDeEncryptDES", dataDeEncryptDES)


        //RSA
        val dataAfterEncryptRSA = testEncryptRSA(textEncrypt)
        Log.d("eEncryptRSA", dataAfterEncryptRSA)
        Log.d("decryptRSA", testDeCryptRSA(dataAfterEncryptRSA))


        //AndroidKeyStore
        createKeyStore(keyStoreAliasRsa)
        val dataEncryptRSAKeyStore = encryptStringKeyStore(textEncrypt, keyStoreAliasRsa)
        Log.d("encryptString", dataEncryptRSAKeyStore)
        Log.d(
            "encryptString",
            deCryptStringKeyStore(
                dataEncryptRSAKeyStore,
                keyStoreAliasRsa
            )
        )
    }

    private fun roundTranslation(dataCrypt: String, encryptOrDecrypt: Int): String {
        val key = 9
        var text = ""
        for (i in dataCrypt.indices) {
            val chars = dataCrypt[i].toInt()
            var y = if (encryptOrDecrypt == 0) (chars + key % 26) else (chars - key % 26)
            when (chars) {
                in 65..90 -> {
                    keyNumber = 0
                }
                in 97..122 -> {
                    keyNumber = 32
                }
                else -> {
                    y = chars
                }
            }

            keyNumber?.let {
                if (y > (90 + it)) {
                    y -= 26
                }
                if (y < (65 + it)) {
                    y += 26
                }
            }
            keyNumber = null
            text += y.toChar()

        }
        return text
    }

    private fun hashFunc(textEncrypt: String): String {
        val md5 = MessageDigest.getInstance("MD5")//SHA-256
        val sb = StringBuilder()
        val byteArray: ByteArray = md5.digest(textEncrypt.toByteArray(StandardCharsets.UTF_8))
        for (item in byteArray) {
            sb.append(String.format("%02x", item))//convert to hexa
        }
        return sb.toString()
    }


//    private fun encryptAES(textEncrypt: String, myKey: String): String {
//        val sha = MessageDigest.getInstance("SHA-256")
//        var key = myKey.toByteArray(StandardCharsets.UTF_8)
//        key = sha.digest(key)
//        key = key.copyOf(16)
//        val secretKey = SecretKeySpec(key, "AES")
//        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
//        return Base64.getEncoder()
//            .encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
//    }
//
//    private fun deCryptAES(textEncrypt: String, myKey: String): String {
//        val sha = MessageDigest.getInstance("SHA-256")
//        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
//        key = sha.digest(key)
//        key = key.copyOf(16)
//        val secretKey = SecretKeySpec(key, "AES")
//        val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
//        cipher.init(Cipher.DECRYPT_MODE, secretKey)
//        return String(
//            cipher.doFinal(
//                Base64.getDecoder().decode(textEncrypt)
//            )
//        )
//    }

//    private fun encryptDES(textEncrypt: String, myKey: String): String {
//        val sha = MessageDigest.getInstance("SHA-256")
//        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
//        key = sha.digest(key)
//        key = key.copyOf(8)
//        val secretKey = SecretKeySpec(key, "DES")
//        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
//        return Base64.getEncoder().encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
//    }
//
//    private fun deCryptDES(textEncrypt: String, myKey: String): String {
//        val sha = MessageDigest.getInstance("SHA-256")
//        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
//        key = sha.digest(key)
//        key = key.copyOf(8)
//
//        val secretKey = SecretKeySpec(key, "DES")
//        Log.d("secretKey","$secretKey")
//        val cipher = Cipher.getInstance("DES/ECB/PKCS5PADDING")
//        cipher.init(Cipher.DECRYPT_MODE, secretKey)
//        return String(
//            cipher.doFinal(
//                Base64.getDecoder().decode(textEncrypt)
//            )
//        )
//    }

    private val sr = SecureRandom()
    private var privateKey: PrivateKey? = null
    private fun testEncryptRSA(textEncrypt: String): String {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024, sr)
        val kp = kpg.genKeyPair()
        val publicKey = kp.public
        privateKey = kp.private
        Log.d("privateKey", "$privateKey")

        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val textByte = cipher.doFinal(textEncrypt.toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }


    private fun testDeCryptRSA(text: String): String {
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(text)
            )
        )
    }

    private fun enCryptAES(textEncrypt: String, myKey: String): String {
        val secretKeySpec = SecretKeySpec(myKey.toByteArray().copyOf(16), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
        val byteArray = cipher.doFinal(textEncrypt.toByteArray())
        return (Base64.getEncoder().encodeToString(byteArray))
    }

    private fun deCryptAES(text: String, myKey: String): String {
        val secretKeySpec = SecretKeySpec(myKey.toByteArray().copyOf(16), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(text)
            )
        )
    }

    ////AndroidKeyStore
    private var keyStore: KeyStore? = null
    private var keyPair: KeyPair? = null
    private fun createKeyStore(keyStoreAlias: String) {
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore?.load(null)

        if (!keyStore!!.containsAlias(keyStoreAlias)) {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                keyStoreAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA1)
                .build()
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPair = keyPairGenerator.genKeyPair()
        }

    }

    private fun encryptStringKeyStore(text: String, alias: String): String {
        val publicKey = keyStore?.getCertificate(alias)?.publicKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        publicKey?.let {
            cipher.init(Cipher.ENCRYPT_MODE, it)
        }

        val textByte = cipher.doFinal(text.toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }

    private fun deCryptStringKeyStore(text: String, alias: String): String {
        val privateKeyEntry = keyStore?.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(text)
            )
        )
    }


//    private var keyStoreTest: KeyStore? = null
//    private var keySecrect: SecretKey? = null
//    private fun createTestKeyStoreAES() {
//        keyStoreTest = KeyStore.getInstance("AndroidKeyStore")
//        keyStoreTest?.load(null)
//        val keyGenerator =
//            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
//        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
//
//        keyGenerator.init(
//            KeyGenParameterSpec.Builder(
//                "keyAlias",
//                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
//            )
//                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                .setRandomizedEncryptionRequired(false)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                .build()
//        )
//        keySecrect = keyGenerator.generateKey()
//    }

//    private fun testEncrypt(text: String?): String {
//        keyStoreTest?.load(null)
//        val key1 = keyStoreTest?.getEntry("keyAlias", null) as KeyStore.SecretKeyEntry
//        val key = key1.secretKey
//        Log.d("keyNull", "${key}")
//        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
//        cipher.init(Cipher.ENCRYPT_MODE, keySecrect!!)
//        val textByte = cipher.doFinal(text?.toByteArray())
//        return Base64.getEncoder().encodeToString(textByte)
//    }
//
//    //
//    private fun testEncrypt1(text: String?): String {
//        val key1 = keyStoreTest?.getEntry("keyAlias", null) as KeyStore.SecretKeyEntry
//        val key = key1.secretKey
//        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
//        keySecrect?.let {
//            cipher.init(Cipher.DECRYPT_MODE, it, IvParameterSpec(cipher.iv))
//        }
//
//        return String(
//            cipher.doFinal(
//                Base64.getDecoder().decode(text)
//            ), StandardCharsets.UTF_8
//        )
//    }


//    private fun getKeyInfo(): String {
//        val secretKey = ((keyStoreTest?.getEntry("keyAlias", null)) as KeyStore.SecretKeyEntry)
//
////        val privateKeyBytes: ByteArray = android.util.Base64.encode(privateKey?.encoded, android.util.Base64.DEFAULT)
////        val priKeyString = String(privateKeyBytes)
//        val publicKeyBytes: ByteArray =
//            android.util.Base64.encode(secretKey.secretKey.toString().toByteArray(), android.util.Base64.DEFAULT)
//        return String(publicKeyBytes)
//    }
//    private fun getAliases() {
//        var aliasesString = ""
//        var keyAlis = arrayListOf<String>()
//        val aliases = keyStore?.aliases()
//        if (aliases != null) {
//            while (aliases.hasMoreElements()) {
//                keyAlis.add(aliases.nextElement())
//
//            }
//        }
//        Log.d("getAliases", "${keyAlis}")
//    }

}


// ECB mode là tiêu chuẩn cơ bản nhất của DES. Plaintext (văn bản hay thông tin chưa mã hóa) được chia ra thành mỗi khối 8-byte và mỗi khối 8-byte này được mã hóa, hợp lại tất cả các khối 8-byte mã hóa này thành ciphertext (văn bản hay thông tin được mã hóa) hoàn chỉnh.
//Mỗi khối 8-byte khi được mã hóa sẽ tạo ra một bộ đệm 64-bit đầu vào. Từ đó, phát sinh ra một vấn đề “nếu khối cuối cùng của plaintext không đủ 8-byte thì sao ? ”.  Bằng cách nào đó phải làm cho khối cuối cùng này phải đủ 8-byte, thì cách làm cho khối cuối cùng này đủ 8-byte được gọi là PADDING. Vấn đề của padding là “khi ciphertext được giải mã, padding phải đưa được về đúng trạng thái ban đầu”.
//Để giải quyết vấn đề về padding, công ty RSA Data Security phát triển 1 tiêu chuẩn gọi là Public Key Crytography Standard # 5 padding (viết tắt là PKCS#5 ). Cách làm việc của PKCS#5 padding như sau:
//- Nếu n là số các byte cần thêm vào khối cuối cùng, thì giá trị của mỗi byte thêm vào đó là n.
//- Nếu khối cuối cùng không cần thêm bất kỳ byte nào cả, thì một khối mới 8-byte được tạo ra và giá trị của mỗi byte là 8.

//publicKey: must use RSAPublickey or X509EncodedKeySpec
//privateKey : must RSAPrivatekey or PKCS8EncodedKeySpec
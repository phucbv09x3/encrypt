package com.example.mdvapp

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {
    private val dataEncrypt =
        "682c56de-9b1d-4e73-a240-3887872face2 "
    private var keyStart: Int? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        //tét
        createTest()
        Log.d("testEnc","${testEncrypt("phuc")}")
        Log.d("testEnca","${testEncrypt1(testEncrypt("phuc"))}")

        //Hash : MD5
        val textMD5 = hashFunc("Miichisoft")
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


        Log.d("eEncryptRSA", testEncryptRSA("phuc sau"))
        Log.d("edecryptRSA", testDeCryptRSA(testEncryptRSA("phuc sau")))

        Log.d("dichVong", "${dichVong(dataEncrypt, 0)}")
        Log.d("dichVong", "${dichVong(dichVong(dataEncrypt, 0), 1)}")



        Log.d("encryptString", encryptString("phuc", "phuctest"))
        Log.d("encryptString", deCrypt(encryptString("phuc", "phuctest"), "phuctest"))




        createKeyStore("phuctest")
        getKeyInfo("phuctest")
        getAliases()
        Log.d("getAliases", "${getKeyInfo("phuctest")}")
    }

    private fun dichVong(dataCrypt: String, encryptOrDecrypt: Int): String {

        val key = 9
        var text = ""
        for (i in dataCrypt.indices) {
            val chars = dataCrypt[i].toInt()
            var y = if (encryptOrDecrypt == 0) (chars + key % 26) else (chars - key % 26)
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
        return text
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


    private fun hashFunc(textEncrypt: String): String {
        val md5 = MessageDigest.getInstance("MD5")//SHA-256
        val sb = StringBuilder()
        //Nhận đầu vào là 1 mảng byte
        //Md5 chuoi đàu a 128 bit ==> dạng 32 số hexar
        val byteArray: ByteArray = md5.digest(textEncrypt.toByteArray(StandardCharsets.UTF_8))
        for (item in byteArray) {
            sb.append(String.format("%02x", item))//convert to hexa
        }
        return sb.toString()
    }

    //var secretKeySpec : SecretKeySpec?=null
    private fun encryptAES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-256")
        var key = myKey.toByteArray(StandardCharsets.UTF_8)
        key = sha.digest(key)
        key = key.copyOf(16)
        //secretKeySpec = SecretKeySpec(key, "AES")
        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.getEncoder()
            .encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
    }

    private fun deCryptAES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-256")
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
        val sha = MessageDigest.getInstance("SHA-256")
        var key: ByteArray = myKey.toByteArray(StandardCharsets.UTF_8)
        key = sha.digest(key)
        key = key.copyOf(8)
        val secretKey = SecretKeySpec(key, "DES")
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.getEncoder().encodeToString(cipher.doFinal(textEncrypt.toByteArray()))
    }

    private fun deCryptDES(textEncrypt: String, myKey: String): String {
        val sha = MessageDigest.getInstance("SHA-256")
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

    private val sr = SecureRandom()
    private var privateKey: PrivateKey? = null
    private fun testEncryptRSA(textEncrypt: String): String {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024, sr)
        val kp = kpg.genKeyPair()
        val publicKey = kp.public
        privateKey = kp.private

        val spec = X509EncodedKeySpec(publicKey.encoded)
        val factory = KeyFactory.getInstance("RSA")
        val pubKey = factory.generatePublic(spec)
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        val textByte = cipher.doFinal(textEncrypt.toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }


    private fun testDeCryptRSA(text: String): String {
        val spec = PKCS8EncodedKeySpec(privateKey?.encoded)
        val factory = KeyFactory.getInstance("RSA")
        val prikey = factory.generatePrivate(spec)
        Log.d("prikey","${prikey}")
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, prikey)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(text)
            )
        )
    }


    private var keyStore: KeyStore? = null
    private var keyPair: KeyPair? = null
    private fun createKeyStore(keyStoreAlias: String) {
        keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore?.load(null)

        //create Key
        if (!keyStore!!.containsAlias(keyStoreAlias)) {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                keyStoreAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA1)
                .build()
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPair = keyPairGenerator.genKeyPair()
        }

    }
    private fun getKeyInfo(alias: String): String {
        val privateKey = ((keyStore?.getEntry(alias, null)) as KeyStore.PrivateKeyEntry).privateKey
        val certificate = keyStore?.getCertificate(alias)
        val publicKey = certificate?.publicKey
//        val privateKeyBytes: ByteArray = android.util.Base64.encode(privateKey?.encoded, android.util.Base64.DEFAULT)
//        val priKeyString = String(privateKeyBytes)
        val publicKeyBytes: ByteArray =
            android.util.Base64.encode(publicKey?.encoded, android.util.Base64.DEFAULT)
        return String(publicKeyBytes)

    }

    private fun encryptString(text: String, alias: String): String {
        val publicKey = keyStore?.getCertificate(alias)?.publicKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val textByte = cipher.doFinal(text.toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }

    private fun deCrypt(text: String, alias: String): String {
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

    private fun getAliases() {
        var aliasesString = ""
        var keyAlis = arrayListOf<String>()
        val aliases = keyStore?.aliases()
        if (aliases != null) {
            while (aliases.hasMoreElements()) {
                keyAlis.add(aliases.nextElement())

            }
        }
        Log.d("getAliases", "${keyAlis}")
    }



    private var keyStoreTest : KeyStore? =null
    private fun createTest(){
        keyStoreTest = KeyStore.getInstance("AndroidKeyStore")
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        keyStoreTest?.load(null)
        keyGenerator.init(
            KeyGenParameterSpec.Builder("keyAlias",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setDigests(KeyProperties.DIGEST_SHA1)
                .build()
        )
        keyGenerator.generateKey()

    }

    private fun testEncrypt(text : String) : String{
        keyStoreTest?.load(null)
        val key1 = keyStoreTest?.getEntry("keyAlias",null) as KeyStore.SecretKeyEntry
        val key = key1.secretKey
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE,key)
        val textByte = cipher.doFinal(text.toByteArray())
        return Base64.getEncoder().encodeToString(textByte)
    }
    private fun testEncrypt1(text: String) : String{
        val key1 = keyStoreTest?.getEntry("keyAlias",null) as KeyStore.SecretKeyEntry
        val key = key1.secretKey
        val spect= IvParameterSpec(text.toByteArray())
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,key,spect)
        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(text)
            )
        )
    }



}


// ECB mode là tiêu chuẩn cơ bản nhất của DES. Plaintext (văn bản hay thông tin chưa mã hóa) được chia ra thành mỗi khối 8-byte và mỗi khối 8-byte này được mã hóa, hợp lại tất cả các khối 8-byte mã hóa này thành ciphertext (văn bản hay thông tin được mã hóa) hoàn chỉnh.
//Mỗi khối 8-byte khi được mã hóa sẽ tạo ra một bộ đệm 64-bit đầu vào. Từ đó, phát sinh ra một vấn đề “nếu khối cuối cùng của plaintext không đủ 8-byte thì sao ? ”.  Bằng cách nào đó phải làm cho khối cuối cùng này phải đủ 8-byte, thì cách làm cho khối cuối cùng này đủ 8-byte được gọi là PADDING. Vấn đề của padding là “khi ciphertext được giải mã, padding phải đưa được về đúng trạng thái ban đầu”.
//Để giải quyết vấn đề về padding, công ty RSA Data Security phát triển 1 tiêu chuẩn gọi là Public Key Crytography Standard # 5 padding (viết tắt là PKCS#5 ). Cách làm việc của PKCS#5 padding như sau:
//- Nếu n là số các byte cần thêm vào khối cuối cùng, thì giá trị của mỗi byte thêm vào đó là n.
//- Nếu khối cuối cùng không cần thêm bất kỳ byte nào cả, thì một khối mới 8-byte được tạo ra và giá trị của mỗi byte là 8.

//publicKey: must use RSAPublickey or X509EncodedKeySpec
//privateKey : must RSAPrivatekey or PKCS8EncodedKeySpec
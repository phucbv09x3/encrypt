package com.example.mdvapp

import android.R.attr.y
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {
    private val dataEncrypt = "9"//682c56de-9b1d-4e73-a240-3887872face2
    private val dataEncrypt1 = "PRLlOPmnGSkKmGNnQMGjLNJGMRRQRQLojlnL"
     var keyStart : Int? =null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Log.d("check","${54.0.toChar()}")
        val key = 9
        var text = ""
        for (i in dataEncrypt.indices) {

            var chars = dataEncrypt[i].toInt()
            var y = chars + key % 26


            when (chars) {

                in 65..90 -> {
                    Log.d("when","when")
                    keyStart = 0
                }
                in 97..122 -> {
                    Log.d("when1","when1")
                    keyStart = 32
                }
                else -> {
                    Log.d("when2","when2")
                    y = chars
                }
            }

            if (y > (90 + keyStart!!)) {
                Log.d("when3","when3")
                y -= 26
            }
            if (y < (65 + keyStart!!)) {
                Log.d("when4","when4")
                y += 26
            }


            text += y.toChar()
            Log.d("when8", "${y}")
        }
        Log.d("when7", "${text}")
    }
}
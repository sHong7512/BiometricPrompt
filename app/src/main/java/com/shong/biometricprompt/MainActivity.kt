package com.shong.biometricprompt

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    val TAG = this::class.java.simpleName + "_sHong"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val packageManager : PackageManager = applicationContext.packageManager
        Log.d(TAG,"finger available? ${packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)}")
        Log.d(TAG,"face available? ${packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)}")
        Log.d(TAG,"iris available? ${packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)}")

        findViewById<Button>(R.id.fingerAndCryptoButton).setOnClickListener {
            startActivity(Intent(this,FingerAndCryptoActivity::class.java))
        }
        findViewById<Button>(R.id.fingerAndFaceButton).setOnClickListener {
            startActivity(Intent(this,FingerFaceCredentialActivity::class.java))
        }
    }

}
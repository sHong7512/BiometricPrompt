package com.shong.biometricprompt

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.*
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.util.*
import java.util.concurrent.Executor

class FingerFaceCredentialActivity : AppCompatActivity() {
    val TAG = this::class.java.simpleName + "_sHong"
    val REQUEST_CODE = 1

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    // biometric은 지문을 기본적으로 사용해야하고, 설정을 요청할 수 있음
    // 하지만 WEAK(face id)는 설정을 요청할 수 없음 (2021.09.07)
    // 아마 기기마다 달라서 그런듯
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_finger_face_credential)

        val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
        val mainKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)

        val encryptedSharedPrefsFile: String = "FILE_NAME"
        val encryptedSharedPreferences: SharedPreferences = EncryptedSharedPreferences.create(
            encryptedSharedPrefsFile,
            mainKeyAlias,
            applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        val resultLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
            object : ActivityResultCallback<ActivityResult?> {
                override fun onActivityResult(result: ActivityResult?) {
                    if (result?.getResultCode() == Activity.RESULT_OK) {
                        val intent: Intent = result.getData()!!
                        val CallType: Int = intent.getIntExtra("CallType", 0)

                        Log.d(TAG, "result $CallType")
                    }
                }
            })

        val biometricManager = BiometricManager.from(this)
        val authNameBS = "BIOMETRIC_STRONG_WEAK" //fingerprint : class 3, face id : class 2
        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                //생체 인증 가능
                Log.d(TAG + "_$authNameBS", "App can authenticate using biometrics.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                //기기에서 지원하지 않음
                Log.e(TAG + "_$authNameBS", "No biometric features available on this device.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                //하드웨어에서 현재 생체인증을 사용할 수 없음
                Log.e(TAG + "_$authNameBS", "Biometric features are currently unavailable.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // 생체 인식 정보가 등록되지 않은경우
                // Prompts the user to create credentials that your app accepts.
                Log.d(
                    TAG + "_$authNameBS",
                    "Prompts the user to create credentials that your app accepts."
                )
                if(Build.VERSION.SDK_INT < 29){
                    val intent = Intent(Settings.ACTION_FINGERPRINT_ENROLL)
                    startActivityForResult(intent, 1)
                }else{
                    Settings.ACTION_BIOMETRIC_ENROLL
                    val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                        putExtra(
                            Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                            BIOMETRIC_STRONG
                        )
                    }
                    enrollIntent.putExtra("CallType", 1)
                    resultLauncher.launch(enrollIntent)
                }
            }
            else -> {
                Log.d(
                    TAG + "_$authNameBS", "else in ${
                        biometricManager.canAuthenticate(
                            BiometricManager.Authenticators.BIOMETRIC_STRONG
                        )
                    }"
                )
            }
        }

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("<Title>")
            .setSubtitle("<SubTitle>")
            .setDescription("<description>")
//             Can't call setNegativeButtonText() and
//             setAllowedAuthenticators(... or DEVICE_CREDENTIAL) at the same time.
//            .setNegativeButtonText("취소")
            .setConfirmationRequired(true)
            .setAllowedAuthenticators(BIOMETRIC_WEAK or DEVICE_CREDENTIAL)
            .build()

        executor = ContextCompat.getMainExecutor(this)
        findViewById<Button>(R.id.fingerAndFaceAndCredental_Login).setOnClickListener {
            biometricPrompt = BiometricPrompt(this, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        super.onAuthenticationError(errorCode, errString)
                        Toast.makeText(
                            applicationContext,
                            "Authentication error: $errString", Toast.LENGTH_SHORT
                        )
                            .show()
                    }

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)

                        Toast.makeText(
                            applicationContext,
                            "Authentication succeeded!",
                            Toast.LENGTH_SHORT
                        ).show()
                        val pw = findViewById<EditText>(R.id.setPasswordEditText).text.toString()
                        with(encryptedSharedPreferences.edit()) {
                            // Edit the user's shared preferences...
                            putString("password", pw)
                            apply()
                        }

                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        Toast.makeText(
                            applicationContext, "Authentication failed",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                })

            biometricPrompt.authenticate(promptInfo)
        }

        findViewById<Button>(R.id.fingerAndFaceAndCredental_GetPassword).setOnClickListener {
            biometricPrompt = BiometricPrompt(this, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        super.onAuthenticationError(errorCode, errString)
                        Toast.makeText(
                            applicationContext,
                            "Authentication error: $errString", Toast.LENGTH_SHORT
                        )
                            .show()
                    }

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)

                        Toast.makeText(
                            applicationContext,
                            "Authentication succeeded!",
                            Toast.LENGTH_SHORT
                        ).show()

                        findViewById<TextView>(R.id.getPasswordTextView).text =
                            encryptedSharedPreferences.getString("password", "default")
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        Toast.makeText(
                            applicationContext, "Authentication failed",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                })

            biometricPrompt.authenticate(promptInfo)
        }

    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        Log.d(TAG, "result $resultCode")
    }
}
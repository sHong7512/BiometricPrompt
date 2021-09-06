package com.shong.biometricprompt

import android.app.Activity
import android.content.Intent
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import org.w3c.dom.Text
import java.nio.charset.Charset
import java.security.KeyStore
import java.util.*
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class FingerAndCryptoActivity : AppCompatActivity() {
    val TAG = this::class.java.simpleName + "_sHong"
    val REQUEST_CODE = 1
    private val pref: Preferences by lazy {
        Preferences(applicationContext)
    }

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_finger_and_crypto)

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
        val authNameBS = "BIOMETRIC_STRONG" //fingerprint   <- class 3
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
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
                            BiometricManager.Authenticators.BIOMETRIC_STRONG
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
            .setNegativeButtonText("취소")
//            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setConfirmationRequired(true)
            .build()

        executor = ContextCompat.getMainExecutor(this)

        findViewById<Button>(R.id.finger_Login).setOnClickListener {
            try {
                generateSecretKey(
                    KeyGenParameterSpec.Builder(
                        "password",
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        .setInvalidatedByBiometricEnrollment(true)
                        .build()
                )

                val cipher = getCipher()
                val secretKey = getSecretKey()
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)

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

                            val encryptedInfo: ByteArray =
                                result.cryptoObject?.cipher?.doFinal(
                                    findViewById<EditText>(R.id.setPasswordEditText_F).text.toString()
                                        .toByteArray(Charset.defaultCharset())
                                )
                                    ?: return
                            Log.d(TAG, "Encrypted information: " + Arrays.toString(encryptedInfo))

                            val iv: ByteArray = result.cryptoObject?.cipher?.iv ?: return
                            val ivBase64String = Base64.encodeToString(iv, Base64.NO_WRAP)
                            val pwBase64String =
                                Base64.encodeToString(encryptedInfo, Base64.NO_WRAP)
                            pref.setBioIv(ivBase64String)
                            pref.setBioPassword(pwBase64String)
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            Toast.makeText(
                                applicationContext, "Authentication failed",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    })

                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(cipher)
                )

            } catch (e: Exception) {
                Log.e(TAG, "등록된 지문이 없음! : $e")
            }

        }

        findViewById<Button>(R.id.Finger_GetPassword).setOnClickListener {
            val cipher = getCipher()
            val secretKey = getSecretKey()

            try {
                val base64Iv = pref.getBioIv()
                val base64Pw = pref.getBioPassword()

                val ivByte = Base64.decode(base64Iv, Base64.NO_WRAP)
                val pwByte = Base64.decode(base64Pw, Base64.NO_WRAP)

                cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(ivByte!!))

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
                            try {

                                val pw = result.cryptoObject?.cipher?.doFinal(pwByte) ?: byteArrayOf()
                                Log.d(TAG, "Decrypted information: ${String(pw, Charsets.UTF_8)}")
                                findViewById<TextView>(R.id.getPasswordTextView_F).text = String(pw, Charsets.UTF_8)
                            } catch (e: Exception) {
                                Log.d(TAG, "$e")
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

                biometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(cipher)
                )
            } catch (e: Exception) {
                Log.e(TAG, "No shared data!\n $e")
            }
        }
    }


    private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null)
        return keyStore.getKey("password", null) as SecretKey
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        Log.d(TAG, "result $resultCode")
    }
}
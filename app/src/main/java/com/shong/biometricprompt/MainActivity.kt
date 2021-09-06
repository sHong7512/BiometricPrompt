package com.shong.biometricprompt

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.nio.charset.Charset
import java.security.KeyStore
import java.util.*
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {
    val TAG = this::class.java.simpleName + "_sHong"
    val REQUEST_CODE = 1

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private val pref : Preferences by lazy {
        Preferences(applicationContext)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val resultLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
            object : ActivityResultCallback<ActivityResult?> {
                override fun onActivityResult(result: ActivityResult?) {
                    if (result?.getResultCode() == Activity.RESULT_OK) {
                        val intent: Intent = result.getData()!!
                        val CallType: Int = intent.getIntExtra("CallType", 0)
                        if (CallType == 0) {
                            Log.d(TAG, "result $CallType")
                        } else if (CallType == 1) {
                            Log.d(TAG, "result $CallType")
                        } else if (CallType == 2) {
                            Log.d(TAG, "result $CallType")
                        }
                    }
                }
            })

        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                //생체 인증 가능
                Log.d("MY_APP_TAG", "App can authenticate using biometrics.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                //기기에서 지원하지 않음
                Log.e("MY_APP_TAG", "No biometric features available on this device.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                //하드웨어에서 현재 생체인증을 사용할 수 없음
                Log.e("MY_APP_TAG", "Biometric features are currently unavailable.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // 생체 인식 정보가 등록되지 않은경우
                // Prompts the user to create credentials that your app accepts.
                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                    putExtra(
                        Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                        BIOMETRIC_STRONG or DEVICE_CREDENTIAL
                    )
                }
                intent.putExtra("CallType", REQUEST_CODE)
                resultLauncher.launch(enrollIntent)
            }
            else -> {
                Log.d(TAG, "else in ${biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)}")
            }
        }

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app <Title>")
            .setSubtitle("Log in using your biometric credential <SubTitle>")
//             Can't call setNegativeButtonText() and
//             setAllowedAuthenticators(... or DEVICE_CREDENTIAL) at the same time.
//            .setNegativeButtonText("Neg Btn")
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()

        var iv : ByteArray? = null
        var encryptedInfo: ByteArray? = null
        executor = ContextCompat.getMainExecutor(this)
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

                    Toast.makeText(applicationContext, "Authentication succeeded!", Toast.LENGTH_SHORT).show()

                    encryptedInfo = result.cryptoObject?.cipher?.doFinal("abcd".toByteArray(Charset.defaultCharset())) ?: return
                    Log.d(TAG, "Encrypted information: " + Arrays.toString(encryptedInfo))

                    iv = result.cryptoObject?.cipher?.iv
                    val ivBase64String = Base64.encodeToString(iv, Base64.NO_WRAP)
                    val pwBase64String = Base64.encodeToString(encryptedInfo, Base64.NO_WRAP)
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

        findViewById<Button>(R.id.biometric_GetPassword).setOnClickListener {
            val cipher = getCipher()
            val secretKey = getSecretKey()

            try{
                val base64Iv = pref.getBioIv()
                val base64Pw = pref.getBioPassword()

                val iv = Base64.decode(base64Iv, Base64.NO_WRAP)
                val pw = Base64.decode(base64Pw, Base64.NO_WRAP)

                cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv!!))
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

                            Toast.makeText(applicationContext, "Authentication succeeded!", Toast.LENGTH_SHORT).show()
                            try{
                                Log.d(TAG, "Decrypted information: " + String(result.cryptoObject?.cipher?.doFinal(pw)!!,Charsets.UTF_8))
                            }catch (e: Exception){
                                Log.d(TAG,"$e")
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
            }catch (e: Exception){
                Log.d(TAG,"No shared data!\n $e")
            }

        }

        val biometricLoginButton = findViewById<Button>(R.id.biometric_login)
        biometricLoginButton.setOnClickListener {
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
            biometricPrompt.authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(cipher)
            )
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
}
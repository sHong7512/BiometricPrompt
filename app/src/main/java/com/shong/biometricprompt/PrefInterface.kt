package com.shong.biometricprompt

interface PrefInterface{
    fun setBioPassword(pwd: String)
    fun getBioPassword(): String

    fun setBioIv(iv: String)
    fun getBioIv(): String
}
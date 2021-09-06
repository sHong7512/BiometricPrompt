package com.shong.biometricprompt

import android.content.Context
import android.content.SharedPreferences


class Preferences(context : Context) : PrefInterface{
    private val pref : SharedPreferences = context.getSharedPreferences("test", Context.MODE_PRIVATE)

    override fun setBioPassword(pwd: String) = pref.edit().putString("pwd",pwd).apply()

    override fun getBioPassword(): String = pref.getString("pwd","")!!

    override fun setBioIv(iv: String) = pref.edit().putString("iv", iv).apply()

    override fun getBioIv(): String = pref.getString("iv", "")!!
}
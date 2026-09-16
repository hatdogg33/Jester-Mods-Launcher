package com.moodtools.hub.nativebridge

object NativeLinker {
    @JvmStatic
    fun load(nativePath: String, packageName: String): Boolean = true

    @JvmStatic
    fun unload() {}

    @JvmStatic
    fun inspectRuntime(): Int = 0
}

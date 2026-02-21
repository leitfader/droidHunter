package android.util

import java.util.Base64 as JBase64

/**
 * Minimal JVM stub for android.util.Base64 to avoid android.jar "Stub!" runtime.
 * Supports the methods used by gplayapi; ignores line-wrapping flags.
 */
object Base64 {
    const val DEFAULT = 0
    const val NO_PADDING = 1 shl 0
    const val NO_WRAP = 1 shl 1
    const val CRLF = 1 shl 2
    const val URL_SAFE = 1 shl 3

    @JvmStatic
    fun decode(str: String, flags: Int): ByteArray =
        decoder(flags).decode(str)

    @JvmStatic
    fun decode(input: ByteArray, flags: Int): ByteArray =
        decoder(flags).decode(input)

    @JvmStatic
    fun encodeToString(input: ByteArray, flags: Int): String =
        encoder(flags).encodeToString(input)

    @JvmStatic
    fun encode(input: ByteArray, flags: Int): ByteArray =
        encoder(flags).encode(input)

    private fun decoder(flags: Int): JBase64.Decoder =
        if ((flags and URL_SAFE) != 0) JBase64.getUrlDecoder() else JBase64.getDecoder()

    private fun encoder(flags: Int): JBase64.Encoder {
        var enc = if ((flags and URL_SAFE) != 0) JBase64.getUrlEncoder() else JBase64.getEncoder()
        if ((flags and NO_PADDING) != 0) {
            enc = enc.withoutPadding()
        }
        // NO_WRAP/CRLF are ignored; java.util.Base64 doesn't line-wrap by default.
        return enc
    }
}

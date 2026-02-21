package android.util

/**
 * Minimal JVM stub for android.util.Log to avoid runtime "Stub!" errors from android.jar.
 * Logs to stdout/stderr and returns 0 like the Android API.
 */
object Log {
    const val VERBOSE = 2
    const val DEBUG = 3
    const val INFO = 4
    const val WARN = 5
    const val ERROR = 6
    const val ASSERT = 7

    @JvmStatic fun v(tag: String?, msg: String?): Int = println(VERBOSE, tag, msg, null)
    @JvmStatic fun v(tag: String?, msg: String?, tr: Throwable?): Int = println(VERBOSE, tag, msg, tr)
    @JvmStatic fun d(tag: String?, msg: String?): Int = println(DEBUG, tag, msg, null)
    @JvmStatic fun d(tag: String?, msg: String?, tr: Throwable?): Int = println(DEBUG, tag, msg, tr)
    @JvmStatic fun i(tag: String?, msg: String?): Int = println(INFO, tag, msg, null)
    @JvmStatic fun i(tag: String?, msg: String?, tr: Throwable?): Int = println(INFO, tag, msg, tr)
    @JvmStatic fun w(tag: String?, msg: String?): Int = println(WARN, tag, msg, null)
    @JvmStatic fun w(tag: String?, msg: String?, tr: Throwable?): Int = println(WARN, tag, msg, tr)
    @JvmStatic fun w(tag: String?, tr: Throwable?): Int = println(WARN, tag, null, tr)
    @JvmStatic fun e(tag: String?, msg: String?): Int = println(ERROR, tag, msg, null)
    @JvmStatic fun e(tag: String?, msg: String?, tr: Throwable?): Int = println(ERROR, tag, msg, tr)
    @JvmStatic fun wtf(tag: String?, msg: String?): Int = println(ASSERT, tag, msg, null)
    @JvmStatic fun wtf(tag: String?, tr: Throwable?): Int = println(ASSERT, tag, null, tr)
    @JvmStatic fun wtf(tag: String?, msg: String?, tr: Throwable?): Int = println(ASSERT, tag, msg, tr)

    @JvmStatic fun isLoggable(tag: String?, level: Int): Boolean = true

    @JvmStatic fun println(priority: Int, tag: String?, msg: String?): Int =
        println(priority, tag, msg, null)

    private fun println(priority: Int, tag: String?, msg: String?, tr: Throwable?): Int {
        val level = when (priority) {
            VERBOSE -> "V"
            DEBUG -> "D"
            INFO -> "I"
            WARN -> "W"
            ERROR -> "E"
            ASSERT -> "A"
            else -> priority.toString()
        }
        val safeTag = tag ?: "null"
        val safeMsg = msg ?: "null"
        val output = if (tr != null) {
            "$safeMsg\n${tr.stackTraceToString()}"
        } else {
            safeMsg
        }
        kotlin.io.println("$level/$safeTag: $output")
        return 0
    }
}

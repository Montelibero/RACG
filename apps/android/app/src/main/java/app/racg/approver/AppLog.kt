package app.racg.approver

import java.io.File
import java.time.Instant
import java.util.ArrayDeque

/** Diagnostics ring buffer shown on the in-app log screen, persisted to disk
 * (item 9.5): a crash no longer wipes the trace, and the default uncaught-
 * exception handler installed by [installCrashHandler] appends full stack
 * traces before the process dies. Never contains private keys: only request/
 * response outcomes and errors. */
object AppLog {
    private const val MAX_ENTRIES = 4000
    private const val MAX_FILE_BYTES = 512L * 1024

    data class Entry(val time: Instant, val message: String)

    private val entries = ArrayDeque<Entry>(MAX_ENTRIES)
    private var logFile: File? = null

    /** Must be called once from the activity before any logging matters. */
    fun init(filesDir: File) {
        if (logFile != null) return
        val file = File(filesDir, "racg-approver.log")
        logFile = file
        if (file.exists() && file.length() > MAX_FILE_BYTES) rotate(file)
        // Reload the persisted tail so a fresh process still shows history.
        if (file.exists()) {
            runCatching {
                file.readLines().takeLast(MAX_ENTRIES).forEach { line ->
                    val sep = line.indexOf("  ")
                    if (sep > 0) {
                        runCatching {
                            Entry(Instant.parse(line.substring(0, sep)), line.substring(sep + 2))
                        }.onSuccess { synchronized(entries) { entries.addLast(it) } }
                    }
                }
            }
        }
    }

    fun log(message: String) {
        val entry = Entry(Instant.now(), message)
        synchronized(entries) {
            if (entries.size >= MAX_ENTRIES) entries.pollFirst()
            entries.addLast(entry)
        }
        android.util.Log.d("RACG", message)
        persist("${entry.time}  ${entry.message}")
    }

    fun error(e: Exception, context: String) {
        log("ERROR $context: ${e::class.java.simpleName}: ${e.message}")
    }

    private fun persist(line: String) {
        val file = logFile ?: return
        runCatching {
            synchronized(this) {
                if (file.length() > MAX_FILE_BYTES) rotate(file)
                file.appendText(line + "\n")
            }
        }
    }

    private fun rotate(file: File) {
        runCatching {
            val lines = file.readLines()
            file.writeText(lines.takeLast(lines.size / 2).joinToString("\n", postfix = "\n"))
        }
    }

    /** Writes an uncaught exception with stack trace; call the previous
     * handler afterwards so the system crash flow stays intact. */
    fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            val sw = java.io.StringWriter()
            throwable.printStackTrace(java.io.PrintWriter(sw))
            val file = logFile
            runCatching {
                file?.appendText("${Instant.now()}  FATAL on ${thread.name}: $throwable\n$sw\n")
            }
            previous?.uncaughtException(thread, throwable)
        }
    }

    fun snapshot(): List<Entry> = synchronized(entries) { entries.toList() }

    /** Rendered log text; null sinceHours means the whole buffer. */
    fun text(sinceHours: Double?): String {
        val list = snapshot()
        val filtered = if (sinceHours == null) {
            list
        } else {
            val cutoff = Instant.now().minusSeconds((sinceHours * 3600).toLong())
            list.filter { it.time.isAfter(cutoff) }
        }
        return filtered.joinToString("\n") { "${it.time}  ${it.message}" }
    }
}

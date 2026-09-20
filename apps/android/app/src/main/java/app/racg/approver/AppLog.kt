package app.racg.approver

import java.time.Instant
import java.util.ArrayDeque

/** In-memory diagnostics ring buffer shown on the in-app log screen.
 * Never contains private keys: only request/response outcomes and errors. */
object AppLog {
    private const val MAX_ENTRIES = 4000

    data class Entry(val time: Instant, val message: String)

    private val entries = ArrayDeque<Entry>(MAX_ENTRIES)

    fun log(message: String) {
        val entry = Entry(Instant.now(), message)
        synchronized(entries) {
            if (entries.size >= MAX_ENTRIES) entries.pollFirst()
            entries.addLast(entry)
        }
    }

    fun error(e: Exception, context: String) {
        log("ERROR $context: ${e::class.java.simpleName}: ${e.message}")
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

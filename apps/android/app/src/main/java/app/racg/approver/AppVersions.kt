package app.racg.approver

/** Semver comparison ported from internal/version/compare.go (Go). Returns
 * -1, 0, or 1 when [a] is older than, equal to, or newer than [b]. */
object AppVersions {
    fun compare(a: String, b: String): Int {
        val (aCore, aPre) = splitVersion(a)
        val (bCore, bPre) = splitVersion(b)
        compareNumericParts(aCore, bCore).let { if (it != 0) return it }
        if (aPre.isEmpty() && bPre.isNotEmpty()) return 1
        if (aPre.isNotEmpty() && bPre.isEmpty()) return -1
        return comparePrerelease(aPre, bPre)
    }

    private fun splitVersion(value: String): Pair<List<String>, String> {
        var rest = value.trim().removePrefix("v")
        rest = rest.substringBefore('+')
        val dash = rest.indexOf('-')
        val core: String
        val pre: String
        if (dash >= 0) {
            core = rest.substring(0, dash)
            pre = rest.substring(dash + 1)
        } else {
            core = rest
            pre = ""
        }
        return Pair(core.split('.'), pre)
    }

    private fun compareNumericParts(a: List<String>, b: List<String>): Int {
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val av = numericPart(a, i)
            val bv = numericPart(b, i)
            if (av > bv) return 1
            if (av < bv) return -1
        }
        return 0
    }

    private fun numericPart(parts: List<String>, index: Int): Int =
        parts.getOrNull(index)?.toIntOrNull() ?: 0

    private fun comparePrerelease(a: String, b: String): Int {
        val aParts = a.split('.')
        val bParts = b.split('.')
        for (i in 0 until minOf(aParts.size, bParts.size)) {
            val av = aParts[i].toIntOrNull()
            val bv = bParts[i].toIntOrNull()
            when {
                av != null && bv != null && av != bv -> return if (av < bv) -1 else 1
                av != null && bv == null -> return -1
                av == null && bv != null -> return 1
                aParts[i] < bParts[i] -> return -1
                aParts[i] > bParts[i] -> return 1
            }
        }
        return aParts.size.compareTo(bParts.size)
    }
}

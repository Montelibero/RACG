package app.racg.approver

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Client-side self-update: checks GitHub releases for a newer approver
 * APK, verifies its SHA-256 against the published checksum, and hands the
 * file to the system package installer. Mirrors the CLI updater
 * (internal/cli/update.go): same repo, same release assets, same
 * never-block, report-only philosophy. */
object AppUpdater {
    const val DEFAULT_REPO = "Montelibero/RACG"
    private const val API_BASE = "https://api.github.com"

    data class CheckResult(
        val currentVersion: String,
        val latestVersion: String,
        val updateAvailable: Boolean,
        val apkUrl: String?,
        val checksumUrl: String?,
        val error: String? = null,
    )

    /** Query the latest GitHub release and locate this app's APK assets. */
    suspend fun checkUpdate(repo: String = DEFAULT_REPO): CheckResult {
        return withContext(Dispatchers.IO) {
            val current = BuildConfig.VERSION_NAME
            try {
                val release = httpJson("$API_BASE/repos/$repo/releases/latest")
                val releaseTag = release.optString("tag_name", "")
                val tag = releaseTag.removePrefix("v")
                if (tag.isEmpty()) {
                    return@withContext CheckResult(current, "", false, null, null, "release has no tag")
                }
                var apkUrl: String? = null
                var checksumUrl: String? = null
                val assets = release.optJSONArray("assets")
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        val name = asset.optString("name", "")
                        val url = asset.optString("browser_download_url", "")
                        // Release assets carry the raw tag with its "v"
                        // prefix (racg-approver-v0.6.2.apk).
                        when {
                            name == "racg-approver-$releaseTag.apk" -> apkUrl = url
                            name == "racg-approver-$releaseTag.apk.sha256" -> checksumUrl = url
                        }
                    }
                }
                if (apkUrl == null) {
                    return@withContext CheckResult(current, tag, false, null, null, "release $tag has no approver APK")
                }
                CheckResult(
                    currentVersion = current,
                    latestVersion = tag,
                    updateAvailable = AppVersions.compare(tag, current) > 0,
                    apkUrl = apkUrl,
                    checksumUrl = checksumUrl,
                )
            } catch (e: Exception) {
                CheckResult(current, "", false, null, null, e.message ?: "network error")
            }
        }
    }

    /** Download the APK plus its checksum file and verify the hash. Returns
     * the verified local file, or throws with the reason. */
    suspend fun downloadVerified(context: Context, apkUrl: String, checksumUrl: String?): File {
        return withContext(Dispatchers.IO) {
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            val apk = File(dir, "racg-approver-update.apk")
            downloadTo(apkUrl, apk)
            if (checksumUrl != null) {
                val sumFile = File(dir, "update.apk.sha256")
                downloadTo(checksumUrl, sumFile)
                val want = sumFile.readText().trim().split(Regex("\\s+")).firstOrNull()?.lowercase()
                if (!want.isNullOrBlank()) {
                    val got = sha256Hex(apk)
                    if (!got.equals(want, ignoreCase = true)) {
                        apk.delete()
                        throw IllegalStateException("checksum mismatch: APK damaged or tampered")
                    }
                }
            }
            apk
        }
    }

    /** Hand a downloaded APK to the system installer. Requires the user to
     * have granted "install unknown apps" for this app once. */
    fun installApk(context: Context, apk: File) {
        val uri: Uri = FileProvider.getUriForFile(context, context.packageName + ".updates", apk)
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            data = uri
            flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        context.startActivity(intent)
    }

    private fun httpJson(url: String): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        try {
            if (conn.responseCode !in 200..299) {
                throw IllegalStateException("GitHub API returned ${conn.responseCode}")
            }
            return JSONObject(conn.inputStream.bufferedReader().readText())
        } finally {
            conn.disconnect()
        }
    }

    private fun downloadTo(url: String, target: File) {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 30_000
        try {
            if (conn.responseCode !in 200..299) {
                throw IllegalStateException("download failed: HTTP ${conn.responseCode}")
            }
            conn.inputStream.use { input -> target.outputStream().use { output -> input.copyTo(output) } }
        } finally {
            conn.disconnect()
        }
    }

    private fun sha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

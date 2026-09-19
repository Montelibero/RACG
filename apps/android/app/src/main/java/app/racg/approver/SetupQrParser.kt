package app.racg.approver

import java.net.URI
import java.util.Base64
import org.json.JSONObject

data class SetupPayload(
    val serverId: String,
    val serverPublicKey: ByteArray,
    val approverId: String,
    val endpoint: String,
    val enrollmentToken: ByteArray?,
    val transferToken: ByteArray? = null,
    val transferDeviceId: String? = null,
    val transferGrantChallenge: ByteArray? = null,
)

/** Parses a QR produced by trusted desktop administration. It never accepts
 * identity data from broker traffic. */
object SetupQrParser {
    const val KIND = "racg.approver.setup"
    private const val TOKEN_VERSION = 2
    private const val TRANSFER_VERSION = 3
    private const val ED25519_KEY_BYTES = 32

    fun parse(raw: String): SetupPayload {
        val value = JSONObject(raw)
        val version = value.getInt("v")
        require(version in 1..TRANSFER_VERSION) { "Unsupported setup QR version" }
        require(value.getString("kind") == KIND) { "This QR code is not an approver setup" }

        val serverId = value.requireText("server_id")
        val approverId = value.requireText("approver_id")
        val endpoint = value.requireText("endpoint")
        val serverKey = decodeKey(value.requireText("server_public_key"))
        val token = if (version == TOKEN_VERSION) {
            decodeKey(value.requireText("enrollment_token"))
        } else {
            null
        }
        val transferToken = if (version == TRANSFER_VERSION) {
            decodeKey(value.requireText("transfer_token"))
        } else {
            null
        }
        val transferDeviceId = if (version == TRANSFER_VERSION) {
            value.requireText("new_device_id")
        } else {
            null
        }
        val transferGrantChallenge = if (version == TRANSFER_VERSION) {
            decodeKey(value.requireText("grant_challenge"))
        } else {
            null
        }

        val uri = try {
            URI(endpoint)
        } catch (_: Exception) {
            throw IllegalArgumentException("Setup QR endpoint is invalid")
        }
        require(uri.scheme == "tcp") { "Setup QR requires a TCP endpoint" }
        require(!uri.host.isNullOrBlank()) { "Setup QR endpoint has no host" }
        require(uri.port != -1) { "Setup QR endpoint has no port" }
        require(uri.rawQuery == null && uri.rawFragment == null) {
            "Setup QR endpoint must not contain query or fragment"
        }

        return SetupPayload(
            serverId = serverId,
            serverPublicKey = serverKey,
            approverId = approverId,
            endpoint = endpoint,
            enrollmentToken = token,
            transferToken = transferToken,
            transferDeviceId = transferDeviceId,
            transferGrantChallenge = transferGrantChallenge,
        )
    }

    private fun JSONObject.requireText(name: String): String {
        val value = getString(name).trim()
        require(value.isNotEmpty()) { "Setup QR field $name is required" }
        return value
    }

    private fun decodeKey(value: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Setup QR public key is invalid")
        }
        require(decoded.size == ED25519_KEY_BYTES) { "Setup QR public key is invalid" }
        return decoded
    }
}

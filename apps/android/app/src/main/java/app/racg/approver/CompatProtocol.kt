package app.racg.approver

import java.security.MessageDigest

/** Canonical message builders for the server's /v1/approver wire protocol.
 * Fields are NUL-separated and must match the Go side byte-for-byte. */
object CompatProtocol {
    private const val PAIRING_DOMAIN = "racg/approver/pairing/v1"
    private const val POLL_DOMAIN = "racg/approver/poll/v1"
    private const val DECISION_DOMAIN = "racg/approver/decision/v1"

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }

    fun pairingMessage(
        serverId: String,
        deviceId: String,
        publicKeySha256Hex: String,
        challenge: String,
        tokenSha256Hex: String,
    ): ByteArray = message(PAIRING_DOMAIN, serverId, deviceId, publicKeySha256Hex, challenge, tokenSha256Hex)

    fun pollMessage(
        serverId: String,
        deviceId: String,
        path: String,
        challenge: String,
    ): ByteArray = message(POLL_DOMAIN, serverId, deviceId, path, challenge)

    fun decisionMessage(
        serverId: String,
        deviceId: String,
        requestId: String,
        operationSha256: String,
        decision: String,
        challenge: String,
    ): ByteArray = message(DECISION_DOMAIN, serverId, deviceId, requestId, operationSha256, decision, challenge)

    private fun message(vararg parts: String): ByteArray =
        parts.joinToString("\u0000").toByteArray(Charsets.UTF_8)
}

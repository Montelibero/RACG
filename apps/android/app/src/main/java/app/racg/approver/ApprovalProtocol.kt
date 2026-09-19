package app.racg.approver

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

const val APPROVAL_VERSION = 1

data class ApprovalRequest(
    val version: Int,
    val serverId: String,
    val requestId: String,
    val clientId: String,
    val sessionId: String,
    val operation: ByteArray,
    val challenge: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ApprovalRequest) return false
        return version == other.version && serverId == other.serverId &&
            requestId == other.requestId && clientId == other.clientId &&
            sessionId == other.sessionId && operation.contentEquals(other.operation) &&
            challenge.contentEquals(other.challenge)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + serverId.hashCode()
        result = 31 * result + requestId.hashCode()
        result = 31 * result + clientId.hashCode()
        result = 31 * result + sessionId.hashCode()
        result = 31 * result + operation.contentHashCode()
        result = 31 * result + challenge.contentHashCode()
        return result
    }
}

data class SignedApprovalRequest(val request: ApprovalRequest, val signature: ByteArray)

data class ApprovalRequestList(
    val version: Int,
    val serverId: String,
    val deviceId: String,
    val challenge: ByteArray,
    val validUntil: String,
)

data class SignedApprovalRequestList(val list: ApprovalRequestList, val signature: ByteArray)

data class ApprovalRequestListResult(
    val listSha256: String,
    val requests: List<SignedApprovalRequest>,
)

data class SignedApprovalRequestListResult(
    val result: ApprovalRequestListResult,
    val signature: ByteArray,
)

data class ApprovalDecision(
    val version: Int,
    val requestSha256: String,
    val deviceId: String,
    val action: String,
    val validUntil: String,
)

data class SignedApprovalDecision(val decision: ApprovalDecision, val signature: ByteArray)

data class ApprovalDecisionReceipt(
    val version: Int,
    val serverId: String,
    val requestId: String,
    val requestSha256: String,
    val deviceId: String,
    val action: String,
    val status: String,
    val challenge: ByteArray,
)

data class SignedApprovalDecisionReceipt(val receipt: ApprovalDecisionReceipt, val signature: ByteArray)

data class DecisionSubmission(
    val requestId: String,
    val decision: SignedApprovalDecision,
    val challenge: ByteArray,
)

/**
 * Byte-compatible codec for the Go approval protocol. Signatures cover exact
 * encoding/json output, including declaration field order and HTML escaping.
 */
object ApprovalProtocol {
    private const val PREFIX = "RACG/approval/v1/"
    private const val KEY_BYTES = 32
    private const val SIGNATURE_BYTES = 64

    fun newRequestList(
        serverId: String,
        deviceId: String,
        now: Instant,
        lifetimeSeconds: Long = 60,
    ): ApprovalRequestList = ApprovalRequestList(
        version = APPROVAL_VERSION,
        serverId = serverId,
        deviceId = deviceId,
        challenge = randomBytes(),
        validUntil = now.plusSeconds(lifetimeSeconds).toString(),
    )

    fun signRequestList(
        list: ApprovalRequestList,
        privateKey: Ed25519PrivateKeyParameters,
    ): SignedApprovalRequestList {
        validateRequestList(list)
        return SignedApprovalRequestList(
            list = list,
            signature = sign(message("request-list", encodeRequestList(list)), privateKey),
        )
    }

    fun requestDigest(request: ApprovalRequest): String {
        validateRequest(request)
        return sha256Hex(message("request", encodeRequest(request)))
    }

    fun verifyRequest(
        signed: SignedApprovalRequest,
        serverId: String,
        serverKey: Ed25519PublicKeyParameters,
    ) {
        validateRequest(signed.request)
        require(signed.request.serverId == serverId) { "Request server identity mismatch" }
        verify(
            serverKey,
            message("request", encodeRequest(signed.request)),
            signed.signature,
        ) { "Request server signature is invalid" }
    }

    fun signDecision(
        request: ApprovalRequest,
        deviceId: String,
        action: String,
        validUntil: Instant,
        privateKey: Ed25519PrivateKeyParameters,
    ): SignedApprovalDecision {
        validateRequest(request)
        require(deviceId.isNotBlank()) { "Decision device identity is required" }
        require(action == "ALLOW_ONCE" || action == "DENY") { "Unsupported mobile decision action" }
        val decision = ApprovalDecision(
            version = APPROVAL_VERSION,
            requestSha256 = requestDigest(request),
            deviceId = deviceId,
            action = action,
            validUntil = validUntil.toString(),
        )
        return SignedApprovalDecision(
            decision = decision,
            signature = sign(message("decision", encodeDecision(decision)), privateKey),
        )
    }

    fun verifyRequestListResult(
        list: ApprovalRequestList,
        signedResult: SignedApprovalRequestListResult,
        serverKey: Ed25519PublicKeyParameters,
        now: Instant,
    ): List<SignedApprovalRequest> {
        validateRequestList(list)
        require(now.isBefore(Instant.parse(list.validUntil))) { "Pending list expired" }
        val expectedDigest = sha256Hex(message("request-list", encodeRequestList(list)))
        require(signedResult.result.listSha256 == expectedDigest) {
            "Pending list response does not match the poll"
        }
        verify(
            serverKey,
            message("request-list-result", encodeRequestListResult(signedResult.result)),
            signedResult.signature,
        ) { "Pending list server signature is invalid" }

        val seen = mutableSetOf<String>()
        signedResult.result.requests.forEach { signed ->
            verifyRequest(signed, list.serverId, serverKey)
            require(seen.add(signed.request.requestId)) { "Duplicate pending request" }
        }
        return signedResult.result.requests
    }

    fun verifyDecisionReceipt(
        request: ApprovalRequest,
        decision: SignedApprovalDecision,
        signedReceipt: SignedApprovalDecisionReceipt,
        challenge: ByteArray,
        deviceKey: Ed25519PublicKeyParameters,
        serverKey: Ed25519PublicKeyParameters,
        now: Instant,
    ) {
        validateRequest(request)
        require(
            decision.decision.version == APPROVAL_VERSION && decision.decision.deviceId.isNotBlank(),
        ) { "Invalid decision identity or version" }
        require(
            decision.decision.action == "ALLOW_ONCE" || decision.decision.action == "DENY",
        ) { "Unsupported mobile decision action" }
        require(now.isBefore(Instant.parse(decision.decision.validUntil))) {
            "Decision expired before sending"
        }
        verify(
            deviceKey,
            message("decision", encodeDecision(decision.decision)),
            decision.signature,
        ) { "Device decision signature is invalid" }

        val receipt = signedReceipt.receipt
        val digest = requestDigest(request)
        val expectedStatus = when (decision.decision.action) {
            "ALLOW_ONCE" -> "AUTHORIZED"
            else -> "DENIED"
        }
        require(challenge.size == KEY_BYTES && receipt.challenge.contentEquals(challenge)) {
            "Receipt challenge mismatch"
        }
        require(
            receipt.serverId == request.serverId && receipt.requestId == request.requestId &&
                receipt.requestSha256 == digest && receipt.deviceId == decision.decision.deviceId &&
                receipt.action == decision.decision.action && receipt.status == expectedStatus,
        ) { "Receipt does not match the submitted decision" }
        verify(
            serverKey,
            message("decision-receipt", encodeDecisionReceipt(receipt)),
            signedReceipt.signature,
        ) { "Authority receipt signature is invalid" }
    }

    fun decodeSignedRequest(raw: JSONObject): SignedApprovalRequest {
        val body = requireObject(raw, "request")
        return SignedApprovalRequest(
            request = ApprovalRequest(
                version = body.getInt("version"),
                serverId = body.requireString("server_id"),
                requestId = body.requireString("request_id"),
                clientId = body.requireString("client_id"),
                sessionId = body.requireString("session_id"),
                operation = body.decodeBase64("operation"),
                challenge = body.decodeBase64("challenge"),
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeRequestList(raw: JSONObject): ApprovalRequestList = ApprovalRequestList(
        version = raw.getInt("version"),
        serverId = raw.requireString("server_id"),
        deviceId = raw.requireString("device_id"),
        challenge = raw.decodeBase64("challenge"),
        validUntil = raw.requireString("valid_until"),
    )

    fun decodeSignedRequestList(raw: JSONObject): SignedApprovalRequestList {
        val list = requireObject(raw, "list")
        return SignedApprovalRequestList(
            list = decodeRequestList(list),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeSignedRequestListResult(raw: JSONObject): SignedApprovalRequestListResult {
        val result = requireObject(raw, "result")
        val requests = result.getJSONArray("requests")
        return SignedApprovalRequestListResult(
            result = ApprovalRequestListResult(
                listSha256 = result.requireString("list_sha256"),
                requests = List(requests.length()) { decodeSignedRequest(requests.getJSONObject(it)) },
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeSignedDecision(raw: JSONObject): SignedApprovalDecision {
        val decision = requireObject(raw, "decision")
        return SignedApprovalDecision(
            decision = ApprovalDecision(
                version = decision.getInt("version"),
                requestSha256 = decision.requireString("request_sha256"),
                deviceId = decision.requireString("device_id"),
                action = decision.requireString("action"),
                validUntil = decision.requireString("valid_until"),
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeSignedDecisionReceipt(raw: JSONObject): SignedApprovalDecisionReceipt {
        val receipt = requireObject(raw, "receipt")
        return SignedApprovalDecisionReceipt(
            receipt = ApprovalDecisionReceipt(
                version = receipt.getInt("version"),
                serverId = receipt.requireString("server_id"),
                requestId = receipt.requireString("request_id"),
                requestSha256 = receipt.requireString("request_sha256"),
                deviceId = receipt.requireString("device_id"),
                action = receipt.requireString("action"),
                status = receipt.requireString("status"),
                challenge = receipt.decodeBase64("challenge"),
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun encodeWireRequest(id: Long, method: String, params: String): String =
        jsonObject {
            number("version", APPROVAL_VERSION)
            number("id", id)
            text("method", method)
            raw("params", params)
        }

    internal fun encodeRequest(value: ApprovalRequest): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("request_id", value.requestId)
        text("client_id", value.clientId)
        text("session_id", value.sessionId)
        base64("operation", value.operation)
        base64("challenge", value.challenge)
    }

    internal fun encodeRequestList(value: ApprovalRequestList): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("device_id", value.deviceId)
        base64("challenge", value.challenge)
        text("valid_until", value.validUntil)
    }

    internal fun encodeSignedRequestList(value: SignedApprovalRequestList): String = jsonObject {
        raw("list", encodeRequestList(value.list))
        base64("signature", value.signature)
    }

    internal fun encodeRequestListResult(value: ApprovalRequestListResult): String = jsonObject {
        text("list_sha256", value.listSha256)
        raw("requests", value.requests.joinToString(",", "[", "]") { encodeSignedRequest(it) })
    }

    internal fun encodeDecision(value: ApprovalDecision): String = jsonObject {
        number("version", value.version)
        text("request_sha256", value.requestSha256)
        text("device_id", value.deviceId)
        text("action", value.action)
        text("valid_until", value.validUntil)
    }

    internal fun encodeSignedDecision(value: SignedApprovalDecision): String = jsonObject {
        raw("decision", encodeDecision(value.decision))
        base64("signature", value.signature)
    }

    internal fun encodeDecisionSubmission(value: DecisionSubmission): String = jsonObject {
        text("request_id", value.requestId)
        raw("decision", encodeSignedDecision(value.decision))
        base64("challenge", value.challenge)
    }

    internal fun encodeDecisionReceipt(value: ApprovalDecisionReceipt): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("request_id", value.requestId)
        text("request_sha256", value.requestSha256)
        text("device_id", value.deviceId)
        text("action", value.action)
        text("status", value.status)
        base64("challenge", value.challenge)
    }

    internal fun encodeSignedDecisionReceipt(value: SignedApprovalDecisionReceipt): String = jsonObject {
        raw("receipt", encodeDecisionReceipt(value.receipt))
        base64("signature", value.signature)
    }

    internal fun encodeSignedRequest(value: SignedApprovalRequest): String = jsonObject {
        raw("request", encodeRequest(value.request))
        base64("signature", value.signature)
    }

    fun sha256Hex(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    internal fun escape(value: String): String {
        val output = StringBuilder(value.length + 16)
        output.append('"')
        value.forEach { char ->
            when (char) {
                '"' -> output.append("\\\"")
                '\\' -> output.append("\\\\")
                '\b' -> output.append("\\b")
                '\t' -> output.append("\\t")
                '\n' -> output.append("\\n")
                '\u000C' -> output.append("\\f")
                '\r' -> output.append("\\r")
                '<' -> output.append("\\u003c")
                '>' -> output.append("\\u003e")
                '&' -> output.append("\\u0026")
                ' ' -> output.append("\\u2028")
                ' ' -> output.append("\\u2029")
                else -> {
                    if (char.code < 0x20) output.append("\\u%04x".format(char.code)) else output.append(char)
                }
            }
        }
        output.append('"')
        return output.toString()
    }

    private fun validateRequest(value: ApprovalRequest) {
        require(value.version == APPROVAL_VERSION) { "Unsupported approval protocol version" }
        require(
            value.serverId.isNotBlank() && value.requestId.isNotBlank() && value.clientId.isNotBlank(),
        ) { "Missing request identity" }
        require(value.challenge.size == KEY_BYTES) { "Invalid approval challenge" }
        runCatching { JSONTokener(String(value.operation, Charsets.UTF_8)).nextValue() }
            .onFailure { throw IllegalArgumentException("Operation must contain valid JSON") }
    }

    private fun validateRequestList(value: ApprovalRequestList) {
        require(value.version == APPROVAL_VERSION) { "Unsupported pending list version" }
        require(value.serverId.isNotBlank() && value.deviceId.isNotBlank()) {
            "Invalid pending list identity"
        }
        require(value.challenge.size == KEY_BYTES) { "Invalid pending list challenge" }
        runCatching { Instant.parse(value.validUntil) }
            .onFailure { throw IllegalArgumentException("Invalid pending list validity") }
    }

    private fun message(domain: String, encoded: String): ByteArray =
        (PREFIX + domain + '\u0000').toByteArray(Charsets.UTF_8) +
            encoded.toByteArray(Charsets.UTF_8)

    private fun sign(message: ByteArray, privateKey: Ed25519PrivateKeyParameters): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun verify(
        publicKey: Ed25519PublicKeyParameters,
        message: ByteArray,
        signature: ByteArray,
        failure: () -> String,
    ) {
        require(signature.size == SIGNATURE_BYTES) { failure() }
        val verifier = Ed25519Signer()
        verifier.init(false, publicKey)
        verifier.update(message, 0, message.size)
        require(verifier.verifySignature(signature)) { failure() }
    }

    private fun randomBytes(): ByteArray = ByteArray(KEY_BYTES).also { SecureRandom().nextBytes(it) }

    private inline fun jsonObject(content: JsonWriter.() -> Unit): String {
        val writer = JsonWriter()
        writer.content()
        return writer.toString()
    }

    private class JsonWriter {
        private val output = ByteArrayOutputStream()
        private var first = true

        init {
            output.write('{'.code)
        }

        fun text(name: String, value: String) = field(name, escape(value))

        fun number(name: String, value: Long) = field(name, value.toString())

        fun number(name: String, value: Int) = field(name, value.toString())

        fun base64(name: String, value: ByteArray) =
            field(name, escape(Base64.getEncoder().encodeToString(value)))

        fun raw(name: String, value: String) = field(name, value)

        private fun field(name: String, encodedValue: String) {
            if (!first) output.write(','.code)
            first = false
            output.write(escape(name).toByteArray(Charsets.UTF_8))
            output.write(':'.code)
            output.write(encodedValue.toByteArray(Charsets.UTF_8))
        }

        override fun toString(): String = output.toString(Charsets.UTF_8) + "}"
    }

    private fun requireObject(value: JSONObject, name: String): JSONObject {
        val child = value.optJSONObject(name)
        require(child != null) { "Protocol field $name is required" }
        return child
    }

    private fun JSONObject.requireString(name: String): String {
        val value = getString(name)
        require(value.isNotEmpty()) { "Protocol field $name is required" }
        return value
    }

    private fun JSONObject.decodeBase64(name: String): ByteArray = try {
        Base64.getDecoder().decode(getString(name))
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Protocol field $name is invalid")
    }
}

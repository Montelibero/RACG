package app.racg.approver

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject

data class PhonePendingRequest(
    val id: String,
    val clientId: String,
    val operation: String,
    val operationSha256: String,
    val createdAt: String,
)

/** Client for the server's signed /v1/approver API. Reads and decisions are
 * authenticated by the device's non-exportable approval key; the one-time
 * enrollment token is used during pairing and never stored afterwards. */
class PhoneClient(private val endpoint: String, private val timeoutMillis: Int = 10_000) {
    private val baseUrl = endpoint.trimEnd('/')

    fun challenge(): String {
        val response = call("GET", "/v1/approver/challenge")
        return response.getString("challenge")
    }

    fun pair(
        deviceId: String,
        publicKey: ByteArray,
        pollPublicKey: ByteArray,
        tokenSha256Hex: String,
        challenge: String,
        signature: String,
    ) {
        val input = JSONObject()
            .put("device_id", deviceId)
            .put("public_key", Base64.encodeToString(publicKey, Base64.NO_WRAP))
            .put("poll_public_key", Base64.encodeToString(pollPublicKey, Base64.NO_WRAP))
            .put("token_sha256", tokenSha256Hex)
            .put("challenge", challenge)
            .put("signature", signature)
        call("POST", "/v1/approver/pairing", input)
    }

    fun pending(
        serverId: String,
        deviceId: String,
        signer: AndroidKeystoreDeviceSigner,
    ): List<PhonePendingRequest> {
        val response = signedCall(serverId, deviceId, signer, "GET", "/v1/approver/requests")
        val array = response.getJSONArray("requests")
        return List(array.length()) { index ->
            val value = array.getJSONObject(index)
            PhonePendingRequest(
                id = value.getString("id"),
                clientId = value.optString("client_id"),
                operation = value.getString("op"),
                operationSha256 = value.getString("op_sha256"),
                createdAt = value.optString("created_at"),
            )
        }
    }

    fun decide(
        serverId: String,
        deviceId: String,
        signer: AndroidKeystoreDeviceSigner,
        input: PhoneDecisionInput,
    ) {
        val challenge = challenge()
        val message = CompatProtocol.decisionMessage(
            serverId = serverId,
            deviceId = deviceId,
            requestId = input.requestId,
            operationSha256 = input.operationSha256,
            decision = input.decision,
            challenge = challenge,
        )
        val body = JSONObject()
            .put("device_id", deviceId)
            .put("request_id", input.requestId)
            .put("decision", input.decision)
            .put("operation_sha256", input.operationSha256)
            .put("challenge", challenge)
            .put("signature", Base64.encodeToString(signer.sign(message), Base64.NO_WRAP))
        input.rulePatterns?.takeIf { it.isNotEmpty() }?.let { patterns ->
            body.put("rule_patterns", JSONArray(patterns))
        }
        input.ruleDuration?.takeIf { it.isNotBlank() }?.let { body.put("rule_duration", it) }
        call("POST", "/v1/approver/decision", body)
    }

    /** Scope candidates for the timed-grant dialog (item 13): poll-key signed
     * read, no biometrics. */
    fun scopeCandidates(
        serverId: String,
        deviceId: String,
        signer: AndroidKeystoreDeviceSigner,
        requestId: String,
    ): List<String> {
        val response = signedCall(
            serverId, deviceId, signer, "GET",
            "/v1/approver/requests/$requestId/scope",
        )
        val array = response.optJSONArray("candidates") ?: return emptyList()
        return List(array.length()) { i -> array.getJSONObject(i).optString("pattern") }
    }

    /** Recent decisions from every source — phone, TUI, auto-rules (item 16).
     * Poll-key signed read, no biometrics. */
    fun history(
        serverId: String,
        deviceId: String,
        signer: AndroidKeystoreDeviceSigner,
    ): List<PhoneHistoryEntry> {
        val response = signedCall(serverId, deviceId, signer, "GET", "/v1/approver/history")
        val array = response.getJSONArray("history")
        return List(array.length()) { i ->
            val value = array.getJSONObject(i)
            PhoneHistoryEntry(
                requestId = value.getString("request_id"),
                decision = value.getString("decision"),
                decisionSource = value.optString("decision_source"),
                decidedAt = value.optString("decided_at"),
                ruleId = value.optString("rule_id", null as String?),
                clientId = value.optString("client_id", null as String?),
                status = value.optString("status", null as String?),
                operation = value.optJSONObject("op")?.toString() ?: value.optString("op"),
            )
        }
    }

    fun signedCall(
        serverId: String,
        deviceId: String,
        signer: AndroidKeystoreDeviceSigner,
        method: String,
        path: String,
    ): JSONObject {
        val challenge = challenge()
        val message = CompatProtocol.pollMessage(serverId, deviceId, path, challenge)
        val connection = open(method, path)
        connection.setRequestProperty("X-Racg-Approver-Device", deviceId)
        connection.setRequestProperty("X-Racg-Approver-Challenge", challenge)
        connection.setRequestProperty(
            "X-Racg-Approver-Signature",
            Base64.encodeToString(signer.sign(message), Base64.NO_WRAP),
        )
        return read(connection)
    }

    fun adminPost(
        serverId: String,
        deviceId: String,
        path: String,
        body: JSONObject,
    ): JSONObject {
        // Path-bound signature header like a poll, JSON body carrying the
        // admin action; the body itself is signed as part of the message.
        val connection = open("POST", path)
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        val output = connection.outputStream
        output.write(body.toString().toByteArray(Charsets.UTF_8))
        output.flush()
        return read(connection)
    }

    private fun call(method: String, path: String, body: JSONObject? = null): JSONObject {
        val connection = open(method, path)
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            val output = connection.outputStream
            output.write(body.toString().toByteArray(Charsets.UTF_8))
            output.flush()
        }
        return read(connection)
    }

    private fun open(method: String, path: String): HttpURLConnection =
        (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMillis
            readTimeout = timeoutMillis
        }

    private fun read(connection: HttpURLConnection): JSONObject {
        val status = try {
            connection.responseCode
        } catch (e: Exception) {
            AppLog.error(e, "${connection.requestMethod} ${connection.url.path}")
            throw e
        }
        AppLog.log("${connection.requestMethod} ${connection.url.path} -> $status")
        val stream = if (status in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream
        }
        val raw = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()

        if (status !in 200..299) {
            AppLog.log("${connection.url.path} body: $raw")
            throw IllegalArgumentException("Approver API returned $status: $raw")
        }
        return JSONObject(raw)
    }
}

data class PhoneDecisionInput(
    val requestId: String,
    val decision: String,
    val operationSha256: String,
    val rulePatterns: List<String>? = null,
    val ruleDuration: String? = null,
)

fun usesCompatibilityApi(endpoint: String): Boolean {
    val scheme = URL(endpoint).protocol.lowercase()
    return scheme == "http" || scheme == "https"
}

// Reads are authenticated by the device's poll key (no user-auth requirement,
// item 9.6/9.7): the background watcher and the approvals screen must work
// without biometrics. Decisions keep using the biometry-bound approval key.
fun pendingCompatibilityRequests(setup: StoredSetup): List<PhonePendingRequest> {
    val signer = DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)
    return PhoneClient(setup.payload.endpoint)
        .pending(setup.payload.serverId, setup.payload.approverId, signer)
}

fun decideCompatibilityRequest(
    setup: StoredSetup,
    requestId: String,
    decision: String,
    operationSha256: String,
    rulePatterns: List<String>? = null,
    ruleDuration: String? = null,
) {
    val signer = DeviceKeyManager.approvalSigner(setup.approvalKeyMaterial.publicKey)
    PhoneClient(setup.payload.endpoint)
        .decide(
            setup.payload.serverId,
            setup.payload.approverId,
            signer,
            PhoneDecisionInput(
                requestId = requestId,
                decision = decision,
                operationSha256 = operationSha256,
                rulePatterns = rulePatterns,
                ruleDuration = ruleDuration,
            ),
        )
}

fun scopeCandidatesForRequest(setup: StoredSetup, requestId: String): List<String> {
    val signer = DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)
    return PhoneClient(setup.payload.endpoint)
        .scopeCandidates(setup.payload.serverId, setup.payload.approverId, signer, requestId)
}

fun decisionHistory(setup: StoredSetup): List<PhoneHistoryEntry> {
    val signer = DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)
    return PhoneClient(setup.payload.endpoint)
        .history(setup.payload.serverId, setup.payload.approverId, signer)
}

data class PhoneHistoryEntry(
    val requestId: String,
    val decision: String,
    val decisionSource: String,
    val decidedAt: String,
    val ruleId: String?,
    val clientId: String?,
    val status: String?,
    val operation: String,
)

data class PhoneSessionInfo(val sessionId: String, val clientId: String, val expiresAt: String?)
data class PhoneDeviceInfo(val deviceId: String, val createdAt: String, val enabled: Boolean, val hasPollKey: Boolean)

/** Reads and device-signed admin mutations for the phone management screen
 * (items 6, 8.3, 8.4). Reads use the poll key; mutations use the
 * biometry-bound approval key over the signed admin protocol. */
fun adminSessions(setup: StoredSetup): List<PhoneSessionInfo> {
    val signer = DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)
    val response = PhoneClient(setup.payload.endpoint)
        .signedCall(setup.payload.serverId, setup.payload.approverId, signer, "GET", "/v1/approver/sessions")
    val array = response.getJSONArray("sessions")
    return List(array.length()) { i ->
        val value = array.getJSONObject(i)
        PhoneSessionInfo(
            sessionId = value.getString("session_id"),
            clientId = value.optString("client_id"),
            expiresAt = value.optString("expires_at", null as String?),
        )
    }
}

fun adminDevices(setup: StoredSetup): List<PhoneDeviceInfo> {
    val signer = DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)
    val response = PhoneClient(setup.payload.endpoint)
        .signedCall(setup.payload.serverId, setup.payload.approverId, signer, "GET", "/v1/approver/devices")
    val array = response.getJSONArray("devices")
    return List(array.length()) { i ->
        val value = array.getJSONObject(i)
        PhoneDeviceInfo(
            deviceId = value.getString("device_id"),
            createdAt = value.optString("created_at"),
            enabled = value.optBoolean("enabled", true),
            hasPollKey = value.optBoolean("has_poll_key", false),
        )
    }
}

/** Signs an admin action with the approval key and posts it. Returns the raw
 * response for action-specific fields (e.g. pairing_code). */
fun adminAction(setup: StoredSetup, action: String, targetId: String): JSONObject {
    val client = PhoneClient(setup.payload.endpoint)
    val challenge = client.challenge()
    val message = CompatProtocol.adminMessage(
        serverId = setup.payload.serverId,
        deviceId = setup.payload.approverId,
        action = action,
        targetId = targetId,
        challenge = challenge,
    )
    val signature = Base64.encodeToString(
        DeviceKeyManager.approvalSigner(setup.approvalKeyMaterial.publicKey).sign(message),
        Base64.NO_WRAP,
    )
    val body = JSONObject()
        .put("device_id", setup.payload.approverId)
        .put("action", action)
        .put("target_id", targetId)
        .put("challenge", challenge)
        .put("signature", signature)
    return client.adminPost(
        setup.payload.serverId,
        setup.payload.approverId,
        adminPath(action),
        body,
    )
}

private fun adminPath(action: String): String = when (action) {
    "sessions.extend" -> "/v1/approver/sessions/extend"
    "sessions.revoke" -> "/v1/approver/sessions/revoke"
    "devices.revoke" -> "/v1/approver/devices/revoke"
    "pairing_code" -> "/v1/approver/pairing-code"
    "enrollment" -> "/v1/approver/enrollment"
    "request.kill" -> "/v1/approver/request/kill"
    else -> throw IllegalArgumentException("Unknown admin action: $action")
}

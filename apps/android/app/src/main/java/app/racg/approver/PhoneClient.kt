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
        tokenSha256Hex: String,
        challenge: String,
        signature: String,
    ) {
        val input = JSONObject()
            .put("device_id", deviceId)
            .put("public_key", Base64.encodeToString(publicKey, Base64.NO_WRAP))
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
        call("POST", "/v1/approver/decision", body)
    }

    private fun signedCall(
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
)

fun usesCompatibilityApi(endpoint: String): Boolean {
    val scheme = URL(endpoint).protocol.lowercase()
    return scheme == "http" || scheme == "https"
}

fun pendingCompatibilityRequests(setup: StoredSetup): List<PhonePendingRequest> {
    val signer = DeviceKeyManager.approvalSigner(setup.approvalKeyMaterial.publicKey)
    return PhoneClient(setup.payload.endpoint)
        .pending(setup.payload.serverId, setup.payload.approverId, signer)
}

fun decideCompatibilityRequest(
    setup: StoredSetup,
    requestId: String,
    decision: String,
    operationSha256: String,
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
            ),
        )
}

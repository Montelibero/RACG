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

class PhoneClient(private val endpoint: String, private val timeoutMillis: Int = 10_000) {
    private val baseUrl = endpoint.trimEnd('/')

    fun pair(code: String, deviceId: String, publicKey: ByteArray) {
        val input = JSONObject()
            .put("code", code)
            .put("device_id", deviceId)
            .put("public_key", Base64.encodeToString(publicKey, Base64.NO_WRAP))
        call("POST", "/v1/pair", input)
    }

    fun challenge(): String {
        val response = call("GET", "/v1/challenge")
        return response.getString("challenge")
    }

    fun pending(): List<PhonePendingRequest> {
        val response = call("GET", "/v1/requests")
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

    fun decide(input: PhoneDecisionInput) {
        val body = JSONObject()
            .put("device_id", input.deviceId)
            .put("request_id", input.requestId)
            .put("decision", input.decision)
            .put("op_sha256", input.opSha256)
            .put("challenge", input.challenge)
            .put("public_key", Base64.encodeToString(input.publicKey, Base64.NO_WRAP))
            .put("signature", Base64.encodeToString(input.signature, Base64.NO_WRAP))
        call("POST", "/v1/decision", body)
    }

    private fun call(method: String, path: String, body: JSONObject? = null): JSONObject {
        val connection = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMillis
            readTimeout = timeoutMillis
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        if (body != null) {
            val output = connection.outputStream
            output.write(body.toString().toByteArray(Charsets.UTF_8))
            output.flush()
        }

        val stream = if (connection.responseCode in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream
        }
        val raw = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()

        if (connection.responseCode !in 200..299) {
            throw IllegalArgumentException("Phone service returned ${connection.responseCode}")
        }
        return JSONObject(raw)
    }
}

data class PhoneDecisionInput(
    val deviceId: String,
    val requestId: String,
    val decision: String,
    val opSha256: String,
    val challenge: String,
    val publicKey: ByteArray,
    val signature: ByteArray,
)

fun usesCompatibilityApi(endpoint: String): Boolean {
    val scheme = URL(endpoint).protocol.lowercase()
    return scheme == "http" || scheme == "https"
}

fun pendingCompatibilityRequests(setup: StoredSetup): List<PhonePendingRequest> =
    PhoneClient(setup.payload.endpoint).pending()

fun decideCompatibilityRequest(
    setup: StoredSetup,
    requestId: String,
    decision: String,
    operationSha256: String,
) {
    val challenge = PhoneClient(setup.payload.endpoint).challenge()
    val signer = DeviceKeyManager.approvalSigner(setup.approvalKeyMaterial.publicKey)
    val message = CompatProtocol.decisionMessage(
        deviceId = setup.payload.approverId,
        requestId = requestId,
        decision = decision,
        operationSha256 = operationSha256,
        challenge = challenge,
    )
    val signature = signer.sign(message)
    PhoneClient(setup.payload.endpoint).decide(
        PhoneDecisionInput(
            deviceId = setup.payload.approverId,
            requestId = requestId,
            decision = decision,
            opSha256 = operationSha256,
            challenge = challenge,
            publicKey = setup.approvalKeyMaterial.publicKey,
            signature = signature,
        ),
    )
}

package app.racg.approver

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
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
const val KEY_TYPE_ED25519 = "ed25519"
const val KEY_TYPE_ECDSA_P256 = "ecdsa-p256"

interface DeviceSigner {
    val publicKey: ByteArray
    val keyType: String
    fun sign(message: ByteArray): ByteArray
}

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

data class DeviceEnrollment(
    val version: Int,
    val serverId: String,
    val deviceId: String,
    val keyType: String,
    val publicKey: ByteArray,
    val pollKey: ByteArray,
    val tokenSha256: ByteArray,
    val challenge: ByteArray,
    val validUntil: String,
)

data class SignedDeviceEnrollment(val enrollment: DeviceEnrollment, val signature: ByteArray)

data class DeviceEnrollmentSubmission(
    val enrollment: SignedDeviceEnrollment,
    val token: ByteArray,
)

data class DeviceEnrollmentReceipt(
    val version: Int,
    val serverId: String,
    val deviceId: String,
    val keyType: String,
    val publicKey: ByteArray,
    val pollKey: ByteArray,
    val enrollmentSha256: String,
    val challenge: ByteArray,
    val status: String,
)

data class SignedDeviceEnrollmentReceipt(val receipt: DeviceEnrollmentReceipt, val signature: ByteArray)

data class DeviceTransferGrant(
    val version: Int,
    val serverId: String,
    val currentDeviceId: String,
    val keyType: String,
    val newDeviceId: String,
    val transferTokenSha256: ByteArray,
    val challenge: ByteArray,
    val validUntil: String,
)

data class SignedDeviceTransferGrant(val grant: DeviceTransferGrant, val signature: ByteArray)

data class DeviceTransferEnrollment(
    val version: Int,
    val serverId: String,
    val newDeviceId: String,
    val keyType: String,
    val publicKey: ByteArray,
    val pollKey: ByteArray,
    val grantChallenge: ByteArray,
    val transferTokenSha256: ByteArray,
    val challenge: ByteArray,
    val validUntil: String,
)

data class SignedDeviceTransferEnrollment(
    val enrollment: DeviceTransferEnrollment,
    val signature: ByteArray,
)

data class DeviceTransferSubmission(
    val enrollment: SignedDeviceTransferEnrollment,
    val token: ByteArray,
)

data class DeviceTransferReceipt(
    val version: Int,
    val serverId: String,
    val currentDeviceId: String,
    val newDeviceId: String,
    val keyType: String,
    val publicKey: ByteArray,
    val pollKey: ByteArray,
    val grantSha256: String,
    val challenge: ByteArray,
    val status: String,
)

data class SignedDeviceTransferReceipt(val receipt: DeviceTransferReceipt, val signature: ByteArray)

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
        return signRequestList(
            list,
            object : DeviceSigner {
                override val publicKey = privateKey.generatePublicKey().encoded
                override val keyType = KEY_TYPE_ED25519
                override fun sign(message: ByteArray) = sign(message, privateKey)
            },
        )
    }

    fun signRequestList(
        list: ApprovalRequestList,
        signer: DeviceSigner,
    ): SignedApprovalRequestList {
        validateRequestList(list)
        return SignedApprovalRequestList(
            list = list,
            signature = signer.sign(message("request-list", encodeRequestList(list))),
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
        return signDecision(
            request,
            deviceId,
            action,
            validUntil,
            object : DeviceSigner {
                override val publicKey = privateKey.generatePublicKey().encoded
                override val keyType = KEY_TYPE_ED25519
                override fun sign(message: ByteArray) = sign(message, privateKey)
            },
        )
    }

    fun signDecision(
        request: ApprovalRequest,
        deviceId: String,
        action: String,
        validUntil: Instant,
        signer: DeviceSigner,
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
            signature = signer.sign(message("decision", encodeDecision(decision))),
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
        return verifyDecisionReceiptWithKeyType(
            request,
            decision,
            signedReceipt,
            challenge,
            KEY_TYPE_ED25519,
            deviceKey.encoded,
            serverKey,
            now,
        )
    }

    fun verifyDecisionReceiptWithKeyType(
        request: ApprovalRequest,
        decision: SignedApprovalDecision,
        signedReceipt: SignedApprovalDecisionReceipt,
        challenge: ByteArray,
        keyType: String,
        deviceKey: ByteArray,
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
        verifyDeviceSignature(
            keyType,
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

    fun newDeviceTransferGrant(
        serverId: String,
        currentDeviceId: String,
        keyType: String,
        newDeviceId: String,
        token: ByteArray,
        now: Instant,
        lifetimeSeconds: Long = 600,
    ): DeviceTransferGrant = DeviceTransferGrant(
        version = APPROVAL_VERSION,
        serverId = serverId,
        currentDeviceId = currentDeviceId,
        keyType = keyType,
        newDeviceId = newDeviceId,
        transferTokenSha256 = sha256(token),
        challenge = randomBytes(),
        validUntil = now.plusSeconds(lifetimeSeconds).toString(),
    )

    fun signDeviceTransferGrant(grant: DeviceTransferGrant, signer: DeviceSigner): SignedDeviceTransferGrant {
        validateTransferGrant(grant)
        require(grant.currentDeviceId.isNotBlank() && grant.keyType == signer.keyType) {
            "Transfer signer identity mismatch"
        }
        return SignedDeviceTransferGrant(
            grant = grant,
            signature = signer.sign(message("device-transfer-grant", encodeTransferGrant(grant))),
        )
    }

    fun newDeviceTransferEnrollment(
        serverId: String,
        newDeviceId: String,
        signer: DeviceSigner,
        pollKey: ByteArray,
        grantChallenge: ByteArray,
        token: ByteArray,
        now: Instant,
        lifetimeSeconds: Long = 300,
    ): DeviceTransferEnrollment = DeviceTransferEnrollment(
        version = APPROVAL_VERSION,
        serverId = serverId,
        newDeviceId = newDeviceId,
        keyType = signer.keyType,
        publicKey = signer.publicKey,
        pollKey = pollKey,
        grantChallenge = grantChallenge,
        transferTokenSha256 = sha256(token),
        challenge = randomBytes(),
        validUntil = now.plusSeconds(lifetimeSeconds).toString(),
    )

    fun signDeviceTransferEnrollment(
        enrollment: DeviceTransferEnrollment,
        signer: DeviceSigner,
    ): SignedDeviceTransferEnrollment {
        validateTransferEnrollment(enrollment)
        require(enrollment.newDeviceId.isNotBlank() && enrollment.keyType == signer.keyType) {
            "Transfer signer identity mismatch"
        }
        return SignedDeviceTransferEnrollment(
            enrollment = enrollment,
            signature = signer.sign(message("device-transfer-enrollment", encodeTransferEnrollment(enrollment))),
        )
    }

    fun verifyTransferEnrollment(
        signed: SignedDeviceTransferEnrollment,
        serverId: String,
        newDeviceId: String,
        now: Instant,
    ) {
        val enrollment = signed.enrollment
        validateTransferEnrollment(enrollment)
        require(enrollment.serverId == serverId && enrollment.newDeviceId == newDeviceId) {
            "Transfer enrollment identity mismatch"
        }
        verifyDeviceSignature(
            enrollment.keyType,
            enrollment.publicKey,
            message("device-transfer-enrollment", encodeTransferEnrollment(enrollment)),
            signed.signature,
        ) { "Transfer enrollment signature is invalid" }
        require(now.isBefore(Instant.parse(enrollment.validUntil))) { "Transfer enrollment expired" }
    }

    fun verifyTransferReceipt(
        enrollment: SignedDeviceTransferEnrollment,
        signedReceipt: SignedDeviceTransferReceipt,
        serverKey: Ed25519PublicKeyParameters,
        now: Instant,
    ) {
        val enrollmentBody = enrollment.enrollment
        verifyTransferEnrollment(enrollment, enrollmentBody.serverId, enrollmentBody.newDeviceId, now)
        val receipt = signedReceipt.receipt
        require(
            receipt.version == APPROVAL_VERSION && receipt.serverId == enrollmentBody.serverId &&
                receipt.newDeviceId == enrollmentBody.newDeviceId &&
                receipt.keyType == enrollmentBody.keyType &&
                receipt.publicKey.contentEquals(enrollmentBody.publicKey) &&
                receipt.pollKey.contentEquals(enrollmentBody.pollKey) &&
                receipt.challenge.contentEquals(enrollmentBody.challenge) &&
                receipt.status == "TRANSFERRED",
        ) { "Transfer receipt does not match the enrollment" }
        verify(
            serverKey,
            message("device-transfer-receipt", encodeTransferReceipt(receipt)),
            signedReceipt.signature,
        ) { "Transfer receipt signature is invalid" }
    }

    fun newDeviceEnrollment(
        serverId: String,
        deviceId: String,
        publicKey: ByteArray,
        pollKey: ByteArray,
        token: ByteArray,
        now: Instant,
        lifetimeSeconds: Long = 60,
    ): DeviceEnrollment = DeviceEnrollment(
        version = APPROVAL_VERSION,
        serverId = serverId,
        deviceId = deviceId,
        keyType = KEY_TYPE_ED25519,
        publicKey = publicKey,
        pollKey = pollKey,
        tokenSha256 = sha256(token),
        challenge = randomBytes(),
        validUntil = now.plusSeconds(lifetimeSeconds).toString(),
    )

    fun newDeviceEnrollmentWithKeyType(
        serverId: String,
        deviceId: String,
        keyType: String,
        publicKey: ByteArray,
        pollKey: ByteArray,
        token: ByteArray,
        now: Instant,
        lifetimeSeconds: Long = 60,
    ): DeviceEnrollment = DeviceEnrollment(
        version = APPROVAL_VERSION,
        serverId = serverId,
        deviceId = deviceId,
        keyType = keyType,
        publicKey = publicKey,
        pollKey = pollKey,
        tokenSha256 = sha256(token),
        challenge = randomBytes(),
        validUntil = now.plusSeconds(lifetimeSeconds).toString(),
    )

    fun signDeviceEnrollment(
        enrollment: DeviceEnrollment,
        privateKey: Ed25519PrivateKeyParameters,
    ): SignedDeviceEnrollment {
        return signDeviceEnrollment(
            enrollment,
            object : DeviceSigner {
                override val publicKey = privateKey.generatePublicKey().encoded
                override val keyType = KEY_TYPE_ED25519
                override fun sign(message: ByteArray) = sign(message, privateKey)
            },
        )
    }

    fun signDeviceEnrollment(
        enrollment: DeviceEnrollment,
        signer: DeviceSigner,
    ): SignedDeviceEnrollment {
        validateDeviceEnrollment(enrollment)
        require(enrollment.publicKey.contentEquals(signer.publicKey)) {
            "Device enrollment key mismatch"
        }
        return SignedDeviceEnrollment(
            enrollment = enrollment,
            signature = signer.sign(message("device-enrollment", encodeDeviceEnrollment(enrollment))),
        )
    }

    fun verifyDeviceEnrollment(
        signed: SignedDeviceEnrollment,
        serverId: String,
        now: Instant,
    ) {
        val enrollment = signed.enrollment
        validateDeviceEnrollment(enrollment)
        require(enrollment.serverId == serverId) { "Enrollment server identity mismatch" }
        verifyDeviceSignature(
            enrollment.keyType,
            enrollment.publicKey,
            message("device-enrollment", encodeDeviceEnrollment(enrollment)),
            signed.signature,
        ) { "Device enrollment signature is invalid" }
        require(now.isBefore(Instant.parse(enrollment.validUntil))) { "Device enrollment expired" }
    }

    fun verifyEnrollmentReceipt(
        signed: SignedDeviceEnrollment,
        signedReceipt: SignedDeviceEnrollmentReceipt,
        serverKey: Ed25519PublicKeyParameters,
        now: Instant,
    ) {
        verifyDeviceEnrollment(signed, signed.enrollment.serverId, now)
        val digest = sha256Hex(message("device-enrollment", encodeDeviceEnrollment(signed.enrollment)))
        val receipt = signedReceipt.receipt
        require(receipt.version == APPROVAL_VERSION) { "Unsupported enrollment receipt version" }
        require(
            receipt.serverId == signed.enrollment.serverId &&
                receipt.deviceId == signed.enrollment.deviceId &&
                receipt.keyType == signed.enrollment.keyType &&
                receipt.publicKey.contentEquals(signed.enrollment.publicKey) &&
                receipt.pollKey.contentEquals(signed.enrollment.pollKey) &&
                receipt.enrollmentSha256 == digest &&
                receipt.challenge.contentEquals(signed.enrollment.challenge) &&
                receipt.status == "ENROLLED",
        ) { "Enrollment receipt does not match the request" }
        verify(
            serverKey,
            message("device-enrollment-receipt", encodeEnrollmentReceipt(receipt)),
            signedReceipt.signature,
        ) { "Enrollment receipt signature is invalid" }
    }

    fun decodeSignedTransferEnrollment(raw: JSONObject): SignedDeviceTransferEnrollment {
        val enrollment = requireObject(raw, "enrollment")
        return SignedDeviceTransferEnrollment(
            enrollment = DeviceTransferEnrollment(
                version = enrollment.getInt("version"),
                serverId = enrollment.requireString("server_id"),
                newDeviceId = enrollment.requireString("new_device_id"),
                keyType = enrollment.requireString("key_type"),
                publicKey = enrollment.decodeBase64("public_key"),
                pollKey = enrollment.decodeBase64("poll_public_key"),
                grantChallenge = enrollment.decodeBase64("grant_challenge"),
                transferTokenSha256 = enrollment.decodeBase64("transfer_token_sha256"),
                challenge = enrollment.decodeBase64("challenge"),
                validUntil = enrollment.requireString("valid_until"),
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeSignedTransferReceipt(raw: JSONObject): SignedDeviceTransferReceipt {
        val receipt = requireObject(raw, "receipt")
        return SignedDeviceTransferReceipt(
            receipt = DeviceTransferReceipt(
                version = receipt.getInt("version"),
                serverId = receipt.requireString("server_id"),
                currentDeviceId = receipt.requireString("current_device_id"),
                newDeviceId = receipt.requireString("new_device_id"),
                keyType = receipt.requireString("key_type"),
                publicKey = receipt.decodeBase64("public_key"),
                pollKey = receipt.decodeBase64("poll_public_key"),
                grantSha256 = receipt.requireString("grant_sha256"),
                challenge = receipt.decodeBase64("challenge"),
                status = receipt.requireString("status"),
            ),
            signature = raw.decodeBase64("signature"),
        )
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

    fun decodeSignedDeviceEnrollment(raw: JSONObject): SignedDeviceEnrollment {
        val enrollment = requireObject(raw, "enrollment")
        return SignedDeviceEnrollment(
            enrollment = DeviceEnrollment(
                version = enrollment.getInt("version"),
                serverId = enrollment.requireString("server_id"),
                deviceId = enrollment.requireString("device_id"),
                keyType = enrollment.requireString("key_type"),
                publicKey = enrollment.decodeBase64("public_key"),
                pollKey = enrollment.decodeBase64("poll_public_key"),
                tokenSha256 = enrollment.decodeBase64("token_sha256"),
                challenge = enrollment.decodeBase64("challenge"),
                validUntil = enrollment.requireString("valid_until"),
            ),
            signature = raw.decodeBase64("signature"),
        )
    }

    fun decodeEnrollmentSubmission(raw: JSONObject): DeviceEnrollmentSubmission =
        DeviceEnrollmentSubmission(
            enrollment = decodeSignedDeviceEnrollment(requireObject(raw, "enrollment")),
            token = raw.decodeBase64("token"),
        )

    fun decodeSignedEnrollmentReceipt(raw: JSONObject): SignedDeviceEnrollmentReceipt {
        val receipt = requireObject(raw, "receipt")
        return SignedDeviceEnrollmentReceipt(
            receipt = DeviceEnrollmentReceipt(
                version = receipt.getInt("version"),
                serverId = receipt.requireString("server_id"),
                deviceId = receipt.requireString("device_id"),
                keyType = receipt.requireString("key_type"),
                publicKey = receipt.decodeBase64("public_key"),
                pollKey = receipt.decodeBase64("poll_public_key"),
                enrollmentSha256 = receipt.requireString("enrollment_sha256"),
                challenge = receipt.decodeBase64("challenge"),
                status = receipt.requireString("status"),
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

    internal fun encodeDeviceEnrollment(value: DeviceEnrollment): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("device_id", value.deviceId)
        text("key_type", value.keyType)
        base64("public_key", value.publicKey)
        base64("poll_public_key", value.pollKey)
        base64("token_sha256", value.tokenSha256)
        base64("challenge", value.challenge)
        text("valid_until", value.validUntil)
    }

    internal fun encodeSignedDeviceEnrollment(value: SignedDeviceEnrollment): String = jsonObject {
        raw("enrollment", encodeDeviceEnrollment(value.enrollment))
        base64("signature", value.signature)
    }

    internal fun encodeEnrollmentSubmission(value: DeviceEnrollmentSubmission): String = jsonObject {
        raw("enrollment", encodeSignedDeviceEnrollment(value.enrollment))
        base64("token", value.token)
    }

    internal fun encodeEnrollmentReceipt(value: DeviceEnrollmentReceipt): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("device_id", value.deviceId)
        text("key_type", value.keyType)
        base64("public_key", value.publicKey)
        base64("poll_public_key", value.pollKey)
        text("enrollment_sha256", value.enrollmentSha256)
        base64("challenge", value.challenge)
        text("status", value.status)
    }

    internal fun encodeSignedEnrollmentReceipt(value: SignedDeviceEnrollmentReceipt): String = jsonObject {
        raw("receipt", encodeEnrollmentReceipt(value.receipt))
        base64("signature", value.signature)
    }

    internal fun encodeTransferGrant(value: DeviceTransferGrant): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("current_device_id", value.currentDeviceId)
        text("key_type", value.keyType)
        text("new_device_id", value.newDeviceId)
        base64("transfer_token_sha256", value.transferTokenSha256)
        base64("challenge", value.challenge)
        text("valid_until", value.validUntil)
    }

    internal fun encodeSignedTransferGrant(value: SignedDeviceTransferGrant): String = jsonObject {
        raw("grant", encodeTransferGrant(value.grant))
        base64("signature", value.signature)
    }

    internal fun encodeTransferGrantSubmission(value: SignedDeviceTransferGrant): String = jsonObject {
        raw("grant", encodeSignedTransferGrant(value))
    }

    internal fun encodeTransferEnrollment(value: DeviceTransferEnrollment): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("new_device_id", value.newDeviceId)
        text("key_type", value.keyType)
        base64("public_key", value.publicKey)
        base64("poll_public_key", value.pollKey)
        base64("grant_challenge", value.grantChallenge)
        base64("transfer_token_sha256", value.transferTokenSha256)
        base64("challenge", value.challenge)
        text("valid_until", value.validUntil)
    }

    internal fun encodeSignedTransferEnrollment(value: SignedDeviceTransferEnrollment): String = jsonObject {
        raw("enrollment", encodeTransferEnrollment(value.enrollment))
        base64("signature", value.signature)
    }

    internal fun encodeTransferSubmission(value: DeviceTransferSubmission): String = jsonObject {
        raw("enrollment", encodeSignedTransferEnrollment(value.enrollment))
        base64("token", value.token)
    }

    internal fun encodeTransferReceipt(value: DeviceTransferReceipt): String = jsonObject {
        number("version", value.version)
        text("server_id", value.serverId)
        text("current_device_id", value.currentDeviceId)
        text("new_device_id", value.newDeviceId)
        text("key_type", value.keyType)
        base64("public_key", value.publicKey)
        base64("poll_public_key", value.pollKey)
        text("grant_sha256", value.grantSha256)
        base64("challenge", value.challenge)
        text("status", value.status)
    }

    internal fun encodeSignedTransferReceipt(value: SignedDeviceTransferReceipt): String = jsonObject {
        raw("receipt", encodeTransferReceipt(value.receipt))
        base64("signature", value.signature)
    }

    fun sha256Hex(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

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

    private fun validateDeviceEnrollment(value: DeviceEnrollment) {
        require(value.version == APPROVAL_VERSION) { "Unsupported enrollment version" }
        require(value.serverId.isNotBlank() && value.deviceId.isNotBlank()) {
            "Invalid enrollment identity"
        }
        require(value.keyType == KEY_TYPE_ED25519 || value.keyType == KEY_TYPE_ECDSA_P256) {
            "Unsupported enrollment key type"
        }
        require(value.publicKey.isNotEmpty()) { "Invalid enrollment public key" }
        require(value.pollKey.isNotEmpty()) { "Invalid enrollment poll key" }
        require(value.tokenSha256.size == KEY_BYTES) { "Invalid enrollment token digest" }
        require(value.challenge.size == KEY_BYTES) { "Invalid enrollment challenge" }
        runCatching { Instant.parse(value.validUntil) }
        .onFailure { throw IllegalArgumentException("Invalid enrollment validity") }
    }

    private fun validateTransferGrant(value: DeviceTransferGrant) {
        require(value.version == APPROVAL_VERSION) { "Unsupported transfer grant version" }
        require(
            value.serverId.isNotBlank() && value.currentDeviceId.isNotBlank() &&
                value.newDeviceId.isNotBlank() && value.currentDeviceId != value.newDeviceId,
        ) { "Invalid transfer grant identity" }
        require(value.keyType == KEY_TYPE_ED25519 || value.keyType == KEY_TYPE_ECDSA_P256) {
            "Unsupported transfer key type"
        }
        require(value.transferTokenSha256.size == KEY_BYTES) { "Invalid transfer token digest" }
        require(value.challenge.size == KEY_BYTES) { "Invalid transfer grant challenge" }
        runCatching { Instant.parse(value.validUntil) }
            .onFailure { throw IllegalArgumentException("Invalid transfer grant validity") }
    }

    private fun validateTransferEnrollment(value: DeviceTransferEnrollment) {
        require(value.version == APPROVAL_VERSION) { "Unsupported transfer enrollment version" }
        require(value.serverId.isNotBlank() && value.newDeviceId.isNotBlank()) {
            "Invalid transfer enrollment identity"
        }
        require(value.keyType == KEY_TYPE_ED25519 || value.keyType == KEY_TYPE_ECDSA_P256) {
            "Unsupported transfer key type"
        }
        require(value.publicKey.isNotEmpty() && value.pollKey.isNotEmpty()) {
            "Invalid transfer public keys"
        }
        require(value.grantChallenge.size == KEY_BYTES) { "Invalid transfer grant challenge" }
        require(value.transferTokenSha256.size == KEY_BYTES) { "Invalid transfer token digest" }
        require(value.challenge.size == KEY_BYTES) { "Invalid transfer enrollment challenge" }
        runCatching { Instant.parse(value.validUntil) }
            .onFailure { throw IllegalArgumentException("Invalid transfer enrollment validity") }
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

    private fun verifyDeviceSignature(
        keyType: String,
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
        failure: () -> String,
    ) {
        when (keyType) {
            KEY_TYPE_ED25519 -> {
                require(signature.size == SIGNATURE_BYTES) { failure() }
                val verifier = Ed25519Signer()
                verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
                verifier.update(message, 0, message.size)
                require(verifier.verifySignature(signature)) { failure() }
            }
            KEY_TYPE_ECDSA_P256 -> {
                val public = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKey))
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(public)
                verifier.update(message)
                require(verifier.verify(signature)) { failure() }
            }
            else -> throw IllegalArgumentException("Unsupported enrollment key type")
        }
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

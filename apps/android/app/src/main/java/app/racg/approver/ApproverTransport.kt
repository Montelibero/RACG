package app.racg.approver

import java.security.SecureRandom
import java.time.Instant
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

/** Verifies every authority snapshot and signs only mobile one-shot actions. */
class ApproverTransport(
    private val setup: StoredSetup,
    private val connection: BrokerClient,
) {
    private val serverKey = Ed25519PublicKeyParameters(setup.payload.serverPublicKey, 0)

    fun pendingRequests(key: UnlockedDeviceKey, now: Instant = Instant.now()): List<SignedApprovalRequest> {
        requireKeyMatchesSetup(key)
        val list = ApprovalProtocol.newRequestList(
            serverId = setup.payload.serverId,
            deviceId = setup.payload.approverId,
            now = now,
        )
        val signedList = ApprovalProtocol.signRequestList(list, key.privateKey)
        val result = connection.listPending(signedList)
        return ApprovalProtocol.verifyRequestListResult(list, result, serverKey, now)
    }

    fun submitDecision(
        key: UnlockedDeviceKey,
        request: SignedApprovalRequest,
        action: String,
        now: Instant = Instant.now(),
    ): SignedApprovalDecisionReceipt {
        requireKeyMatchesSetup(key)
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val decision = ApprovalProtocol.signDecision(
            request = request.request,
            deviceId = setup.payload.approverId,
            action = action,
            validUntil = now.plusSeconds(300),
            privateKey = key.privateKey,
        )
        val receipt = connection.submitDecision(
            DecisionSubmission(
                requestId = request.request.requestId,
                decision = decision,
                challenge = challenge,
            ),
        )
        ApprovalProtocol.verifyDecisionReceipt(
            request = request.request,
            decision = decision,
            signedReceipt = receipt,
            challenge = challenge,
            deviceKey = Ed25519PublicKeyParameters(key.publicKey, 0),
            serverKey = serverKey,
            now = now,
        )
        return receipt
    }

    private fun requireKeyMatchesSetup(key: UnlockedDeviceKey) {
        require(key.publicKey.contentEquals(setup.keyMaterial.publicKey)) {
            "Unlocked device key does not match stored setup"
        }
    }
}

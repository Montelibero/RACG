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

    fun pendingRequests(key: DeviceSigner, now: Instant = Instant.now()): List<SignedApprovalRequest> {
        requireKeyMatchesSetup(key)
        val list = ApprovalProtocol.newRequestList(
            serverId = setup.payload.serverId,
            deviceId = setup.payload.approverId,
            now = now,
        )
        val signedList = ApprovalProtocol.signRequestList(list, key)
        val result = connection.listPending(signedList)
        return ApprovalProtocol.verifyRequestListResult(list, result, serverKey, now)
    }

    fun submitDecision(
        key: DeviceSigner,
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
            signer = key,
        )
        val receipt = connection.submitDecision(
            DecisionSubmission(
                requestId = request.request.requestId,
                decision = decision,
                challenge = challenge,
            ),
        )
        ApprovalProtocol.verifyDecisionReceiptWithKeyType(
            request = request.request,
            decision = decision,
            signedReceipt = receipt,
            challenge = challenge,
            deviceKey = key.publicKey,
            keyType = key.keyType,
            serverKey = serverKey,
            now = now,
        )
        return receipt
    }

    private fun requireKeyMatchesSetup(key: DeviceSigner) {
        require(key.publicKey.contentEquals(setup.keyMaterial.publicKey)) {
            "Unlocked device key does not match stored setup"
        }
    }
}

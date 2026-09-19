package app.racg.approver

import java.time.Instant
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ApprovalProtocolTest {
    private val serverKey = Ed25519PublicKeyParameters(
        hex("8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"),
        0,
    )
    private val devicePrivate = Ed25519PrivateKeyParameters(bytes(1), 0)
    private val deviceKey = devicePrivate.generatePublicKey()

    @Test
    fun `verifies Go request fixture`() {
        val signed = ApprovalProtocol.decodeSignedRequest(resource("signed-request.json"))
        ApprovalProtocol.verifyRequest(signed, "server", serverKey)
        assertEquals(
            "f13783072890a698b7f156522670a6a376499f3f89ca46b03f1f1a6802cb0485",
            ApprovalProtocol.requestDigest(signed.request),
        )
    }

    @Test
    fun `verifies Go pending list fixture`() {
        val signedList = ApprovalProtocol.decodeSignedRequestList(resource("signed-request-list.json"))
        val result = ApprovalProtocol.decodeSignedRequestListResult(
            resource("signed-request-list-result.json"),
        )
        val requests = ApprovalProtocol.verifyRequestListResult(
            signedList.list,
            result,
            serverKey,
            Instant.parse("2029-01-01T00:00:00Z"),
        )
        assertEquals(1, requests.size)
    }

    @Test
    fun `rejects Go result with a changed request`() {
        val signedList = ApprovalProtocol.decodeSignedRequestList(resource("signed-request-list.json"))
        val result = ApprovalProtocol.decodeSignedRequestListResult(
            resource("signed-request-list-result.json"),
        )
        val changed = result.copy(
            result = result.result.copy(
                requests = result.result.requests.map {
                    it.copy(request = it.request.copy(clientId = "attacker"))
                },
            ),
        )

        assertThrows(IllegalArgumentException::class.java) {
            ApprovalProtocol.verifyRequestListResult(
                signedList.list,
                changed,
                serverKey,
                Instant.parse("2029-01-01T00:00:00Z"),
            )
        }
    }

    @Test
    fun `produces Go-compatible signed request list`() {
        val list = ApprovalProtocol.decodeRequestList(resource("signed-request-list.json").getJSONObject("list"))
        val signed = ApprovalProtocol.signRequestList(list, devicePrivate)
        assertEquals(rawResource("signed-request-list.json"), ApprovalProtocol.encodeSignedRequestList(signed))
    }

    @Test
    fun `produces Go-compatible signed decision and verifies receipt`() {
        val request = ApprovalProtocol.decodeSignedRequest(resource("signed-request.json"))
        val signed = ApprovalProtocol.signDecision(
            request.request,
            "phone",
            "ALLOW_ONCE",
            Instant.parse("2030-01-02T03:04:05Z"),
            devicePrivate,
        )

        assertEquals(rawResource("signed-decision.json"), ApprovalProtocol.encodeSignedDecision(signed))
        ApprovalProtocol.verifyDecisionReceipt(
            request.request,
            signed,
            ApprovalProtocol.decodeSignedDecisionReceipt(resource("signed-decision-receipt.json")),
            bytes(5),
            deviceKey,
            serverKey,
            Instant.parse("2029-01-01T00:00:00Z"),
        )
    }

    @Test
    fun `verifies Go device enrollment fixture`() {
        val signed = ApprovalProtocol.decodeSignedDeviceEnrollment(resource("signed-device-enrollment.json"))
        val receipt = ApprovalProtocol.decodeSignedEnrollmentReceipt(
            resource("signed-device-enrollment-receipt.json"),
        )
        ApprovalProtocol.verifyDeviceEnrollment(signed, "server", Instant.parse("2029-01-01T00:00:00Z"))
        ApprovalProtocol.verifyEnrollmentReceipt(signed, receipt, serverKey, Instant.parse("2029-01-01T00:00:00Z"))
    }

    @Test
    fun `produces Go-compatible signed device enrollment`() {
        val signed = ApprovalProtocol.decodeSignedDeviceEnrollment(resource("signed-device-enrollment.json"))
        val resigned = ApprovalProtocol.signDeviceEnrollment(signed.enrollment, devicePrivate)
        assertEquals(
            rawResource("signed-device-enrollment.json"),
            ApprovalProtocol.encodeSignedDeviceEnrollment(resigned),
        )
    }

    private fun resource(name: String): JSONObject = JSONObject(
        javaClass.getResourceAsStream("/$name")!!.readBytes().toString(Charsets.UTF_8),
    )

    private fun rawResource(name: String): String =
        javaClass.getResourceAsStream("/$name")!!.readBytes().toString(Charsets.UTF_8)

    private fun bytes(value: Byte): ByteArray = ByteArray(32) { value }

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

package app.racg.approver

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import org.json.JSONObject

/** One-shot sequential-JSON authority client. Responses are verified by callers. */
class BrokerClient(
    private val host: String,
    private val port: Int,
    private val timeoutMillis: Int = 15_000,
) {
    fun listPending(signedList: SignedApprovalRequestList): SignedApprovalRequestListResult =
        call("v1/authority.list-pending", ApprovalProtocol.encodeSignedRequestList(signedList)) {
            ApprovalProtocol.decodeSignedRequestListResult(it)
        }

    fun submitDecision(submission: DecisionSubmission): SignedApprovalDecisionReceipt =
        call("v1/authority.submit-decision", ApprovalProtocol.encodeDecisionSubmission(submission)) {
            ApprovalProtocol.decodeSignedDecisionReceipt(it)
        }

    fun enrollDevice(submission: DeviceEnrollmentSubmission): SignedDeviceEnrollmentReceipt =
        call("v1/authority.enroll-device", ApprovalProtocol.encodeEnrollmentSubmission(submission)) {
            ApprovalProtocol.decodeSignedEnrollmentReceipt(it)
        }

    fun createTransfer(grant: SignedDeviceTransferGrant) {
        call("v1/authority.create-transfer", ApprovalProtocol.encodeTransferGrantSubmission(grant)) { it }
    }

    fun enrollTransfer(submission: DeviceTransferSubmission): SignedDeviceTransferReceipt =
        call("v1/authority.enroll-transfer", ApprovalProtocol.encodeTransferSubmission(submission)) {
            ApprovalProtocol.decodeSignedTransferReceipt(it)
        }

    private fun <T> call(
        method: String,
        params: String,
        parseResult: (JSONObject) -> T,
    ): T = Socket().use { socket ->
        socket.connect(InetSocketAddress(host, port), timeoutMillis)
        socket.soTimeout = timeoutMillis
        val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))
        val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
        writer.write(ApprovalProtocol.encodeWireRequest(1, method, params))
        writer.newLine()
        writer.flush()

        val line = reader.readLine() ?: throw IllegalArgumentException("Broker closed without a response")
        val response = JSONObject(line)
        require(response.getInt("version") == APPROVAL_VERSION) { "Unsupported broker response version" }
        require(response.getLong("id") == 1L) { "Broker response identity mismatch" }
        val error = response.optString("error", "")
        require(error.isEmpty()) { error }
        val result = response.optJSONObject("result")
        require(result != null) { "Broker response is missing a result" }
        parseResult(result)
    }
}

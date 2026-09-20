package app.racg.approver

object CompatProtocol {
    const val VERSION = 1

    fun decisionMessage(
        deviceId: String,
        requestId: String,
        decision: String,
        operationSha256: String,
        challenge: String,
    ): ByteArray {
        val value = "racg/phone-decision/v1\u0000$deviceId\u0000$requestId\u0000$decision\u0000$operationSha256\u0000$challenge"
        return value.toByteArray(Charsets.UTF_8)
    }
}

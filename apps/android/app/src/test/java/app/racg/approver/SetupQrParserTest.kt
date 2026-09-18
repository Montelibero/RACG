package app.racg.approver

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SetupQrParserTest {
    private val key = ByteArray(32) { it.toByte() }
    private val encodedKey = Base64.getEncoder().encodeToString(key)

    @Test
    fun `parses trusted setup QR`() {
        val raw = """
            {"v":1,"kind":"racg.approver.setup","server_id":"prod",
             "server_public_key":"$encodedKey","approver_id":"phone",
             "endpoint":"tcp://127.0.0.1:40123"}
        """.trimIndent()

        val payload = SetupQrParser.parse(raw)

        assertEquals("prod", payload.serverId)
        assertEquals("phone", payload.approverId)
        assertEquals("tcp://127.0.0.1:40123", payload.endpoint)
        assertEquals(key.toList(), payload.serverPublicKey.toList())
    }

    @Test
    fun `rejects wrong kind`() {
        val raw = """
            {"v":1,"kind":"other","server_id":"prod",
             "server_public_key":"$encodedKey","approver_id":"phone",
             "endpoint":"tcp://127.0.0.1:40123"}
        """.trimIndent()

        assertThrows(IllegalArgumentException::class.java) { SetupQrParser.parse(raw) }
    }

    @Test
    fun `rejects wrong public key length`() {
        val raw = """
            {"v":1,"kind":"racg.approver.setup","server_id":"prod",
             "server_public_key":"AAAA","approver_id":"phone",
             "endpoint":"tcp://127.0.0.1:40123"}
        """.trimIndent()

        assertThrows(IllegalArgumentException::class.java) { SetupQrParser.parse(raw) }
    }

    @Test
    fun `rejects non-TCP endpoint`() {
        val raw = """
            {"v":1,"kind":"racg.approver.setup","server_id":"prod",
             "server_public_key":"$encodedKey","approver_id":"phone",
             "endpoint":"https://example.invalid"}
        """.trimIndent()

        assertThrows(IllegalArgumentException::class.java) { SetupQrParser.parse(raw) }
    }
}

package app.racg.approver

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HumanOperationTest {
    private fun op(type: String, payload: JSONObject): String =
        JSONObject().put("type", type).put("payload", payload).toString()

    @Test
    fun `conf set details show path key and value`() {
        val raw = op(
            "conf.set",
            JSONObject()
                .put("path", "/home/op/.ssh/authorized_keys")
                .put("format", "env")
                .put("key", "ssh-ed25519 AAAAC3Nza host")
                .put("value", "comment"),
        )
        val text = humanOperation(raw)
        assertTrue(text.contains("/home/op/.ssh/authorized_keys"))
        assertTrue(text.contains("key: ssh-ed25519 AAAAC3Nza host"))
        assertTrue(text.contains("value: comment"))
    }

    @Test
    fun `long config value is truncated with raw hint`() {
        val longValue = "x".repeat(1000)
        val raw = op(
            "conf.set",
            JSONObject()
                .put("path", "/etc/app.conf")
                .put("format", "env")
                .put("key", "TOKEN")
                .put("value", longValue),
        )
        val text = humanOperation(raw)
        assertTrue(text.contains("value: " + "x".repeat(400)))
        assertTrue(text.contains("show raw for the full value"))
        assertTrue(!text.contains("x".repeat(401)))
    }

    @Test
    fun `empty config value is stated explicitly`() {
        val raw = op(
            "conf.set_kv",
            JSONObject()
                .put("path", "/etc/app.conf")
                .put("format", "env")
                .put("key", "FLAG")
                .put("value", ""),
        )
        assertEquals("Set config key: /etc/app.conf\nkey: FLAG\nvalue: (empty)", humanOperation(raw))
    }
}

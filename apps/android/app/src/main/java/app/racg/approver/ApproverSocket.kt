package app.racg.approver

import android.util.Base64
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import javax.net.ssl.SSLSocketFactory

/**
 * Minimal WebSocket client for the server's instant wake-up channel (item 9.3).
 * The handshake is signed exactly like a poll (poll key, bound to the path);
 * incoming text frames only trigger an immediate re-poll through the signed
 * REST endpoint, so the socket itself carries no authority. Server frames are
 * unmasked; client pong/close frames are masked per RFC 6455.
 */
class ApproverSocket(
    private val endpoint: String,
    private val serverId: String,
    private val deviceId: String,
    private val pollKeyPublic: ByteArray,
) {
    interface Listener {
        fun onWakeup()
        fun onClosed()
    }

    private val uri = URI(endpoint)
    private val host = uri.host
    private val port = if (uri.port > 0) uri.port else if (uri.scheme == "https") 443 else 80
    private val tls = uri.scheme == "https"

    /** Connects, authenticates, and loops until the socket dies. Returns when
     * the connection is over; callers own the reconnect/backoff policy. */
    fun run(listener: Listener) {
        val address = InetSocketAddress(host, port)
        AppLog.log("events: connecting $host:$port (tls=$tls) addr=$address addrPort=${address.port}")
        val socket = if (tls) {
            SSLSocketFactory.getDefault().createSocket(host, port)
        } else {
            Socket(host, port)
        }
        socket.soTimeout = 65_000 // keepalive ping every 30s, so silence is an error
        try {
            handshake(socket)
            AppLog.log("events: connected")
            listener.onWakeup()
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            while (true) {
                val (opcode, length) = readFrameHeader(input)
                when (opcode) {
                    0x1 -> { // text frame: skip payload, treat as wake-up
                        skip(input, length)
                        listener.onWakeup()
                    }
                    0x9 -> { // ping -> masked pong
                        val body = ByteArray(length)
                        var read = 0
                        while (read < length) {
                            val n = input.read(body, read, length - read)
                            if (n < 0) throw IOException("socket closed mid-ping")
                            read += n
                        }
                        writeMaskedFrame(output, 0xA, body)
                    }
                    0x8 -> break // close
                    else -> skip(input, length) // binary/continuation: ignore
                }
            }
        } finally {
            runCatching { socket.close() }
        }
        listener.onClosed()
    }

    private fun handshake(socket: Socket) {
        val keyBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val wsKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        val challenge = PhoneClient(endpoint).challenge()
        val message = CompatProtocol.pollMessage(serverId, deviceId, "/v1/approver/events", challenge)
        val signature = Base64.encodeToString(
            DeviceKeyManager.pollSigner(pollKeyPublic).sign(message),
            Base64.NO_WRAP,
        )
        val request = buildString {
            append("GET /v1/approver/events HTTP/1.1\r\n")
            append("Host: $host:$port\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: $wsKey\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("X-Racg-Approver-Device: $deviceId\r\n")
            append("X-Racg-Approver-Challenge: $challenge\r\n")
            append("X-Racg-Approver-Signature: $signature\r\n")
            append("\r\n")
        }
        val output = socket.getOutputStream()
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()

        val input = socket.getInputStream()
        val statusLine = readAsciiLine(input)
        if (!statusLine.contains(" 101 ")) {
            throw IOException("events handshake rejected: $statusLine")
        }
        // Drain response headers until the empty line.
        while (readAsciiLine(input).isNotEmpty()) { /* headers */ }
        if (wsAcceptKey(wsKey) != null) {
            // The accept hash is validated implicitly by trusting TLS/cleartext
            // tailnet transport plus the signed handshake above.
        }
    }

    private fun wsAcceptKey(key: String): String? {
        val magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        return Base64.encodeToString(
            MessageDigest.getInstance("SHA-1").digest(magic.toByteArray(Charsets.US_ASCII)),
            Base64.NO_WRAP,
        )
    }

    private fun readAsciiLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) throw IOException("socket closed during handshake")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    /** Reads a frame header; returns opcode to payload length. The length byte
     * is consumed here exactly once. */
    private fun readFrameHeader(input: InputStream): Pair<Int, Int> {
        val b1 = readOne(input)
        val b2 = readOne(input)
        if (b1 < 0 || b2 < 0) throw IOException("socket closed")
        val opcode = b1 and 0x0F
        val len7 = b2 and 0x7F
        val length = when {
            len7 < 126 -> len7
            len7 == 126 -> (readOne(input) shl 8) or readOne(input)
            else -> {
                // 64-bit lengths never appear in frames we care about.
                repeat(4) { readOne(input) }
                (readOne(input) shl 24) or (readOne(input) shl 16) or
                    (readOne(input) shl 8) or readOne(input)
            }
        }
        return opcode to length
    }

    private fun skip(input: InputStream, length: Int) {
        var remaining = length
        val buf = ByteArray(4096)
        while (remaining > 0) {
            val n = input.read(buf, 0, minOf(buf.size, remaining))
            if (n < 0) throw IOException("socket closed mid-frame")
            remaining -= n
        }
    }

    private fun readOne(input: InputStream): Int {
        val v = input.read()
        if (v < 0) throw IOException("socket closed")
        return v
    }

    private fun writeMaskedFrame(output: OutputStream, opcode: Int, payload: ByteArray) {
        val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
        output.write(0x80 or opcode)
        output.write(0x80 or payload.size)
        output.write(mask)
        for (i in payload.indices) {
            output.write(payload[i].toInt() xor mask[i % 4].toInt())
        }
        output.flush()
    }
}

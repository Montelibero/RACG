package app.racg.approver

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceKeyTest {
    @Test
    fun `generates compatible Ed25519 key material`() {
        val first = DeviceKeyManager.generate()
        val second = DeviceKeyManager.generate()

        assertFalse(first.encoded.contentEquals(second.encoded))
        assertEquals(32, first.encoded.size)
        assertEquals(32, DeviceKeyManager.publicKey(first).encoded.size)
    }

    @Test
    fun `signature verifies with generated public key`() {
        val privateKey = DeviceKeyManager.generate()
        val publicKey = DeviceKeyManager.publicKey(privateKey)
        val message = byteArrayOf(1, 2, 3, 4)
        val signature = UnlockedDeviceKey(publicKey.encoded, privateKey).sign(message)

        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey.encoded, 0))
        verifier.update(message, 0, message.size)
        assertTrue(verifier.verifySignature(signature))
    }
}

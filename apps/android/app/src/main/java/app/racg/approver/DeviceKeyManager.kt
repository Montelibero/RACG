package app.racg.approver

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

data class DeviceKeyMaterial(
    val publicKey: ByteArray,
    val encryptedPrivateKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DeviceKeyMaterial) return false
        return publicKey.contentEquals(other.publicKey) &&
            encryptedPrivateKey.contentEquals(other.encryptedPrivateKey)
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + encryptedPrivateKey.contentHashCode()
        return result
    }
}

data class UnlockedDeviceKey(
    val publicKey: ByteArray,
    val privateKey: Ed25519PrivateKeyParameters,
) {
    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

/**
 * Android Keystore stores only the wrapping AES key. The Ed25519 seed is
 * software-generated and encrypted at rest; this initial transport stage does
 * not yet provide hardware-backed approval signing.
 */
object DeviceKeyManager {
    private const val MASTER_ALIAS = "racg_approver_key_wrap_v1"
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val GCM_TAG_BITS = 128
    private const val ED25519_KEY_BYTES = 32

    fun generate(): Ed25519PrivateKeyParameters {
        val seed = ByteArray(ED25519_KEY_BYTES)
        SecureRandom().nextBytes(seed)
        return Ed25519PrivateKeyParameters(seed, 0)
    }

    fun publicKey(privateKey: Ed25519PrivateKeyParameters): Ed25519PublicKeyParameters =
        privateKey.generatePublicKey()

    fun protect(context: Context, privateKey: Ed25519PrivateKeyParameters): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey(context))
        val encrypted = cipher.doFinal(privateKey.encoded)
        return cipher.iv + encrypted
    }

    fun unprotect(context: Context, protectedKey: ByteArray): Ed25519PrivateKeyParameters {
        require(protectedKey.size > GCM_TAG_BITS / Byte.SIZE_BITS + 12) {
            "Protected device key is invalid"
        }
        val iv = protectedKey.copyOfRange(0, 12)
        val encrypted = protectedKey.copyOfRange(12, protectedKey.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey(context), GCMParameterSpec(GCM_TAG_BITS, iv))
        val seed = cipher.doFinal(encrypted)
        require(seed.size == ED25519_KEY_BYTES) { "Protected device key is invalid" }
        return Ed25519PrivateKeyParameters(seed, 0)
    }

    fun unlock(context: Context, protectedKey: ByteArray): UnlockedDeviceKey {
        val privateKey = unprotect(context, protectedKey)
        return UnlockedDeviceKey(
            publicKey = publicKey(privateKey).encoded,
            privateKey = privateKey,
        )
    }

    private fun masterKey(context: Context): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getEntry(MASTER_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        val spec = KeyGenParameterSpec.Builder(
            MASTER_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }
}

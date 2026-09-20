package app.racg.approver

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

data class DeviceKeyMaterial(
    val publicKey: ByteArray,
    val keyType: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DeviceKeyMaterial) return false
        return publicKey.contentEquals(other.publicKey) && keyType == other.keyType
    }

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + keyType.hashCode()
}

/** Signs with a private key that never leaves Android Keystore. */
class AndroidKeystoreDeviceSigner(
    private val privateKey: PrivateKey,
    override val publicKey: ByteArray,
    override val keyType: String,
) : DeviceSigner {
    override fun sign(message: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }
}

object DeviceKeyManager {
    private const val APPROVAL_KEY_ALIAS = "racg_approver_p256_v1"
    private const val POLL_KEY_ALIAS = "racg_approver_poll_p256_v1"
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"

    // KeePass-style window (item 11): one biometric confirmation unlocks
    // decision signing for five minutes; reads never need it (poll key).
    // NOTE: changing this only affects newly generated approval keys.
    private const val AUTH_WINDOW_SECONDS = 300

    /** Creates, or reuses, a non-exportable ECDSA P-256 user-auth key. */
    data class KeyPair(
        val approval: DeviceKeyMaterial,
        val poll: DeviceKeyMaterial,
    )

    fun createOrLoadPair(): KeyPair = KeyPair(
        approval = createOrLoad(APPROVAL_KEY_ALIAS, authRequired = true),
        poll = createOrLoad(POLL_KEY_ALIAS, authRequired = false),
    )

    fun approvalSigner(publicKey: ByteArray): AndroidKeystoreDeviceSigner =
        signer(APPROVAL_KEY_ALIAS, publicKey)

    fun pollSigner(publicKey: ByteArray): AndroidKeystoreDeviceSigner =
        signer(POLL_KEY_ALIAS, publicKey)

    /** Deletes both device keys. Only safe before a brand-new enrollment
     * (no server has registered these public keys yet); regenerating after
     * deleting the last configured server lets settings changes like the
     * auth window take effect. */
    fun deleteAll() {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        keyStore.deleteEntry(APPROVAL_KEY_ALIAS)
        keyStore.deleteEntry(POLL_KEY_ALIAS)
    }

    private fun createOrLoad(alias: String, authRequired: Boolean): DeviceKeyMaterial {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.let { entry ->
            return DeviceKeyMaterial(entry.certificate.publicKey.encoded, KEY_TYPE_ECDSA_P256)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setInvalidatedByBiometricEnrollment(false)

        if (authRequired) {
            builder.setUserAuthenticationRequired(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (authRequired) {
                builder.setUserAuthenticationParameters(
                    AUTH_WINDOW_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            }
        } else {
            if (authRequired) {
                builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
            }
        }
        generator.initialize(builder.build())
        val keyPair = generator.generateKeyPair()
        return DeviceKeyMaterial(keyPair.public.encoded, KEY_TYPE_ECDSA_P256)
    }

    private fun signer(alias: String, publicKey: ByteArray): AndroidKeystoreDeviceSigner {
        require(publicKey.contentEquals(createOrLoad(alias, alias == APPROVAL_KEY_ALIAS).publicKey)) {
            "Stored approver key does not match Android Keystore"
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Approver key is unavailable")
        return AndroidKeystoreDeviceSigner(entry.privateKey, publicKey, KEY_TYPE_ECDSA_P256)
    }
}

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
    private const val KEY_ALIAS = "racg_approver_p256_v1"
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val AUTH_WINDOW_SECONDS = 30

    /** Creates, or reuses, a non-exportable ECDSA P-256 user-auth key. */
    fun createOrLoad(): DeviceKeyMaterial {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let { entry ->
            return DeviceKeyMaterial(entry.certificate.publicKey.encoded, KEY_TYPE_ECDSA_P256)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        )
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                AUTH_WINDOW_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
        }
        generator.initialize(builder.build())
        val keyPair = generator.generateKeyPair()
        return DeviceKeyMaterial(keyPair.public.encoded, KEY_TYPE_ECDSA_P256)
    }

    fun signer(publicKey: ByteArray): AndroidKeystoreDeviceSigner {
        require(publicKey.contentEquals(createOrLoad().publicKey)) {
            "Stored approver key does not match Android Keystore"
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Approver key is unavailable")
        return AndroidKeystoreDeviceSigner(entry.privateKey, publicKey, KEY_TYPE_ECDSA_P256)
    }
}

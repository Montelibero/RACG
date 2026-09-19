package app.racg.approver

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.util.Base64
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.approverDataStore by preferencesDataStore(name = "racg_approver")

data class StoredSetup(
    val payload: SetupPayload,
    val keyMaterial: DeviceKeyMaterial,
)

interface ApproverStore {
    suspend fun load(): StoredSetup?
    suspend fun save(setup: StoredSetup)
    suspend fun clear()
}

class DataStoreApproverStore(private val context: Context) : ApproverStore {
    private object Keys {
        val serverId = stringPreferencesKey("server_id")
        val serverPublicKey = stringPreferencesKey("server_public_key")
        val approverId = stringPreferencesKey("approver_id")
        val endpoint = stringPreferencesKey("endpoint")
        val enrollmentToken = stringPreferencesKey("enrollment_token")
        val devicePublicKey = stringPreferencesKey("device_public_key")
        val encryptedDeviceKey = stringPreferencesKey("encrypted_device_key")
    }

    override suspend fun load(): StoredSetup? {
        val values = context.approverDataStore.data.first()
        val serverId = values[Keys.serverId] ?: return null
        val serverKey = values[Keys.serverPublicKey] ?: return null
        val approverId = values[Keys.approverId] ?: return null
        val endpoint = values[Keys.endpoint] ?: return null
        val deviceKey = values[Keys.devicePublicKey] ?: return null
        val encryptedKey = values[Keys.encryptedDeviceKey] ?: return null

        return StoredSetup(
            payload = SetupPayload(
                serverId = serverId,
                serverPublicKey = decode(serverKey),
                approverId = approverId,
                endpoint = endpoint,
                enrollmentToken = values[Keys.enrollmentToken]?.let(::decode),
            ),
            keyMaterial = DeviceKeyMaterial(
                publicKey = decode(deviceKey),
                encryptedPrivateKey = decode(encryptedKey),
            ),
        )
    }

    override suspend fun save(setup: StoredSetup) {
        context.approverDataStore.edit { values ->
            values[Keys.serverId] = setup.payload.serverId
            values[Keys.serverPublicKey] = encode(setup.payload.serverPublicKey)
            values[Keys.approverId] = setup.payload.approverId
            values[Keys.endpoint] = setup.payload.endpoint
            setup.payload.enrollmentToken?.let { values[Keys.enrollmentToken] = encode(it) }
            values[Keys.devicePublicKey] = encode(setup.keyMaterial.publicKey)
            values[Keys.encryptedDeviceKey] = encode(setup.keyMaterial.encryptedPrivateKey)
        }
    }

    override suspend fun clear() {
        context.approverDataStore.edit { it.clear() }
    }

    private fun encode(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    private fun decode(value: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw IllegalStateException("Stored setup data is invalid")
    }
}

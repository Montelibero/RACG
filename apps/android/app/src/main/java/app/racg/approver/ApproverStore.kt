package app.racg.approver

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.util.Base64
import kotlinx.coroutines.flow.first
import org.json.JSONArray
import org.json.JSONObject

private val Context.approverDataStore by preferencesDataStore(name = "racg_approver")

data class StoredSetup(
    val payload: SetupPayload,
    val keyMaterial: DeviceKeyMaterial,
)

interface ApproverStore {
    suspend fun loadAll(): List<StoredSetup>
    suspend fun save(setup: StoredSetup): List<StoredSetup>
}

class DataStoreApproverStore(private val context: Context) : ApproverStore {
    private object Keys {
        val setups = stringPreferencesKey("setups_v1")
        val legacyServerId = stringPreferencesKey("server_id")
        val legacyServerPublicKey = stringPreferencesKey("server_public_key")
        val legacyApproverId = stringPreferencesKey("approver_id")
        val legacyEndpoint = stringPreferencesKey("endpoint")
        val legacyEnrollmentToken = stringPreferencesKey("enrollment_token")
        val legacyDevicePublicKey = stringPreferencesKey("device_public_key")
        val legacyDeviceKeyType = stringPreferencesKey("device_key_type")
    }

    override suspend fun loadAll(): List<StoredSetup> {
        val values = context.approverDataStore.data.first()
        values[Keys.setups]?.let { return decodeSetups(it) }
        return listOfNotNull(loadLegacy(values))
    }

    override suspend fun save(setup: StoredSetup): List<StoredSetup> {
        val current = loadAll()
        val updated = current.filterNot { it.payload.serverId == setup.payload.serverId } + setup
        context.approverDataStore.edit { values ->
            values[Keys.setups] = encodeSetups(updated)
            clearLegacy(values)
        }
        return updated
    }

    private suspend fun loadLegacy(values: Preferences): StoredSetup? {
        val serverId = values[Keys.legacyServerId] ?: return null
        val serverKey = values[Keys.legacyServerPublicKey] ?: return null
        val approverId = values[Keys.legacyApproverId] ?: return null
        val endpoint = values[Keys.legacyEndpoint] ?: return null
        val deviceKey = values[Keys.legacyDevicePublicKey] ?: return null
        val deviceKeyType = values[Keys.legacyDeviceKeyType] ?: return null

        return StoredSetup(
            payload = SetupPayload(
                serverId = serverId,
                serverPublicKey = decode(serverKey),
                approverId = approverId,
                endpoint = endpoint,
                enrollmentToken = values[Keys.legacyEnrollmentToken]?.let(::decode),
            ),
            keyMaterial = DeviceKeyMaterial(decode(deviceKey), deviceKeyType),
        )
    }

    private suspend fun clearLegacy(values: androidx.datastore.preferences.core.MutablePreferences) {
        values.remove(Keys.legacyServerId)
        values.remove(Keys.legacyServerPublicKey)
        values.remove(Keys.legacyApproverId)
        values.remove(Keys.legacyEndpoint)
        values.remove(Keys.legacyEnrollmentToken)
        values.remove(Keys.legacyDevicePublicKey)
        values.remove(Keys.legacyDeviceKeyType)
    }

    private fun encodeSetups(setups: List<StoredSetup>): String {
        val array = JSONArray()
        setups.forEach { setup ->
            array.put(JSONObject().apply {
                put("server_id", setup.payload.serverId)
                put("server_public_key", encode(setup.payload.serverPublicKey))
                put("approver_id", setup.payload.approverId)
                put("endpoint", setup.payload.endpoint)
                setup.payload.enrollmentToken?.let { put("enrollment_token", encode(it)) }
                put("device_public_key", encode(setup.keyMaterial.publicKey))
                put("device_key_type", setup.keyMaterial.keyType)
            })
        }
        return array.toString()
    }

    private fun decodeSetups(raw: String): List<StoredSetup> {
        val array = JSONArray(raw)
        return List(array.length()) { index ->
            val value = array.getJSONObject(index)
            StoredSetup(
                payload = SetupPayload(
                    serverId = value.getString("server_id"),
                    serverPublicKey = decode(value.getString("server_public_key")),
                    approverId = value.getString("approver_id"),
                    endpoint = value.getString("endpoint"),
                    enrollmentToken = value.optString("enrollment_token", "")
                        .takeIf { it.isNotEmpty() }?.let(::decode),
                ),
                keyMaterial = DeviceKeyMaterial(
                    publicKey = decode(value.getString("device_public_key")),
                    keyType = value.getString("device_key_type"),
                ),
            )
        }
    }

    private fun encode(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    private fun decode(value: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw IllegalStateException("Stored setup data is invalid")
    }
}

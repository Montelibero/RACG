package app.racg.approver

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Server-through-the-phone administration (items 6, 8.3, 8.4): agent
 * sessions with extend/revoke, enrolled approver devices with revocation,
 * and on-demand pairing codes. Reads are poll-key signed (no biometrics);
 * every mutation asks for one biometric confirmation (item 11 window).
 */
@Composable
fun AdminScreen(
    setups: List<StoredSetup>,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var serverId by remember { mutableStateOf(setups.firstOrNull()?.payload?.serverId ?: "") }
    var sessions by remember { mutableStateOf<List<PhoneSessionInfo>>(emptyList()) }
    var devices by remember { mutableStateOf<List<PhoneDeviceInfo>>(emptyList()) }
    var status by remember { mutableStateOf("") }
    var pairingCode by remember { mutableStateOf<PairingCodeInfo?>(null) }
    var busy by remember { mutableStateOf(false) }

    val setup = setups.firstOrNull { it.payload.serverId == serverId } ?: setups.firstOrNull()

    fun load() {
        val target = setup ?: return
        scope.launch {
            busy = true
            runCatching {
                withContext(Dispatchers.IO) {
                    adminSessions(target) to adminDevices(target)
                }
            }.onSuccess { (s, d) ->
                sessions = s
                devices = d
                status = "${s.size} session(s), ${d.size} device(s)"
            }.onFailure { error ->
                status = "Load failed: ${error.message ?: "unknown error"}"
            }
            busy = false
        }
    }

    fun mutate(action: String, targetId: String, after: (JSONObject) -> Unit = {}) {
        val target = setup ?: return
        val activity = context as? FragmentActivity
        if (activity == null) {
            status = "Biometric authentication is unavailable"
            return
        }
        requestDeviceAuthentication(activity) {
            scope.launch {
                busy = true
                runCatching {
                    withContext(Dispatchers.IO) { adminAction(target, action, targetId) }
                }.onSuccess { response ->
                    status = "$action ok"
                    after(response)
                    load()
                }.onFailure { error ->
                    status = "$action failed: ${error.message ?: "unknown error"}"
                }
                busy = false
            }
        }
    }

    LaunchedEffect(serverId) {
        load()
    }

    AppFrame(title = "Admin", onBack = onBack) {
        if (setups.size > 1) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                setups.forEach { candidate ->
                    OutlinedButton(
                        onClick = { serverId = candidate.payload.serverId },
                        enabled = candidate.payload.serverId != serverId,
                    ) { Text(candidate.payload.serverId) }
                }
            }
        }
        Text(status, style = MaterialTheme.typography.bodyMedium)
        pairingCode?.let { code ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("New pairing code", style = MaterialTheme.typography.titleSmall)
                    Text(
                        code.code,
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Text("Valid for ${code.expiresInSeconds}s — enter it in 'racg login --pairing-code'.")
                }
            }
        }
        AppButton(
            text = "Issue pairing code",
            onClick = { mutate("pairing_code", "") { response ->
                pairingCode = PairingCodeInfo(
                    code = response.optString("pairing_code"),
                    expiresInSeconds = response.optInt("expires_in_seconds"),
                )
            } },
            outlined = true,
            enabled = !busy,
        )

        Text("Agent sessions", style = MaterialTheme.typography.titleMedium)
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(sessions, key = { it.sessionId }) { session ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(session.clientId.ifEmpty { session.sessionId.take(12) }, style = MaterialTheme.typography.titleSmall)
                        Text(
                            session.expiresAt?.let { "expires $it" } ?: "no expiry",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = {
                                mutate("sessions.extend", session.sessionId)
                            }, enabled = !busy) { Text("Extend") }
                            OutlinedButton(onClick = {
                                mutate("sessions.revoke", session.sessionId)
                            }, enabled = !busy) { Text("Revoke") }
                        }
                    }
                }
            }
            items(devices, key = { it.deviceId }) { device ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(device.deviceId, style = MaterialTheme.typography.titleSmall)
                        Text(
                            when {
                                !device.enabled -> "revoked"
                                device.hasPollKey -> "active (poll key)"
                                else -> "active (legacy)"
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (device.enabled) {
                            OutlinedButton(onClick = {
                                mutate("devices.revoke", device.deviceId)
                            }, enabled = !busy) { Text("Revoke device") }
                        }
                    }
                }
            }
        }
    }
}

data class PairingCodeInfo(val code: String, val expiresInSeconds: Int)

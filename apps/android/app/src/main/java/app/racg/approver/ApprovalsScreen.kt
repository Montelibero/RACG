package app.racg.approver

import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
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
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONTokener
import org.json.JSONArray
import org.json.JSONObject

@Composable
fun ApprovalsScreen(
    setup: StoredSetup,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var deciding by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Loading verified approvals") }
    var requests by remember { mutableStateOf<List<SignedApprovalRequest>>(emptyList()) }
    var selected by remember { mutableStateOf<SignedApprovalRequest?>(null) }

    fun load() {
        scope.launch {
            loading = true
            status = "Loading verified approvals"
            runCatching {
                withContext(Dispatchers.IO) {
                    val key = DeviceKeyManager.unlock(context, setup.keyMaterial.encryptedPrivateKey)
                    val uri = URI(setup.payload.endpoint)
                    val transport = ApproverTransport(setup, BrokerClient(uri.host, uri.port))
                    transport.pendingRequests(key)
                }
            }.onSuccess { verified ->
                requests = verified
                if (verified.none { it.request.requestId == selected?.request?.requestId }) selected = null
                status = if (verified.isEmpty()) {
                    "No pending approvals"
                } else {
                    "${verified.size} verified pending approval(s)"
                }
            }.onFailure { error ->
                status = "Pending load failed: ${error.message ?: "unknown error"}"
            }
            loading = false
        }
    }

    fun decide(action: String) {
        val request = selected ?: return
        scope.launch {
            deciding = true
            status = "Signing $action"
            runCatching {
                withContext(Dispatchers.IO) {
                    val key = DeviceKeyManager.unlock(context, setup.keyMaterial.encryptedPrivateKey)
                    val uri = URI(setup.payload.endpoint)
                    val transport = ApproverTransport(setup, BrokerClient(uri.host, uri.port))
                    transport.submitDecision(key, request, action, Instant.now())
                }
            }.onSuccess { receipt ->
                status = "$action accepted. Receipt: ${receipt.receipt.status}"
                load()
            }.onFailure { error ->
                status = "$action failed: ${error.message ?: "unknown error"}"
            }
            deciding = false
        }
    }

    LaunchedEffect(setup) {
        load()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            OutlinedButton(onClick = { load() }, enabled = !loading) { Text("Refresh") }
        }
        Text(status, style = MaterialTheme.typography.bodyMedium)

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(0.34f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(requests, key = { it.request.requestId }) { request ->
                Card(
                    onClick = { selected = request },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            request.request.clientId,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(request.request.requestId, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        selected?.let { request ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(0.46f),
            ) {
                RequestDetails(
                    request = request,
                    busy = loading || deciding,
                    onAllow = {
                        val activity = context as? FragmentActivity
                        if (activity == null) decide("ALLOW_ONCE") else authenticate(activity) {
                            decide("ALLOW_ONCE")
                        }
                    },
                    onDeny = {
                        val activity = context as? FragmentActivity
                        if (activity == null) decide("DENY") else authenticate(activity) {
                            decide("DENY")
                        }
                    },
                )
            }
        } ?: run {
            Text("Select a request to inspect it.", style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun RequestDetails(
    request: SignedApprovalRequest,
    busy: Boolean,
    onAllow: () -> Unit,
    onDeny: () -> Unit,
) {
    val operation = remember(request) {
        runCatching {
            val value = JSONTokener(String(request.request.operation, Charsets.UTF_8)).nextValue()
            when (value) {
                is JSONObject -> value.toString(2)
                is JSONArray -> value.toString(2)
                else -> value.toString()
            }
        }.getOrElse { String(request.request.operation, Charsets.UTF_8) }
    }
    val digest = remember(request) { ApprovalProtocol.requestDigest(request.request) }

    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("Verified request", style = MaterialTheme.typography.titleMedium)
        Text("Server: ${request.request.serverId}")
        Text("Agent: ${request.request.clientId}")
        Text("Request: ${request.request.requestId}")
        Text("Digest: $digest")
        Text("Signed operation:", style = MaterialTheme.typography.titleSmall)
        Text(
            operation,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onAllow, enabled = !busy) { Text("Allow once") }
            OutlinedButton(onClick = onDeny, enabled = !busy) { Text("Deny") }
        }
    }
}

private fun authenticate(activity: FragmentActivity, onSuccess: () -> Unit) {
    val executor = ContextCompat.getMainExecutor(activity)
    val prompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onSuccess()
            }
        },
    )
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm this decision")
        .setSubtitle("Device unlock signs the selected action")
        .setAllowedAuthenticators(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info)
}

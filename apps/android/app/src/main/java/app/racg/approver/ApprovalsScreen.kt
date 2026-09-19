package app.racg.approver

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
import androidx.fragment.app.FragmentActivity
import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

data class PendingRequestItem(
    val setup: StoredSetup,
    val request: SignedApprovalRequest,
) {
    val key: String
        get() = "${setup.payload.serverId}:${request.request.requestId}"
}

private data class AggregatePoll(
    val requests: List<PendingRequestItem>,
    val errors: List<String>,
)

@Composable
fun ApprovalsScreen(
    setups: List<StoredSetup>,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var deciding by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Unlock to load verified approvals") }
    var requests by remember { mutableStateOf<List<PendingRequestItem>>(emptyList()) }
    var selected by remember { mutableStateOf<PendingRequestItem?>(null) }

    fun load() {
        scope.launch {
            loading = true
            status = "Loading verified approvals"
            runCatching {
                withContext(Dispatchers.IO) {
                    coroutineScope {
                        setups.map { setup ->
                            async {
                                try {
                                    val transport = ApproverTransport(
                                        setup,
                                        BrokerClient(URI(setup.payload.endpoint).host, URI(setup.payload.endpoint).port),
                                    )
                                    transport.pendingRequests(DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey))
                                        .map { PendingRequestItem(setup, it) } to null
                                } catch (error: Exception) {
                                    emptyList<PendingRequestItem>() to "${setup.payload.serverId}: ${error.message ?: "failed"}"
                                }
                            }
                        }.awaitAll().fold(AggregatePoll(emptyList(), emptyList())) { result, pair ->
                            AggregatePoll(result.requests + pair.first, result.errors + listOfNotNull(pair.second))
                        }
                    }
                }
            }.onSuccess { poll ->
                requests = poll.requests
                if (poll.requests.none { it.key == selected?.key }) selected = null
                status = when {
                    poll.errors.isNotEmpty() -> poll.errors.joinToString("; ")
                    poll.requests.isEmpty() -> "No pending approvals"
                    else -> "${poll.requests.size} verified pending approval(s)"
                }
            }.onFailure { error ->
                status = "Pending load failed: ${error.message ?: "unknown error"}"
            }
            loading = false
        }
    }

    fun decide(action: String) {
        val target = selected ?: return
        scope.launch {
            deciding = true
            status = "Signing $action"
            runCatching {
                withContext(Dispatchers.IO) {
                    val transport = ApproverTransport(
                        target.setup,
                        BrokerClient(
                            URI(target.setup.payload.endpoint).host,
                            URI(target.setup.payload.endpoint).port,
                        ),
                    )
                    transport.submitDecision(
                        DeviceKeyManager.approvalSigner(target.setup.approvalKeyMaterial.publicKey),
                        target.request,
                        action,
                        Instant.now(),
                    )
                }
            }.onSuccess { receipt ->
                status = "$action accepted by ${target.setup.payload.serverId}. Receipt: ${receipt.receipt.status}"
                load()
            }.onFailure { error ->
                status = "$action failed: ${error.message ?: "unknown error"}"
            }
            deciding = false
        }
    }

    LaunchedEffect(setups) {
        (context as? FragmentActivity)?.let { activity ->
            requestDeviceAuthentication(activity) { load() }
        }
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
            OutlinedButton(
                onClick = {
                    (context as? FragmentActivity)?.let { activity ->
                        requestDeviceAuthentication(activity) { load() }
                    }
                },
                enabled = !loading,
            ) { Text("Refresh") }
        }
        Text(status, style = MaterialTheme.typography.bodyMedium)

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(0.34f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(requests, key = { it.key }) { request ->
                Card(
                    onClick = { selected = request },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            request.request.request.clientId,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(request.request.request.serverId, style = MaterialTheme.typography.bodySmall)
                        Text(request.request.request.requestId, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        selected?.let { target ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(0.46f),
            ) {
                RequestDetails(
                    request = target.request,
                    busy = loading || deciding,
                    onAllow = {
                        val activity = context as? FragmentActivity
                        if (activity == null) decide("ALLOW_ONCE") else requestDeviceAuthentication(activity) {
                            decide("ALLOW_ONCE")
                        }
                    },
                    onDeny = {
                        val activity = context as? FragmentActivity
                        if (activity == null) decide("DENY") else requestDeviceAuthentication(activity) {
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

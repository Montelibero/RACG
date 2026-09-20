package app.racg.approver

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import java.net.URI
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
    val requestId: String,
    val clientId: String,
    val operation: String,
    val operationSha256: String,
    val legacyRequest: SignedApprovalRequest? = null,
) {
    val key: String get() = setup.payload.serverId + ":" + requestId
}

private data class AggregatePoll(
    val requests: List<PendingRequestItem>,
    val errors: List<String>,
)

/** Screen 1 (item 12): the pending list, nothing else. */
@Composable
fun ApprovalsScreen(
    setups: List<StoredSetup>,
    onBack: () -> Unit,
    onOpen: (PendingRequestItem) -> Unit,
    onOpenHistory: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var status by remember { mutableStateOf("Loading verified approvals") }
    var requests by remember { mutableStateOf<List<PendingRequestItem>>(emptyList()) }

    // Item 9.7: pending-list reads are poll-key signed and never ask for
    // biometrics.
    fun load() {
        // Synchronous flag: the pull-to-scroll threshold (item 14) checks it
        // between drag events, so one gesture fires exactly one refresh.
        loading = true
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    coroutineScope {
                        setups.map { setup ->
                            async {
                                try {
                                    if (usesCompatibilityApi(setup.payload.endpoint)) {
                                        pendingCompatibilityRequests(setup).map {
                                            PendingRequestItem(setup, it.id, it.clientId, it.operation, it.operationSha256)
                                        } to null
                                    } else {
                                        val transport = ApproverTransport(
                                            setup,
                                            BrokerClient(URI(setup.payload.endpoint).host, URI(setup.payload.endpoint).port),
                                        )
                                        transport.pendingRequests(DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)).map {
                                            PendingRequestItem(
                                                setup = setup,
                                                requestId = it.request.requestId,
                                                clientId = it.request.clientId,
                                                operation = String(it.request.operation),
                                                operationSha256 = ApprovalProtocol.requestDigest(it.request),
                                            )
                                        } to null
                                    }
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

    LaunchedEffect(setups) { load() }

    val listState = rememberLazyListState()
    val pullScope = rememberCoroutineScope()
    var pullDistance by remember { mutableStateOf(0f) }
    // Item 14: browser-style pull-to-refresh via NestedScrollConnection.
    // While dragging: the spinner fades in with pull distance (no rotation).
    // On finger release: past the threshold exactly one refresh starts.
    val pullConnection = remember {
        object : androidx.compose.ui.input.nestedscroll.NestedScrollConnection {
            override fun onPreScroll(
                available: Offset,
                source: androidx.compose.ui.input.nestedscroll.NestedScrollSource,
            ): Offset {
                val atTop = listState.firstVisibleItemIndex == 0 &&
                    listState.firstVisibleItemScrollOffset == 0
                return if (atTop && available.y > 0f && !loading) {
                    pullDistance += available.y
                    available
                } else {
                    if (!atTop) pullDistance = 0f
                    Offset.Zero
                }
            }

            override suspend fun onPreFling(available: androidx.compose.ui.unit.Velocity): androidx.compose.ui.unit.Velocity {
                // Finger release: one refresh per gesture, never during drag.
                if (pullDistance >= 140f && !loading) {
                    pullScope.launch { load() }
                }
                pullDistance = 0f
                return androidx.compose.ui.unit.Velocity.Zero
            }
        }
    }
    AppFrame(title = "Approvals", onBack = onBack) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = { load() }, enabled = !loading) { Text("Refresh") }
            OutlinedButton(onClick = onOpenHistory) { Text("History") }
        }
        Text(status, style = MaterialTheme.typography.bodyMedium)
        Box(
            modifier = Modifier
                .fillMaxSize()
                .nestedScroll(pullConnection),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(requests, key = { it.key }) { request ->
                    Card(
                        onClick = { onOpen(request) },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                operationSummary(request.operation),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(request.clientId, style = MaterialTheme.typography.bodySmall)
                            Text(request.setup.payload.serverId, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            if (loading) {
                androidx.compose.material3.CircularProgressIndicator(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 8.dp),
                )
            } else if (pullDistance > 0f) {
                // Live feedback while the finger drags (item 14).
                androidx.compose.material3.CircularProgressIndicator(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 8.dp)
                        .alpha((pullDistance / 140f).coerceIn(0f, 1f)),
                )
            }
        }
    }
}

/** Screen 2 (item 12): human-readable details for one request, with the
 * decision buttons. Raw JSON lives on its own screen (item 12, screen 3). */
@Composable
fun RequestDetailsScreen(
    request: PendingRequestItem,
    onBack: () -> Unit,
    onShowRaw: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var deciding by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    var grantDialog by remember { mutableStateOf(false) }

    fun decide(action: String, rulePatterns: List<String>? = null, ruleDuration: String? = null, allowAuthRetry: Boolean = true) {
        val target = request
        val activity = context as? FragmentActivity
        scope.launch {
            deciding = true
            status = "Signing"
            runCatching {
                withContext(Dispatchers.IO) {
                    if (usesCompatibilityApi(target.setup.payload.endpoint)) {
                        decideCompatibilityRequest(
                            target.setup,
                            target.requestId,
                            action,
                            target.operationSha256,
                            rulePatterns,
                            ruleDuration,
                        )
                    } else {
                        val transport = ApproverTransport(
                            target.setup,
                            BrokerClient(
                                URI(target.setup.payload.endpoint).host,
                                URI(target.setup.payload.endpoint).port,
                            ),
                        )
                        transport.submitDecision(
                            DeviceKeyManager.approvalSigner(target.setup.approvalKeyMaterial.publicKey),
                            target.legacyRequest ?: throw IllegalStateException("Legacy request unavailable"),
                            action,
                            Instant.now(),
                        )
                    }
                }
            }.onSuccess {
                status = "$action accepted by ${target.setup.payload.serverId}"
            }.onFailure { error ->
                // Item 11: the approval key is valid for five minutes after a
                // single unlock. Try silently first; ask for biometrics only
                // when the signing window has actually expired.
                if (allowAuthRetry && isUserAuthError(error)) {
                    deciding = false
                    if (activity == null) {
                        status = "Biometric authentication is unavailable"
                        return@launch
                    }
                    status = "Unlock signing window"
                    requestDeviceAuthentication(activity) {
                        decide(action, rulePatterns, ruleDuration, allowAuthRetry = false)
                    }
                    return@launch
                }
                status = "$action failed: ${error.message ?: "unknown error"}"
            }
            deciding = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            OutlinedButton(onClick = onShowRaw) { Text("Show raw") }
        }
        Text(
            humanOperation(request.operation),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
        )
        Text("Agent: ${request.clientId}", style = MaterialTheme.typography.bodyMedium)
        Text("Server: ${request.setup.payload.serverId}", style = MaterialTheme.typography.bodyMedium)
        status.let { Text(status, style = MaterialTheme.typography.bodyMedium) }
        androidx.compose.foundation.layout.Spacer(modifier = Modifier.weight(1f))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            androidx.compose.material3.Button(
                onClick = { decide("ALLOW_ONCE") },
                enabled = !deciding,
                modifier = Modifier.weight(1f),
            ) { Text("Allow once") }
            OutlinedButton(
                onClick = { decide("DENY") },
                enabled = !deciding,
                modifier = Modifier.weight(1f),
            ) { Text("Deny") }
        }
        AppButton(
            text = "Allow for a while…",
            onClick = { grantDialog = true },
            outlined = true,
            enabled = !deciding,
        )
    }

    if (grantDialog) {
        GrantDialog(
            request = request,
            busy = deciding,
            onDismiss = { grantDialog = false },
            onGrant = { patterns, duration ->
                grantDialog = false
                decide("ALLOW_SESSION", rulePatterns = patterns, ruleDuration = duration)
            },
            onGrantAlways = { patterns ->
                grantDialog = false
                decide("ALLOW_ALWAYS", rulePatterns = patterns, ruleDuration = "always")
            },
        )
    }
}

/** Grant dialog (item 13), modeled on the TUI rule_scope overlay: one
 * checked+editable line per script segment (per path for fs and conf ops), all
 * checked by default; Save collects the checked patterns. Durations 1h, 24h
 * and session live inside the agent session; always is permanent. */
@Composable
private fun GrantDialog(
    request: PendingRequestItem,
    busy: Boolean,
    onDismiss: () -> Unit,
    onGrant: (patterns: List<String>, duration: String) -> Unit,
    onGrantAlways: (patterns: List<String>) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var candidates by remember { mutableStateOf<List<String>?>(null) }
    var problem by remember { mutableStateOf("") }
    var rows by remember { mutableStateOf(listOf(exactOperationPattern(request.operation))) }
    var checked by remember { mutableStateOf(listOf(true)) }

    LaunchedEffect(request.key) {
        runCatching {
            withContext(Dispatchers.IO) { scopeCandidatesForRequest(request.setup, request.requestId) }
        }.onSuccess { loaded ->
            if (loaded.isNotEmpty()) {
                candidates = loaded
                rows = loaded
                checked = List(loaded.size) { true }
            } else {
                problem = "no reusable rule scope could be derived"
            }
        }.onFailure { problem = it.message ?: "" }
    }

    fun checkedPatterns(): List<String> =
        rows.mapIndexedNotNull { i, pattern -> if (checked.getOrNull(i) == true && pattern.isNotBlank()) pattern else null }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Allow for a while") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("Rule scope (* is a glob):", style = MaterialTheme.typography.bodySmall)
                rows.forEachIndexed { index, pattern ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        androidx.compose.material3.Checkbox(
                            checked = checked.getOrNull(index) == true,
                            onCheckedChange = { value ->
                                checked = checked.toMutableList().also { if (index < it.size) it[index] = value }
                            },
                        )
                        OutlinedTextField(
                            value = pattern,
                            onValueChange = { value ->
                                rows = rows.toMutableList().also { if (index < it.size) it[index] = value }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            label = { Text("scope ${index + 1}") },
                        )
                    }
                }
                if (candidates == null && problem.isBlank()) {
                    Text("Loading scopes…", style = MaterialTheme.typography.bodySmall)
                }
                if (problem.isNotBlank()) {
                    Text("No reusable scope: $problem", style = MaterialTheme.typography.bodySmall)
                }
                Text("Duration:", style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = { onGrant(checkedPatterns(), "1h") },
                        enabled = !busy && checkedPatterns().isNotEmpty(),
                    ) { Text("1 hour") }
                    TextButton(
                        onClick = { onGrant(checkedPatterns(), "24h") },
                        enabled = !busy && checkedPatterns().isNotEmpty(),
                    ) { Text("24 hours") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = { onGrant(checkedPatterns(), "session") },
                        enabled = !busy && checkedPatterns().isNotEmpty(),
                    ) { Text("Session") }
                    TextButton(
                        onClick = { onGrantAlways(checkedPatterns()) },
                        enabled = !busy && checkedPatterns().isNotEmpty(),
                    ) { Text("Always") }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Screen 3 (item 12): the raw signed operation, only on explicit demand. */
@Composable
fun RawRequestScreen(
    request: PendingRequestItem,
    onBack: () -> Unit,
) {
    val pretty = remember(request) {
        runCatching {
            val value = JSONTokener(request.operation).nextValue()
            when (value) {
                is JSONObject -> value.toString(2)
                is JSONArray -> value.toString(2)
                else -> value.toString()
            }
        }.getOrElse { request.operation }
    }
    AppFrame(title = "Raw request", onBack = onBack) {
        Text("Digest: ${request.operationSha256}", style = MaterialTheme.typography.bodySmall)
        Text(
            pretty,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .weight(1f),
        )
    }
}

/** History screen (item 16): recent decisions from every source — phone,
 * TUI, auto-rules — mirroring the desktop TUI history list. */
@Composable
fun HistoryScreen(
    setups: List<StoredSetup>,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var status by remember { mutableStateOf("Loading history") }
    var entries by remember { mutableStateOf<List<PhoneHistoryEntry>>(emptyList()) }
    var serverId by remember { mutableStateOf(setups.firstOrNull()?.payload?.serverId ?: "") }
    val setup = setups.firstOrNull { it.payload.serverId == serverId } ?: setups.firstOrNull()

    fun load() {
        val target = setup ?: return
        scope.launch {
            loading = true
            runCatching {
                withContext(Dispatchers.IO) { decisionHistory(target) }
            }.onSuccess {
                entries = it
                status = "${it.size} recent decision(s)"
            }.onFailure { error ->
                status = "History load failed: ${error.message ?: "unknown error"}"
            }
            loading = false
        }
    }

    LaunchedEffect(serverId) { load() }

    AppFrame(title = "History", onBack = onBack) {
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
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(entries, key = { it.requestId + it.decidedAt }) { entry ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            operationSummary(entry.operation),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(historyVerdict(entry), style = MaterialTheme.typography.bodyMedium)
                        entry.clientId?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                        Text(formatHistoryTime(entry.decidedAt), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

internal fun historyVerdict(entry: PhoneHistoryEntry): String {
    val action = when (entry.decision) {
        "ALLOW_ONCE" -> "Allowed once"
        "ALLOW_SESSION" -> "Allowed for session"
        "ALLOW_ALWAYS" -> "Allowed always"
        "ALLOW_RULE" -> "Auto-approved"
        "DENY" -> "Denied"
        else -> entry.decision
    }
    val by = when {
        entry.decisionSource.startsWith("approver:") -> "by ${entry.decisionSource.removePrefix("approver:")} (phone)"
        entry.decisionSource == "rule" -> "by rule ${entry.ruleId ?: ""}"
        entry.decisionSource == "tui" -> "by TUI"
        else -> "by ${entry.decisionSource}"
    }
    val status = entry.status?.let { " — $it" } ?: ""
    return "$action $by$status".replace("  ", " ")
}

internal fun formatHistoryTime(decidedAt: String): String =
    runCatching { Instant.parse(decidedAt).atZone(java.time.ZoneId.systemDefault()).toString().take(19) }
        .getOrElse { decidedAt }

/** One-line summary for list cards (item 3/12). */
internal fun operationSummary(operation: String): String {
    return runCatching {
        val value = JSONTokener(operation).nextValue()
        if (value !is JSONObject) return@runCatching operation.take(120)
        val type = value.optString("type", value.optString("op", ""))
        val payload = value.optJSONObject("payload")
        if (type.isEmpty() || payload == null) return@runCatching operation.take(120)
        val detail = when {
            payload.has("argv") -> {
                val argv = payload.optJSONArray("argv")
                (0 until (argv?.length() ?: 0)).joinToString(" ") { argv!!.getString(it) }
            }
            payload.has("command") -> payload.optString("command")
            payload.has("path") -> payload.optString("path")
            payload.has("url") -> payload.optString("url")
            else -> ""
        }
        if (detail.isBlank()) type else "$type: $detail"
    }.getOrElse { operation.take(120) }
}

/** Multi-line human description for the details screen (item 12): scripts
 * are shown as plain text, path ops as plain sentences. */
internal fun humanOperation(operation: String): String {
    return runCatching {
        val value = JSONTokener(operation).nextValue()
        if (value !is JSONObject) return@runCatching operation.take(2000)
        val type = value.optString("type", value.optString("op", ""))
        val payload = value.optJSONObject("payload") ?: return@runCatching operation.take(2000)
        when (type) {
            "cmd.run" -> {
                val argv = payload.optJSONArray("argv")
                val args = (0 until (argv?.length() ?: 0)).map { argv!!.getString(it) }
                val scriptIndex = args.indexOfFirst { it == "-c" || it == "-lc" }
                if (scriptIndex >= 0 && scriptIndex + 1 < args.size) {
                    // Shell script: show it verbatim, one command per line.
                    args[scriptIndex + 1]
                } else {
                    "Run: " + args.joinToString(" ")
                }
            }
            "fs.read" -> "Read file: ${payload.optString("path")}"
            "fs.download" -> "Download file: ${payload.optString("path")}"
            "fs.patch_unified" -> "Patch file: ${payload.optString("path")}"
            "fs.upload" -> "Upload file to: ${payload.optString("path")}"
            "fs.append_block" -> "Append to file: ${payload.optString("path")}"
            "fs.replace_literal" -> "Replace in file: ${payload.optString("path")}"
            "conf.set" -> "Set config: ${payload.optString("path")}"
            "conf.set_kv" -> "Set config key: ${payload.optString("path")}"
            else -> operation.take(2000)
        }
    }.getOrElse { operation.take(2000) }
}

/** Default grant scope: the exact command with arguments (item 13). */
internal fun exactOperationPattern(operation: String): String {
    return runCatching {
        val value = JSONTokener(operation).nextValue()
        if (value !is JSONObject) return@runCatching ""
        val type = value.optString("type", value.optString("op", ""))
        val payload = value.optJSONObject("payload") ?: return@runCatching ""
        when {
            type == "cmd.run" && payload.has("argv") -> {
                val argv = payload.optJSONArray("argv")
                (0 until (argv?.length() ?: 0)).joinToString(" ") { argv!!.getString(it) }
            }
            payload.has("path") -> payload.optString("path")
            else -> ""
        }
    }.getOrElse { "" }
}

/** Keystore refused to sign because the user-auth window has expired
 * (item 11): retryable after one biometric unlock. */
internal fun isUserAuthError(error: Throwable): Boolean {
    if (error::class.qualifiedName == "android.security.keystore.UserNotAuthenticatedException") return true
    val message = (error.message ?: "").lowercase()
    return "user not authenticated" in message ||
        "requires user authentication" in message ||
        "user authentication required" in message
}

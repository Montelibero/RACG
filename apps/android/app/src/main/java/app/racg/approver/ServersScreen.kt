package app.racg.approver

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun ServersScreen(
    setups: List<StoredSetup>,
    onBack: () -> Unit,
    onAddServer: () -> Unit,
    onForget: (StoredSetup) -> Unit,
) {
    var pendingForget by remember { mutableStateOf<StoredSetup?>(null) }

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
            OutlinedButton(onClick = onAddServer) { Text("Add server") }
        }
        Text("My servers", style = MaterialTheme.typography.headlineMedium)
        Text(
            "These profiles stay on this phone. Removing one does not revoke access on the server.",
            style = MaterialTheme.typography.bodyMedium,
        )

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(setups, key = { it.payload.serverId }) { setup ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            setup.payload.serverId,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            "Profile stored on this phone",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        OutlinedButton(onClick = { pendingForget = setup }) {
                            Text("Remove from phone")
                        }
                    }
                }
            }
        }
    }

    pendingForget?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingForget = null },
            title = { Text("Remove server?") },
            text = {
                Text(
                    "${target.payload.serverId} will disappear from this phone. " +
                        "Its server-side access stays active until an administrator revokes it.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val targetToForget = target
                        pendingForget = null
                        onForget(targetToForget)
                    },
                ) { Text("Remove") }
            },
            dismissButton = {
                TextButton(onClick = { pendingForget = null }) { Text("Cancel") }
            },
        )
    }
}

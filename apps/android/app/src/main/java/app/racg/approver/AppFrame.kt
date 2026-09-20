package app.racg.approver

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Shared screen frame (item 2): status-bar safe area, a top bar with a
 * consistent Back control and screen title, bottom inset padding. */
@Composable
fun AppFrame(
    title: String,
    onBack: (() -> Unit)?,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 16.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (onBack != null) {
                OutlinedButton(onClick = onBack) { Text("Back") }
            }
            Text(title, style = MaterialTheme.typography.titleLarge)
        }
        content()
    }
}

/** Uniform action button (item 2): every action button on every screen gets
 * the same width and minimum height. */
@Composable
fun AppButton(
    text: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    outlined: Boolean = false,
) {
    val modifier = Modifier
        .fillMaxWidth()
        .heightIn(min = 48.dp)
    if (outlined) {
        OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier) { Text(text) }
    } else {
        Button(onClick = onClick, enabled = enabled, modifier = modifier) { Text(text) }
    }
}

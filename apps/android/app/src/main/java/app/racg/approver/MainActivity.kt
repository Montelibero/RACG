package app.racg.approver

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

private enum class Screen {
    Home,
    ScanSetup,
    SetupRead,
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var screen by remember { mutableStateOf(Screen.Home) }

                    when (screen) {
                        Screen.Home -> HomeScreen(
                            onScanSetup = { screen = Screen.ScanSetup },
                        )

                        Screen.ScanSetup -> BarcodeScannerView(
                            onScanned = { screen = Screen.SetupRead },
                            modifier = Modifier.fillMaxSize(),
                        )

                        Screen.SetupRead -> SetupReadScreen(
                            onBack = { screen = Screen.Home },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(onScanSetup: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("RACG Approver", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Set up this device with a QR code.",
            style = MaterialTheme.typography.bodyLarge,
        )
        Button(onClick = onScanSetup) {
            Text("Scan setup QR")
        }
        OutlinedButton(onClick = onScanSetup) {
            Text("Transfer to another phone")
        }
        Text(
            "This build reads the QR code only. It cannot approve anything yet.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Start,
        )
    }
}

@Composable
private fun SetupReadScreen(onBack: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("QR code read", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Setup storage and secure key creation will be connected next.",
            style = MaterialTheme.typography.bodyLarge,
        )
        OutlinedButton(onClick = onBack) {
            Text("Back")
        }
    }
}

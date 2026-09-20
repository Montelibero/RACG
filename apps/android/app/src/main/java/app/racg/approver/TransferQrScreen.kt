package app.racg.approver

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

fun setupQrBitmap(content: String, size: Int = 900): Bitmap {
    val matrix = QRCodeWriter().encode(
        content,
        BarcodeFormat.QR_CODE,
        size,
        size,
        mapOf(EncodeHintType.MARGIN to 2),
    )
    val bitmap = Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.RGB_565)
    for (x in 0 until matrix.width) {
        for (y in 0 until matrix.height) {
            bitmap.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
    }
    return bitmap
}

@Composable
fun TransferQrScreen(
    serverId: String,
    qr: String,
    onDone: () -> Unit,
) {
    val bitmap = remember(qr) { setupQrBitmap(qr) }
    AppFrame(title = "Transfer $serverId", onBack = onDone) {
        Text("Scan this once from the new phone. It expires in ten minutes and can be used only once.")
        Image(
            bitmap.asImageBitmap(),
            contentDescription = "Transfer QR",
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
        )
        AppButton(text = "Done", onClick = onDone, outlined = true)
    }
}

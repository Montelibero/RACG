package app.racg.approver

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

@Composable
fun BarcodeScannerView(
    onScanned: (String) -> Unit,
    modifier: Modifier = Modifier,
    hint: String = "Show the setup QR code",
) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }

    LaunchedEffect(Unit) {
        if (!hasPermission) launcher.launch(Manifest.permission.CAMERA)
    }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        if (hasPermission) {
            CameraPreview(onScanned = onScanned, hint = hint)
        } else {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Camera access is required")
                Spacer(Modifier.height(16.dp))
                Button(onClick = { launcher.launch(Manifest.permission.CAMERA) }) {
                    Text("Allow camera")
                }
            }
        }
    }
}

@OptIn(ExperimentalGetImage::class)
@Composable
private fun CameraPreview(
    onScanned: (String) -> Unit,
    hint: String,
) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember { BarcodeScanning.getClient() }
    var handled by remember { mutableStateOf(false) }
    val current by rememberUpdatedState(onScanned)

    DisposableEffect(Unit) {
        onDispose {
            executor.shutdown()
            scanner.close()
        }
    }

    Box(Modifier.fillMaxSize()) {
        AndroidView(
            factory = { context ->
                val previewView = PreviewView(context)
                val future = ProcessCameraProvider.getInstance(context)
                future.addListener({
                    val provider = future.get()
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }
                    val analysis = ImageAnalysis.Builder()
                        .setTargetResolution(android.util.Size(1920, 1080))
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                    analysis.setAnalyzer(executor) { proxy ->
                        val media = proxy.image
                        if (media == null || handled) {
                            proxy.close()
                            return@setAnalyzer
                        }
                        val image = InputImage.fromMediaImage(
                            media,
                            proxy.imageInfo.rotationDegrees,
                        )
                        scanner.process(image)
                            .addOnSuccessListener { codes ->
                                val raw = codes.firstOrNull()?.rawValue
                                if (raw != null && !handled) {
                                    handled = true
                                    current(raw)
                                }
                            }
                            .addOnFailureListener { error ->
                                Log.e("RACGScanner", "QR scan failed", error)
                            }
                            .addOnCompleteListener { proxy.close() }
                    }
                    try {
                        provider.unbindAll()
                        provider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analysis,
                        )
                    } catch (error: Exception) {
                        Log.e("RACGScanner", "Camera bind failed", error)
                    }
                }, ContextCompat.getMainExecutor(context))
                previewView
            },
            modifier = Modifier.fillMaxSize(),
        )

        Canvas(
            Modifier
                .fillMaxSize()
                .graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen },
        ) {
            val frame = size.minDimension * 0.6f
            val left = (size.width - frame) / 2f
            val top = (size.height - frame) / 2f
            val strokeWidth = 3.dp.toPx()
            val cornerLength = 32.dp.toPx()
            val cornerColor = Color(0xFF4CAF50)

            drawRect(Color.Black.copy(alpha = 0.4f))
            drawRoundRect(
                color = Color.Transparent,
                topLeft = Offset(left, top),
                size = Size(frame, frame),
                cornerRadius = CornerRadius(8.dp.toPx()),
                blendMode = BlendMode.Clear,
            )
            listOf(
                Offset(left, top) to Pair(
                    Offset(left + cornerLength, top),
                    Offset(left, top + cornerLength),
                ),
                Offset(left + frame, top) to Pair(
                    Offset(left + frame - cornerLength, top),
                    Offset(left + frame, top + cornerLength),
                ),
                Offset(left, top + frame) to Pair(
                    Offset(left + cornerLength, top + frame),
                    Offset(left, top + frame - cornerLength),
                ),
                Offset(left + frame, top + frame) to Pair(
                    Offset(left + frame - cornerLength, top + frame),
                    Offset(left + frame, top + frame - cornerLength),
                ),
            ).forEach { (corner, lines) ->
                drawLine(cornerColor, corner, lines.first, strokeWidth)
                drawLine(cornerColor, corner, lines.second, strokeWidth)
            }
        }

        Text(
            text = hint,
            color = Color.White,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 24.dp),
        )
    }
}

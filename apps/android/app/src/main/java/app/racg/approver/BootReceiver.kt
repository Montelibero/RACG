package app.racg.approver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restarts the approval watcher after a reboot (item 9.1). The service
 * itself checks for configured servers and stops when there are none. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ApproverPollService.start(context)
        }
    }
}

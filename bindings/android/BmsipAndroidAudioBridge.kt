package com.bymaker.bmsip

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Reference Android audio and network handover adapter for `bmsip-ffi` (`BmsipClient`).
 *
 * Uses `MediaRecorder.AudioSource.VOICE_COMMUNICATION` and `AcousticEchoCanceler`
 * for hardware AEC while exchanging 20 ms (160-sample @ 8 kHz) mono PCM16 frames.
 */
class BmsipAndroidAudioBridge(
    private val context: Context,
    config: FfiConfig,
) {
    private val client = BmsipClient(config)
    private val running = AtomicBoolean(true)
    private val mediaActive = AtomicBoolean(false)
    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Volatile
    var activeCallId: String? = null
        private set

    private var recordThread: Thread? = null
    private var playoutThread: Thread? = null
    private var eventThread: Thread? = null
    private var aec: AcousticEchoCanceler? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            runCatching { client.notifyNetworkChanged("0.0.0.0", 0u) }
        }
    }

    init {
        connectivityManager.registerNetworkCallback(NetworkRequest.Builder().build(), networkCallback)
        startEventLoop()
    }

    fun register() = client.registerAccount()

    fun dial(targetUri: String) = client.dial(targetUri)

    fun answer(callId: String) = client.answer(callId)

    fun hangup(callId: String) {
        client.hangup(callId)
        stopAudioThreads()
    }

    private fun startAudioThreads() {
        if (!mediaActive.compareAndSet(false, true)) return
        audioManager.mode = AudioManager.MODE_IN_COMMUNICATION

        val sampleRate = 8000
        val frameSamples = 160
        val minRecBuf = AudioRecord.getMinBufferSize(
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        ).coerceAtLeast(frameSamples * 4)

        val recorder = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            minRecBuf,
        )
        if (AcousticEchoCanceler.isAvailable()) {
            aec = AcousticEchoCanceler.create(recorder.audioSessionId)?.apply { enabled = true }
        }

        val minPlayBuf = AudioTrack.getMinBufferSize(
            sampleRate,
            AudioFormat.CHANNEL_OUT_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        ).coerceAtLeast(frameSamples * 4)

        val track = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build(),
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(sampleRate)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build(),
            )
            .setBufferSizeInBytes(minPlayBuf)
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()

        recorder.startRecording()
        track.play()

        recordThread = thread(start = true, name = "bmsip-android-rec") {
            val buf = ShortArray(frameSamples)
            while (mediaActive.get()) {
                val read = recorder.read(buf, 0, frameSamples)
                if (read == frameSamples) {
                    runCatching { client.pushCapturedPcm(buf.toList()) }
                }
            }
            recorder.stop()
            recorder.release()
            aec?.release()
            aec = null
        }

        playoutThread = thread(start = true, name = "bmsip-android-play") {
            val silence = ShortArray(frameSamples)
            while (mediaActive.get()) {
                val frame = client.popPlayoutPcm()?.toShortArray() ?: silence
                track.write(frame, 0, frame.size)
                Thread.sleep(20)
            }
            track.stop()
            track.release()
        }
    }

    private fun stopAudioThreads() {
        if (!mediaActive.compareAndSet(true, false)) return
        recordThread?.join(500)
        playoutThread?.join(500)
        recordThread = null
        playoutThread = null
        audioManager.mode = AudioManager.MODE_NORMAL
    }

    private fun startEventLoop() {
        eventThread = thread(start = true, name = "bmsip-android-events") {
            while (running.get()) {
                val ev = client.pollEvent(50u) ?: continue
                when (ev.kind) {
                    FfiEventKind.OUTBOUND_CALL_STARTED, FfiEventKind.INCOMING_CALL -> {
                        activeCallId = ev.callId
                    }
                    FfiEventKind.CALL_ESTABLISHED -> startAudioThreads()
                    FfiEventKind.CALL_TERMINATED -> {
                        stopAudioThreads()
                        activeCallId = null
                    }
                    FfiEventKind.STOPPED -> break
                    else -> Unit
                }
            }
        }
    }

    fun close() {
        running.set(false)
        stopAudioThreads()
        connectivityManager.unregisterNetworkCallback(networkCallback)
        client.shutdown()
        eventThread?.join(500)
    }
}


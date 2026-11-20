import AVFoundation
import CallKit
import Foundation
import Network

/// Reference iOS audio, CallKit, and network handover adapter for `bmsip-ffi` (`BmsipClient`).
///
/// Link against the UniFFI-generated `BmsipClient` Swift module from `crates/bmsip-ffi/src/bmsip.udl`.
final class BmsipIosAudioBridge: NSObject, CXProviderDelegate {
    private let client: BmsipClient
    private let audioEngine = AVAudioEngine()
    private let provider: CXProvider
    private let callController = CXCallController()
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "com.bmsip.network")
    private var eventTask: Task<Void, Never>?
    private var playoutNode: AVAudioSourceNode?
    private var activeCallUUID: UUID?
    private var activeCallId: String?

    init(config: FfiConfig, localizedName: String = "bmsip") throws {
        self.client = try BmsipClient(config: config)
        let cxConfig = CXProviderConfiguration()
        cxConfig.supportsVideo = false
        cxConfig.maximumCallsPerCallGroup = 1
        cxConfig.supportedHandleTypes = [.generic]
        self.provider = CXProvider(configuration: cxConfig)
        super.init()
        self.provider.setDelegate(self, queue: nil)
        startPathMonitoring()
        startEventLoop()
    }

    func register() throws {
        try client.registerAccount()
    }

    func startOutgoingCall(targetUri: String, handleDisplay: String) throws {
        let uuid = UUID()
        activeCallUUID = uuid
        let handle = CXHandle(type: .generic, value: handleDisplay)
        let action = CXStartCallAction(call: uuid, handle: handle)
        callController.request(CXTransaction(action: action)) { error in
            if let error = error {
                print("CallKit start error: \(error)")
            }
        }
        try client.dial(targetUri: targetUri)
    }

    func endActiveCall() throws {
        if let callId = activeCallId {
            try client.hangup(callId: callId)
        }
        if let uuid = activeCallUUID {
            let action = CXEndCallAction(call: uuid)
            callController.request(CXTransaction(action: action), completion: { _ in })
        }
        stopAudioPipeline()
    }

    private func startAudioPipeline() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth, .defaultToSpeaker])
        try session.setPreferredSampleRate(8000)
        try session.setPreferredIOBufferDuration(0.020)
        try session.setActive(true)

        // Enable Apple hardware acoustic echo cancellation (VoiceProcessingIO).
        let input = audioEngine.inputNode
        try input.setVoiceProcessingEnabled(true)

        guard let format = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: 8000, channels: 1, interleaved: true) else {
            return
        }

        input.installTap(onBus: 0, bufferSize: 160, format: format) { [weak self] buffer, _ in
            guard let self = self, let channelData = buffer.int16ChannelData?[0] else { return }
            let count = min(Int(buffer.frameLength), 160)
            var samples = [Int16](repeating: 0, count: 160)
            for i in 0..<count {
                samples[i] = channelData[i]
            }
            try? self.client.pushCapturedPcm(samples: samples)
        }

        let source = AVAudioSourceNode(format: format) { [weak self] _, _, frameCount, audioBufferList -> OSStatus in
            let abl = UnsafeMutableAudioBufferListPointer(audioBufferList)
            guard let buf = abl.first, let mData = buf.mData?.assumingMemoryBound(to: Int16.self) else {
                return noErr
            }
            let frames = self?.client.popPlayoutPcm() ?? [Int16](repeating: 0, count: Int(frameCount))
            let copyCount = min(Int(frameCount), frames.count)
            for i in 0..<copyCount {
                mData[i] = frames[i]
            }
            for i in copyCount..<Int(frameCount) {
                mData[i] = 0
            }
            return noErr
        }
        playoutNode = source
        audioEngine.attach(source)
        audioEngine.connect(source, to: audioEngine.mainMixerNode, format: format)
        try audioEngine.start()
    }

    private func stopAudioPipeline() {
        audioEngine.inputNode.removeTap(onBus: 0)
        if let node = playoutNode {
            audioEngine.detach(node)
            playoutNode = nil
        }
        audioEngine.stop()
        try? AVAudioSession.sharedInstance().setActive(false)
    }

    private func startPathMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, path.status == .satisfied else { return }
            try? self.client.notifyNetworkChanged(bindIp: "0.0.0.0", sipPort: 0)
        }
        pathMonitor.start(queue: monitorQueue)
    }

    private func startEventLoop() {
        eventTask = Task.detached { [weak self] in
            while let self = self, !Task.isCancelled {
                guard let ev = self.client.pollEvent(timeoutMs: 50) else { continue }
                switch ev.kind {
                case .outboundCallStarted, .incomingCall:
                    self.activeCallId = ev.callId
                case .callEstablished:
                    try? self.startAudioPipeline()
                case .callTerminated:
                    self.stopAudioPipeline()
                    self.activeCallId = nil
                case .stopped:
                    return
                default:
                    break
                }
            }
        }
    }

    func providerDidReset(_ provider: CXProvider) {
        stopAudioPipeline()
    }

    func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        if let callId = activeCallId {
            try? client.answer(callId: callId)
        }
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        if let callId = activeCallId {
            try? client.hangup(callId: callId)
        }
        stopAudioPipeline()
        action.fulfill()
    }

    deinit {
        eventTask?.cancel()
        pathMonitor.cancel()
        stopAudioPipeline()
        client.shutdown()
    }
}


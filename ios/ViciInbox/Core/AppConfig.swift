import Foundation

/// Static configuration for the isolated staging app.
enum AppConfig {

    /// Base URL of the Vici inbox backend (Railway).
    /// Override at runtime with the `VICI_SERVER_URL` env var when debugging.
    static let serverURL: URL = {
        if let raw = ProcessInfo.processInfo.environment["VICI_SERVER_URL"],
           let url = URL(string: raw) {
            return url
        }
        if let raw = Bundle.main.object(forInfoDictionaryKey: "VICI_SERVER_URL") as? String,
           let url = URL(string: raw),
           url.scheme == "https",
           url.host?.hasSuffix(".invalid") == false {
            return url
        }
        fatalError("Set the staging VICI_SERVER_URL after Railway creates its domain.")
    }()

    /// Telnyx push environment must match how the binary was signed:
    /// debug builds get a sandbox APNs token, TestFlight/App Store get production.
    /// Getting this wrong is the single most common cause of "push never arrives".
    static var pushEnvironmentIsProduction: Bool {
        #if DEBUG
        return false
        #else
        return true
        #endif
    }

    /// A connected SDK client receives the INVITE directly and reports it to
    /// CallKit. Asking Telnyx to also push while that socket is active makes
    /// SDK 4.1.2 disconnect the live socket in `processVoIPNotification`, which
    /// can discard the INVITE while the user is answering.
    static let pushWhenActive = false

    /// Shown as the app name in the native iOS call UI (lock screen, Recents).
    static let callKitDisplayName = "Vici Inbox Staging"
}

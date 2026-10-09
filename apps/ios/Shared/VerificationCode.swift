import Foundation

/// A one-time code the server found in an email, and the service it belongs to.
nonisolated struct VerificationCode: Codable, Sendable, Hashable, Identifiable {
    /// Stable handle shared with `ASOneTimeCodeCredentialIdentity`.
    var id: String
    var code: String
    /// Domain the code is for, matched against the site or app asking for it.
    var domain: String
    /// Human name for the QuickType suggestion ("GitHub").
    var service: String
    var subject: String
    var messageId: String
    var mailboxId: String
    var receivedAt: Date

    /// Codes are short-lived by design; anything older is noise in the
    /// QuickType bar and a small liability in the Keychain.
    static let lifetime: TimeInterval = 15 * 60

    var isLive: Bool { Date.now.timeIntervalSince(receivedAt) < Self.lifetime }

    /// What iOS shows under the code in the AutoFill suggestion.
    var label: String { "\(code) — \(service)" }

    /// A readable name for the QuickType row: "github.com" → "Github".
    static func serviceName(forDomain domain: String, fromName: String?) -> String {
        if let name = fromName?.trimmingCharacters(in: .whitespaces), !name.isEmpty,
           !name.lowercased().contains("no-reply"), !name.lowercased().contains("noreply"),
           !name.contains("@") {
            return name
        }
        guard let first = domain.split(separator: ".").first, !first.isEmpty else { return domain }
        return first.prefix(1).uppercased() + first.dropFirst()
    }
}

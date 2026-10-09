import XCTest

/// Unit coverage for how a found code is labelled in the QuickType bar. Finding
/// the code is the server's job (apps/worker/src/mail/otp.ts) and tested there.
final class VerificationCodeTests: XCTestCase {
    func testServiceNamePrefersTheSenderName() {
        XCTAssertEqual(
            VerificationCode.serviceName(forDomain: "github.com", fromName: "GitHub"),
            "GitHub"
        )
        // "no-reply" is not a name anybody wants to read in a suggestion.
        XCTAssertEqual(
            VerificationCode.serviceName(forDomain: "github.com", fromName: "no-reply"),
            "Github"
        )
        XCTAssertEqual(
            VerificationCode.serviceName(forDomain: "notion.so", fromName: nil),
            "Notion"
        )
    }
}

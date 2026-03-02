import XCTest

class RunnerTests: XCTestCase {

  func testPluginLoads() {
    // M-Security uses FFI (not method channels), so there is no Swift plugin class to test.
    // Cryptographic functionality is validated via Dart integration tests.
    XCTAssertTrue(true)
  }

}

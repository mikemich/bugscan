import XCTest
@testable import Counter

final class CounterTests: XCTestCase {
    func testConcurrentCount() {
        _ = countConcurrently(200)
    }

    func testTotal() {
        addToTotal(2)
        XCTAssertEqual(sharedTotal, 3, "total should be 3")
    }
}

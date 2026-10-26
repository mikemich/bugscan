import Foundation

public final class Counter {
    public var value = 0
    public init() {}
    public func increment() { value += 1 }
}

/// Increments from many threads without a lock: a data race.
public func countConcurrently(_ n: Int) -> Int {
    let c = Counter()
    DispatchQueue.concurrentPerform(iterations: n) { _ in c.increment() }
    return c.value
}

public var sharedTotal = 0   // global mutable state: flagged under strict concurrency

public func addToTotal(_ x: Int) { sharedTotal += x }

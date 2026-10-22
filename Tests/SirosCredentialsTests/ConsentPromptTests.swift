// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class ConsentPromptTests: XCTestCase {
    private typealias Prompt = ConsentPrompt<String, Bool>

    /// Records what the host UI is told, thread-safely.
    private final class Host: @unchecked Sendable {
        private let lock = NSLock()
        private var events: [String?] = []
        func record(_ pending: Prompt.Pending?) { lock.withLock { events.append(pending?.request) } }
        var seen: [String?] { lock.withLock { events } }
    }

    private func makePrompt(timeout: TimeInterval? = nil) -> (Prompt, Host) {
        let prompt = Prompt(decline: false, timeout: timeout)
        let host = Host()
        prompt.onChange = { host.record($0) }
        return (prompt, host)
    }

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var taken = false
        func take() -> Bool { lock.withLock { if taken { return false }; taken = true; return true } }
    }

    /// The asking task's value, or a failure (not a hang) when it never resumes: the two racers are unstructured
    /// so a never-resuming task cannot hold the test open.
    private func value(_ task: Task<Bool, Never>, file: StaticString = #filePath, line: UInt = #line) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            let once = Once()
            Task {
                let result = await task.value
                if once.take() { continuation.resume(returning: result) }
            }
            Task {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                if once.take() {
                    XCTFail("the asking call never resumed", file: file, line: line)
                    continuation.resume(returning: false)
                }
            }
        }
    }

    /// Waits until the prompt holds a question (the asking task has installed it).
    /// With a `host`, also waits until the host has been TOLD of the question: `current` becomes visible when the
    /// asker installs the entry, a moment before the notification is delivered, and a test that resolves or tears down
    /// in that window would see a history of `[nil]` or `[]` on correct code.
    private func pending(
        _ prompt: Prompt, host: Host? = nil, file: StaticString = #filePath, line: UInt = #line
    ) async throws -> Prompt.Pending {
        for _ in 0..<400 {
            if let current = prompt.current, host.map({ !$0.seen.isEmpty }) ?? true { return current }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("no question was pending", file: file, line: line)
        throw CancellationError()
    }

    /// Waits until the host has recorded `count` notifications (the final one is delivered after the answer).
    private func settled(_ host: Host, count: Int, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<400 {
            if host.seen.count >= count { return }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("the host was told \(host.seen.count) times, expected \(count)", file: file, line: line)
    }

    func testAnAnswerResolvesTheQuestionExactlyOnce() async throws {
        let (prompt, host) = makePrompt()
        let asked = Task { await prompt.ask("share?") }
        let question = try await pending(prompt, host: host)
        XCTAssertEqual(question.request, "share?")
        XCTAssertTrue(question.answer(true))
        XCTAssertFalse(question.answer(false), "a second answer is a no-op")
        XCTAssertFalse(question.decline())
        let answer = await value(asked)
        XCTAssertTrue(answer)
        XCTAssertNil(prompt.current)
        try await settled(host, count: 2)
        XCTAssertEqual(host.seen, ["share?", nil], "shown, then cleared")
    }

    func testDeclineAndDismissResolveToTheDeclineAnswer() async throws {
        let (prompt, _) = makePrompt()
        let declined = Task { await prompt.ask("a") }
        let toDecline = try await pending(prompt)
        XCTAssertTrue(toDecline.decline())
        let first = await value(declined)
        XCTAssertFalse(first)

        let dismissed = Task { await prompt.ask("b") }
        _ = try await pending(prompt)
        prompt.dismiss()
        let second = await value(dismissed)
        XCTAssertFalse(second)
        prompt.dismiss() // nothing pending: harmless
    }

    func testAQuestionNobodyCanShowIsDeclinedAtOnce() async {
        let prompt = Prompt(decline: false)   // no onChange
        let answer = await prompt.ask("anything")
        XCTAssertFalse(answer, "no silent consent")
        XCTAssertNil(prompt.current)
    }

    func testAnUnansweredQuestionIsDeclinedWhenItExpires() async throws {
        let (prompt, host) = makePrompt(timeout: 0.15)
        let start = Date()
        let answer = await prompt.ask("slow")
        XCTAssertFalse(answer)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.1)
        XCTAssertNil(prompt.current)
        try await settled(host, count: 2)
        XCTAssertEqual(host.seen, ["slow", nil])
    }

    /// A question's timer can only ever resolve ITS OWN question: it carries the question's id, so a timer left
    /// over from an answered question is a no-op against the next one. (Asserting it on a wall clock was flaky on
    /// slow runners and the id guard is what makes it true, so it is checked directly instead.)
    func testAnAnsweredQuestionsTimerCannotDeclineTheNextQuestion() async throws {
        let (prompt, _) = makePrompt(timeout: 60)
        let first = Task { await prompt.ask("one") }
        let toAnswer = try await pending(prompt)
        XCTAssertTrue(toAnswer.answer(true))
        let one = await value(first)
        XCTAssertTrue(one)
        let second = Task { await prompt.ask("two") }
        let question = try await pending(prompt)
        XCTAssertFalse(toAnswer.decline(), "the first question's handle (and so its timer) no longer touches anything")
        XCTAssertEqual(prompt.current?.request, "two")
        XCTAssertTrue(question.answer(true))
        let two = await value(second)
        XCTAssertTrue(two)
    }

    func testNonFiniteAndOutOfRangeTimeoutsNeverTrap() async throws {
        for timeout in [TimeInterval.infinity, .nan, 1e300, Double.greatestFiniteMagnitude] {
            let (prompt, _) = makePrompt(timeout: timeout)
            let asked = Task { await prompt.ask("waits for the user") }
            let question = try await pending(prompt)
            try await Task.sleep(nanoseconds: 30_000_000)
            XCTAssertNotNil(prompt.current, "no timer fired for \(timeout)")
            XCTAssertTrue(question.answer(true))
            let answer = await value(asked)
            XCTAssertTrue(answer)
        }
        let (negative, _) = makePrompt(timeout: -5)
        let expired = await negative.ask("already expired")
        XCTAssertFalse(expired, "a negative timeout expires at once")
        // A host that answers SYNCHRONOUSLY from its callback must not be able to approve an already-expired question:
        // a zero-duration timeout is declined before anything is installed or shown.
        for timeout in [-5.0, 0.0] {
            let approving = Prompt(decline: false, timeout: timeout)
            let shown = Once()
            approving.onChange = { pending in
                if let pending { _ = shown.take(); _ = pending.answer(true) }
            }
            let result = await approving.ask("expired")
            XCTAssertFalse(result, "timeout \(timeout): the synchronous approval is too late")
            XCTAssertTrue(shown.take(), "timeout \(timeout): the question was never shown to the host")
        }
    }

    func testANewQuestionDeclinesThePendingOne() async throws {
        let (prompt, host) = makePrompt()
        let first = Task { await prompt.ask("first") }
        let stale = try await pending(prompt)
        let second = Task { await prompt.ask("second") }
        let firstAnswer = await value(first)
        XCTAssertFalse(firstAnswer, "superseded")
        let fresh = try await pending(prompt)
        XCTAssertEqual(fresh.request, "second")
        XCTAssertFalse(stale.answer(true), "an outgoing question can never answer the new one")
        XCTAssertEqual(prompt.current?.request, "second", "and does not clear it")
        XCTAssertTrue(fresh.answer(true))
        let secondAnswer = await value(second)
        XCTAssertTrue(secondAnswer)
        try await settled(host, count: 3)
        XCTAssertEqual(host.seen.last ?? "x", nil)
    }

    func testCancellingTheAskingTaskDeclinesAndWithdrawsTheQuestion() async throws {
        let (prompt, host) = makePrompt()
        let asked = Task { await prompt.ask("cancel me") }
        let question = try await pending(prompt, host: host)
        asked.cancel()
        let answer = await value(asked)
        XCTAssertFalse(answer)
        XCTAssertNil(prompt.current)
        XCTAssertFalse(question.answer(true), "too late")
        try await settled(host, count: 2)
        XCTAssertEqual(host.seen, ["cancel me", nil])
    }

    func testATaskCancelledBeforeAskingNeverShowsAQuestion() async {
        let (prompt, host) = makePrompt()
        let asked = Task { () -> Bool in
            try? await Task.sleep(nanoseconds: 50_000_000)   // cancelled while sleeping
            return await prompt.ask("never")
        }
        asked.cancel()
        let answer = await value(asked)
        XCTAssertFalse(answer)
        XCTAssertEqual(host.seen, [])
    }

    /// The whole point: however answer, decline, dismiss and the timer race, exactly one of them wins and the
    /// asking call resumes once with the matching value.
    func testRacingResolversProduceExactlyOneWinner() async throws {
        for round in 0..<150 {
            let (prompt, _) = makePrompt()
            let asked = Task { await prompt.ask("race \(round)") }
            let question = try await pending(prompt)
            let wins = await withTaskGroup(of: (Bool, Bool).self, returning: [(Bool, Bool)].self) { group in
                group.addTask { (true, question.answer(true)) }
                group.addTask { (false, question.decline()) }
                group.addTask { (false, question.answer(false)) }
                group.addTask { prompt.dismiss(); return (false, false) }
                group.addTask { asked.cancel(); return (false, false) }
                var out: [(Bool, Bool)] = []
                for await result in group { out.append(result) }
                return out
            }
            let value = await value(asked)
            let winners = wins.filter { $0.1 }
            // dismiss() and the task cancellation may also win (declining); each question resolves once.
            XCTAssertLessThanOrEqual(winners.count, 1, "round \(round)")
            if let winner = winners.first, winner.0 { XCTAssertTrue(value, "the answer(true) winner's value is returned") }
            if winners.isEmpty || !(winners.first?.0 ?? false) { XCTAssertFalse(value) }
            XCTAssertNil(prompt.current)
        }
    }

    func testManyConcurrentQuestionsLeaveExactlyOneAnswerable() async throws {
        let (prompt, _) = makePrompt()
        let tasks = (0..<25).map { n in Task { await prompt.ask("q\(n)") } }
        // wait for the queue to settle on one pending question, then answer it
        try await Task.sleep(nanoseconds: 200_000_000)
        let last = try await pending(prompt)
        XCTAssertTrue(last.answer(true))
        var accepted = 0
        for task in tasks where await value(task) { accepted += 1 }
        XCTAssertEqual(accepted, 1, "every other question was declined by supersede")
        XCTAssertNil(prompt.current)
    }

    // MARK: Copilot review: notification order and cancellation before installation

    func testACancellationBeforeInstallationDeclinesWithoutPublishingAnAnswerableQuestion() async {
        let prompt = Prompt(decline: false)
        let shown = Counter()
        // A host that approves synchronously, the moment it is told: if the question were published, this would win.
        prompt.onChange = { pending in
            if let pending { shown.increment(); pending.answer(true) }
        }
        // The hook runs synchronously inside the asking task, so cancelling the CURRENT task is always before installation.
        prompt.beforeInstall = { withUnsafeCurrentTask { $0?.cancel() } }
        let asked = Task { await prompt.ask("cancelled in the window") }
        let answer = await value(asked)
        XCTAssertFalse(answer, "cancelled before it was installed: declined, not approved")
        XCTAssertEqual(shown.value, 0, "nothing answerable was published")
        XCTAssertNil(prompt.current)
    }

    /// However installs, answers and supersedes interleave (callbacks even sleep to widen the windows), the last
    /// thing the host was told is the question that is current.
    func testTheLastNotificationAlwaysMatchesTheCurrentQuestion() async throws {
        for round in 0..<60 {
            let prompt = Prompt(decline: false)
            let seen = Last()
            prompt.onChange = { pending in
                if round % 2 == 0 { Thread.sleep(forTimeInterval: 0.0005) }
                seen.set(pending?.request)
            }
            let tasks = (0..<6).map { n in Task { await prompt.ask("q\(n)") } }
            try await Task.sleep(nanoseconds: UInt64(round % 5) * 1_000_000)
            // answer whatever is current from two directions at once
            await withTaskGroup(of: Void.self) { group in
                group.addTask { prompt.current?.answer(true) }
                group.addTask { prompt.dismiss() }
            }
            // late installers may still be pending: end the round by declining until every asker resumed
            try await Task.sleep(nanoseconds: 40_000_000)
            prompt.dismiss()
            for task in tasks { _ = await value(task) }
            prompt.dismiss()
            // Quiesce: wait for in-flight deliveries to finish
            try await Task.sleep(nanoseconds: 30_000_000)
            XCTAssertEqual(seen.value, prompt.current?.request, "round \(round)")
        }
    }

    /// A callback that answers synchronously must neither deadlock nor reorder.
    func testASynchronousCallbackAnswersWithoutDeadlock() async {
        let prompt = Prompt(decline: false)
        prompt.onChange = { pending in pending?.answer(true) }
        let a = await prompt.ask("a")
        let b = await prompt.ask("b")
        XCTAssertTrue(a)
        XCTAssertTrue(b)
        XCTAssertNil(prompt.current)
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func increment() { lock.withLock { n += 1 } }
        var value: Int { lock.withLock { n } }
    }

    private final class Last: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: String?
        func set(_ value: String?) { lock.withLock { stored = value } }
        var value: String? { lock.withLock { stored } }
    }

    // MARK: teardown (the host clears onChange while an asker is installing)

    func testClearingTheCallbackRetiresTheQuestionThatIsPending() async throws {
        let (prompt, host) = makePrompt()
        let asked = Task { await prompt.ask("pending at teardown") }
        _ = try await pending(prompt, host: host)
        prompt.onChange = nil
        let answer = await value(asked)
        XCTAssertFalse(answer, "no UI left to answer it: declined, not suspended forever")
        XCTAssertNil(prompt.current)
        XCTAssertEqual(host.seen, ["pending at teardown"], "the host had been told once; it cleared its callback itself")
    }

    func testAnAskerThatInstallsAfterTheCallbackWasClearedIsDeclined() async {
        let (prompt, _) = makePrompt()
        // between the asker's first check and its installation the host tears down
        prompt.beforeInstall = { prompt.onChange = nil }
        let answer = await value(Task { await prompt.ask("late asker") })
        XCTAssertFalse(answer)
        XCTAssertNil(prompt.current)
    }
}

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
    private func pending(_ prompt: Prompt, file: StaticString = #filePath, line: UInt = #line) async throws -> Prompt.Pending {
        for _ in 0..<400 {
            if let current = prompt.current { return current }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("no question was pending", file: file, line: line)
        throw CancellationError()
    }

    func testAnAnswerResolvesTheQuestionExactlyOnce() async throws {
        let (prompt, host) = makePrompt()
        let asked = Task { await prompt.ask("share?") }
        let question = try await pending(prompt)
        XCTAssertEqual(question.request, "share?")
        XCTAssertTrue(question.answer(true))
        XCTAssertFalse(question.answer(false), "a second answer is a no-op")
        XCTAssertFalse(question.decline())
        let answer = await value(asked)
        XCTAssertTrue(answer)
        XCTAssertNil(prompt.current)
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

    func testAnUnansweredQuestionIsDeclinedWhenItExpires() async {
        let (prompt, host) = makePrompt(timeout: 0.15)
        let start = Date()
        let answer = await prompt.ask("slow")
        XCTAssertFalse(answer)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.1)
        XCTAssertNil(prompt.current)
        XCTAssertEqual(host.seen, ["slow", nil])
    }

    func testAnAnswerBeforeTheDeadlineCancelsTheTimer() async throws {
        let (prompt, _) = makePrompt(timeout: 0.2)
        let first = Task { await prompt.ask("one") }
        let toAnswer = try await pending(prompt)
        XCTAssertTrue(toAnswer.answer(true))
        let one = await value(first)
        XCTAssertTrue(one)
        // The first question's timer must not decline the NEXT question.
        let second = Task { await prompt.ask("two") }
        let question = try await pending(prompt)
        try await Task.sleep(nanoseconds: 120_000_000)
        XCTAssertTrue(question.answer(true), "still pending: the old timer is gone")
        let two = await value(second)
        XCTAssertTrue(two)
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
        XCTAssertEqual(host.seen.last ?? "x", nil)
    }

    func testCancellingTheAskingTaskDeclinesAndWithdrawsTheQuestion() async throws {
        let (prompt, host) = makePrompt()
        let asked = Task { await prompt.ask("cancel me") }
        let question = try await pending(prompt)
        asked.cancel()
        let answer = await value(asked)
        XCTAssertFalse(answer)
        XCTAssertNil(prompt.current)
        XCTAssertFalse(question.answer(true), "too late")
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
        let box = TaskBox()
        prompt.beforeInstall = { box.task?.cancel() }
        let asked = Task { await prompt.ask("cancelled in the window") }
        box.task = asked
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

    private final class TaskBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Task<Bool, Never>?
        var task: Task<Bool, Never>? { get { lock.withLock { stored } } set { lock.withLock { stored = newValue } } }
    }

    private final class Last: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: String?
        func set(_ value: String?) { lock.withLock { stored = value } }
        var value: String? { lock.withLock { stored } }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class SseEventParserTests: XCTestCase {

    private func events(_ text: String) -> [SseEvent] {
        var splitter = SseLineSplitter()
        var parser = SseEventParser()
        var out: [SseEvent] = []
        for byte in Array(text.utf8) {
            if let line = splitter.feed(byte: byte), let event = parser.feed(line: line) { out.append(event) }
        }
        return out
    }

    func testBlankLinesAreKeptSoEventsDispatch() {
        let out = events("id: 7\ndata: {\"a\":1}\n\ndata: x\ndata: y\n\n")
        XCTAssertEqual(out, [SseEvent(id: "7", event: nil, data: "{\"a\":1}"), SseEvent(id: nil, event: nil, data: "x\ny")])
    }

    func testCRLFAndLoneCRTerminators() {
        XCTAssertEqual(events("id:1\r\ndata:a\r\n\r\n").map(\.data), ["a"])
        XCTAssertEqual(events("data:a\r\r").map(\.data), ["a"])
    }

    func testCommentsAndUnknownFieldsAreIgnoredAndOneLeadingSpaceIsStripped() {
        let out = events(": keep-alive\nretry: 100\nfoo: bar\nevent: wmp\ndata:  two spaces\n\n")
        XCTAssertEqual(out, [SseEvent(id: nil, event: "wmp", data: " two spaces")])
    }

    func testAnEventWithoutDataIsNotDispatchedButItsIdIsRemembered() {
        var parser = SseEventParser()
        XCTAssertNil(parser.feed(line: "id: 9"))
        XCTAssertNil(parser.feed(line: ""))
        XCTAssertEqual(parser.lastEventId, "9")
    }

    func testLastEventIdPersistsAcrossEventsWithoutAnId() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 3"); _ = parser.feed(line: "data: a"); _ = parser.feed(line: "")
        _ = parser.feed(line: "data: b")
        let second = parser.feed(line: "")
        XCTAssertNil(second?.id)
        XCTAssertEqual(parser.lastEventId, "3", "an event without an id does not reset the stream's last id")
    }

    func testAnIdWithNulIsIgnored() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: a\u{0}b")
        _ = parser.feed(line: "data: x")
        let event = parser.feed(line: "")   // the blank line commits the block: only then could an accepted id show
        XCTAssertNil(parser.lastEventId)
        XCTAssertNil(event?.id)
        XCTAssertEqual(event?.data, "x")
    }

    func testReplayFilterDropsAReplayedIdAndNeverEventsWithoutOne() {
        var filter = SseReplayFilter()
        let a = SseEvent(id: "1", event: nil, data: "x")
        XCTAssertTrue(filter.admit(a))
        XCTAssertFalse(filter.admit(a), "the same id replayed after a resume is dropped")
        let anonymous = SseEvent(id: nil, event: nil, data: "x")
        XCTAssertTrue(filter.admit(anonymous))
        XCTAssertTrue(filter.admit(anonymous))
    }

    func testReplayFilterForgetsTheOldestPastItsCapacity() {
        var filter = SseReplayFilter(capacity: 2)
        for id in ["1", "2", "3"] { XCTAssertTrue(filter.admit(SseEvent(id: id, event: nil, data: "d"))) }
        XCTAssertTrue(filter.admit(SseEvent(id: "1", event: nil, data: "d")), "1 fell out of the window")
        XCTAssertFalse(filter.admit(SseEvent(id: "3", event: nil, data: "d")))
    }

    // Copilot review.
    func testAnUnfinishedBlockDoesNotAdvanceTheResumeCursor() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 7"); _ = parser.feed(line: "data: a"); _ = parser.feed(line: "")
        _ = parser.feed(line: "id: 8")           // the connection drops before the blank line
        XCTAssertEqual(parser.lastEventId, "7", "event 8 was never delivered; a resume must ask for what follows 7")
        _ = parser.feed(line: "")                // an id-only block commits
        XCTAssertEqual(parser.lastEventId, "8")
    }

    func testAnEmptyIdResetsTheCursorAndIsNeverADedupeKey() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 5"); _ = parser.feed(line: "")
        _ = parser.feed(line: "id:"); _ = parser.feed(line: "")
        XCTAssertNil(parser.lastEventId, "an empty id resets the cursor")
        var filter = SseReplayFilter()
        var admitted: [String] = []
        for payload in ["one", "two"] {
            _ = parser.feed(line: "id:"); _ = parser.feed(line: "data: \(payload)")
            if let event = parser.feed(line: ""), filter.admit(event) { admitted.append(event.data) }
        }
        XCTAssertEqual(admitted, ["one", "two"], "two different payloads with empty ids are both delivered")
    }

    func testOneLeadingByteOrderMarkIsIgnoredAtTheStartOfTheResponseOnly() {
        var dataFirst = SseEventParser()
        XCTAssertNil(dataFirst.feed(line: "\u{FEFF}data: a"))
        XCTAssertEqual(dataFirst.feed(line: "")?.data, "a")
        var idFirst = SseEventParser()
        _ = idFirst.feed(line: "\u{FEFF}id: 4"); _ = idFirst.feed(line: "data: b")
        XCTAssertEqual(idFirst.feed(line: "")?.id, "4")
        // later BOMs are preserved: that line is an unknown field and is ignored
        var later = SseEventParser()
        _ = later.feed(line: "data: c"); _ = later.feed(line: "\u{FEFF}data: d")
        XCTAssertEqual(later.feed(line: "")?.data, "c")
        // each response expects its own BOM
        var next = SseEventParser()
        _ = next.feed(line: "data: x"); _ = next.feed(line: "")
        next.beginResponse()
        _ = next.feed(line: "\u{FEFF}data: y")
        XCTAssertEqual(next.feed(line: "")?.data, "y")
    }

    func testADisconnectMidEventDoesNotLeakIntoTheNextResponse() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 1"); _ = parser.feed(line: "data: {\"a\":1}")   // the response ends here
        parser.beginResponse()
        _ = parser.feed(line: "data: {\"b\":2}")
        let event = parser.feed(line: "")
        XCTAssertEqual(event?.data, "{\"b\":2}")
        XCTAssertNil(event?.id, "the unfinished block's id is discarded with it")
        XCTAssertNil(parser.lastEventId)
        // the committed cursor survives a new response
        var committed = SseEventParser()
        _ = committed.feed(line: "id: 9"); _ = committed.feed(line: "data: z"); _ = committed.feed(line: "")
        committed.beginResponse()
        XCTAssertEqual(committed.lastEventId, "9")
    }

    func testTheEventDoesNotPrintItsData() {
        let event = SseEvent(id: "1", event: nil, data: "SECRET-SEED")
        var dumped = ""
        dump(event, to: &dumped)
        for text in ["\(event)", String(reflecting: event), dumped] { XCTAssertFalse(text.contains("SECRET-SEED"), text) }
    }

    // MARK: - Unicode: delimiters are scalars, ids are bytes

    /// A combining mark after the colon or the space belongs to the value, not to the delimiter.
    func testTheDelimiterIsAScalarEvenBeforeACombiningMark() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id:\u{0301}x")                  // field `id`, value "\u{0301}x"
        _ = parser.feed(line: "data: \u{0301}y")                // one space stripped, the mark kept
        let event = parser.feed(line: "")
        XCTAssertEqual(event?.id, "\u{0301}x")
        XCTAssertEqual(parser.lastEventId, "\u{0301}x")
        XCTAssertEqual(event?.data, "\u{0301}y")
        // A comment line is a colon scalar first, even with a mark after it.
        var commented = SseEventParser()
        XCTAssertNil(commented.feed(line: ":\u{0301}keep-alive"))
        _ = commented.feed(line: "data: d")
        XCTAssertEqual(commented.feed(line: "")?.data, "d")
    }

    func testTheSpaceAfterTheColonIsStrippedOnlyOnce() {
        var parser = SseEventParser()
        _ = parser.feed(line: "data:  two")
        XCTAssertEqual(parser.feed(line: "")?.data, " two")
    }

    /// Ids are opaque: canonically equivalent but different byte strings are different ids.
    func testReplayFilterComparesIdsByTheirBytes() {
        var filter = SseReplayFilter()
        let composed = SseEvent(id: "\u{00E9}", event: nil, data: "a")
        let decomposed = SseEvent(id: "e\u{0301}", event: nil, data: "b")
        XCTAssertEqual(composed.id, decomposed.id, "Swift String equality would call these the same id")
        XCTAssertTrue(filter.admit(composed))
        XCTAssertTrue(filter.admit(decomposed), "a different byte string is a different event")
        XCTAssertFalse(filter.admit(composed))
        XCTAssertFalse(filter.admit(decomposed))
    }

    // MARK: - One reader at a time

    func testOnlyOneOfManyConcurrentConnectsGetsToRead() async {
        let gate = SseReaderGate()
        let winners = await withTaskGroup(of: Int?.self) { group in
            for _ in 0..<64 { group.addTask { gate.tryStart() } }
            return await group.reduce(into: [Int]()) { if let generation = $1 { $0.append(generation) } }
        }
        XCTAssertEqual(winners.count, 1)
        XCTAssertTrue(gate.isCurrent(winners[0]))
    }

    func testAFinishedOrStoppedReaderFreesTheGateAndAStaleOneCannotFreeAnother() throws {
        let gate = SseReaderGate()
        let first = try XCTUnwrap(gate.tryStart())
        XCTAssertNil(gate.tryStart())
        gate.finish(first)
        let second = try XCTUnwrap(gate.tryStart(), "a finished reader frees the gate (a reconnect)")
        gate.finish(first)                                    // a stale generation
        XCTAssertTrue(gate.isCurrent(second))
        XCTAssertNil(gate.tryStart())
        gate.cancelCurrent()
        XCTAssertFalse(gate.isCurrent(second), "a stopped reader is no longer current")
        XCTAssertNotNil(gate.tryStart())
    }

    /// A reader's shared-state step runs only while it is current, and holds the gate for that whole step.
    func testIfCurrentRunsOnlyForTheCurrentReaderAndHoldsTheGateWhileRunning() throws {
        let gate = SseReaderGate()
        let first = try XCTUnwrap(gate.tryStart())
        XCTAssertEqual(gate.ifCurrent(first) { 7 }, 7)
        // While the body runs, a stop from another thread waits, so the step completes against current state.
        let started = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        var ran = false
        let worker = Thread {
            _ = gate.ifCurrent(first) { started.signal(); release.wait(); ran = true }
        }
        worker.start()
        started.wait()
        let stopper = DispatchQueue.global()
        let stopped = expectation(description: "cancelCurrent returns after the step")
        stopper.async { gate.cancelCurrent(); stopped.fulfill() }
        usleep(50_000)
        XCTAssertFalse(ran)
        release.signal()
        wait(for: [stopped], timeout: 5)
        XCTAssertTrue(ran)
        XCTAssertNil(gate.ifCurrent(first) { 8 }, "a stopped reader runs nothing")
        let second = try XCTUnwrap(gate.tryStart())
        XCTAssertNil(gate.ifCurrent(first) { 9 }, "and neither does a replaced one")
        XCTAssertEqual(gate.ifCurrent(second) { 10 }, 10)
    }

    /// Releasing the gate and publishing the terminal state are one step: a stale reader publishes nothing,
    /// and the current one publishes with the gate already open.
    func testFinishingPublishesOnlyForTheCurrentReaderAndWithTheGateOpen() throws {
        let gate = SseReaderGate()
        var published: [String] = []
        let first = try XCTUnwrap(gate.tryStart())
        gate.finish(first) { published.append("first") }
        XCTAssertEqual(published, ["first"])
        XCTAssertFalse(gate.isCurrent(first), "the gate was freed in the same step")
        let second = try XCTUnwrap(gate.tryStart(), "the gate is open for a successor")
        gate.finish(first) { published.append("stale") }       // the old reader's late terminal state
        XCTAssertEqual(published, ["first"], "a stale reader publishes nothing over its successor")
        gate.finish(second) { published.append("second") }
        XCTAssertEqual(published, ["first", "second"])
    }

    /// `start` installs the reader under the lock and `stop` tears it down under the same lock: a stop that is
    /// racing a start either sees the installed reader or runs first, never in between.
    func testStartInstallsAndStopTearsDownWithoutInterleaving() throws {
        let gate = SseReaderGate()
        var installed: [Int] = []
        var torn: [String] = []
        XCTAssertTrue(gate.start { installed.append($0) })
        XCTAssertFalse(gate.start { installed.append($0) }, "a second start while one runs installs nothing")
        XCTAssertEqual(installed.count, 1)
        gate.stop { torn.append("first") }
        XCTAssertTrue(gate.start { installed.append($0) }, "after a stop a new reader may start")
        XCTAssertEqual(installed.count, 2)
        // A stop issued while a start's install is running waits for it, so it tears down the NEW reader.
        let gate2 = SseReaderGate()
        let inInstall = DispatchSemaphore(value: 0)
        let finishInstall = DispatchSemaphore(value: 0)
        var order: [String] = []
        let starter = Thread { _ = gate2.start { _ in inInstall.signal(); finishInstall.wait(); order.append("installed") } }
        starter.start()
        inInstall.wait()
        let stopped = expectation(description: "stop returns")
        DispatchQueue.global().async { gate2.stop { order.append("stopped") }; stopped.fulfill() }
        usleep(50_000)
        XCTAssertEqual(order, [], "the stop has not got in between")
        finishInstall.signal()
        wait(for: [stopped], timeout: 5)
        XCTAssertEqual(order, ["installed", "stopped"])
    }
}

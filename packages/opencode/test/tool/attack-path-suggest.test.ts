import { describe, expect, test } from "bun:test"
import { computeDifficulty } from "@/tool/attack-path-suggest"

describe("computeDifficulty", () => {
  test("low cost returns Easy", () => {
    expect(computeDifficulty(10)).toBe("Easy")
    expect(computeDifficulty(30)).toBe("Easy")
  })

  test("medium cost returns Medium", () => {
    expect(computeDifficulty(31)).toBe("Medium")
    expect(computeDifficulty(80)).toBe("Medium")
  })

  test("high cost returns Hard", () => {
    expect(computeDifficulty(81)).toBe("Hard")
    expect(computeDifficulty(150)).toBe("Hard")
  })

  test("very high cost returns Very Hard", () => {
    expect(computeDifficulty(151)).toBe("Very Hard")
    expect(computeDifficulty(500)).toBe("Very Hard")
    expect(computeDifficulty(Infinity)).toBe("Very Hard")
  })

  test("zero cost returns Easy", () => {
    expect(computeDifficulty(0)).toBe("Easy")
  })
})

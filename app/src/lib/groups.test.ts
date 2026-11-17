import { expect, test } from "bun:test";
import { isSilentGroupPass } from "./groups";

test("isSilentGroupPass matches blank text and silent group markers", () => {
  expect(isSilentGroupPass("")).toBe(true);
  expect(isSilentGroupPass("   \n\t  ")).toBe(true);

  for (const marker of [
    "[PASS]",
    "[pass]",
    "[NO_REPLY]",
    "[no_reply]",
    "[SILENT]",
    "[Silent]",
  ]) {
    expect(isSilentGroupPass(marker)).toBe(true);
    expect(isSilentGroupPass(`  ${marker}  `)).toBe(true);
    expect(isSilentGroupPass(`*${marker}*`)).toBe(true);
    expect(isSilentGroupPass(`**${marker}**`)).toBe(true);
    expect(isSilentGroupPass(`_${marker}_`)).toBe(true);
    expect(isSilentGroupPass(`\`${marker}\``)).toBe(true);
    expect(isSilentGroupPass(`${marker}: nothing to add`)).toBe(true);
    expect(isSilentGroupPass(`${marker}.`)).toBe(true);
    expect(isSilentGroupPass(`${marker}!`)).toBe(true);
    expect(isSilentGroupPass(`${marker}- skipping`)).toBe(true);
    expect(isSilentGroupPass(`${marker}— skipping`)).toBe(true);
    expect(isSilentGroupPass(`${marker} no comment`)).toBe(true);
    expect(isSilentGroupPass(`*${marker}*: skipping`)).toBe(true);
  }
});

test("isSilentGroupPass ignores real replies and non-marker brackets", () => {
  expect(isSilentGroupPass("Here is the answer.")).toBe(false);
  expect(isSilentGroupPass("Sure, [PASS]")).toBe(false);
  expect(isSilentGroupPass("[PASSAGE] text")).toBe(false);
  expect(isSilentGroupPass("[PASS]word")).toBe(false);
  expect(isSilentGroupPass("[DONE] finished the task")).toBe(false);
});

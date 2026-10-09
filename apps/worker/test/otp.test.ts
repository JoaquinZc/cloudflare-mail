import { describe, expect, it } from "vitest";
import { type ParsedEmail, parseMime } from "../src/mail/mime.ts";
import { detectCode, extractOtp, parseSfItem } from "../src/mail/otp.ts";
import type { AuthResult } from "../src/mail/spam.ts";

async function mail(headers: string[], from = "noreply@example.com") {
  return parseMime(
    [`From: ${from}`, "To: me@test.dev", "Subject: Hello", ...headers, "", "Hi there"].join("\r\n"),
  );
}

const pass = { dmarc: "pass" };
// Only the header path, so a body guess can't mask a rejected header.
const header = async (parsed: Promise<ParsedEmail> | ParsedEmail, auth: AuthResult = pass) =>
  extractOtp(await parsed, auth, "");

describe("OTP-Token header", () => {
  it("binds the code to the origin", async () => {
    expect(await header(mail(['OTP-Token: "123456"; origin="https://example.com"']))).toEqual({
      code: "123456",
      domain: "example.com",
      origin: "https://example.com",
    });
  });

  it("unfolds a folded header and ignores unknown parameters", async () => {
    const parsed = mail([
      'OTP-Token: "A1B2C3";',
      ' origin="https://login.example.com"; token=:NjU0MzIx:; ttl=300',
    ]);
    expect(await header(parsed)).toEqual({
      code: "A1B2C3",
      domain: "login.example.com",
      origin: "https://login.example.com",
    });
  });

  it("accepts an origin on a sibling host of the sender", async () => {
    const parsed = mail(
      ['OTP-Token: "123456"; origin="https://auth.example.co.uk"'],
      "noreply@mail.example.co.uk",
    );
    expect((await header(parsed))?.origin).toBe("https://auth.example.co.uk");
  });

  it("ignores the header without DMARC", async () => {
    const parsed = await mail(['OTP-Token: "123456"; origin="https://example.com"']);
    expect(await header(parsed, { spf: "pass", dkim: "pass" })).toBeNull();
    expect(await header(parsed, { dmarc: "fail" })).toBeNull();
  });

  it("ignores an origin the sender doesn't own", async () => {
    expect(await header(mail(['OTP-Token: "123456"; origin="https://bank.test"']))).toBeNull();
  });

  it("ignores a duplicated header", async () => {
    const parsed = mail([
      'OTP-Token: "123456"; origin="https://example.com"',
      'OTP-Token: "654321"; origin="https://example.com"',
    ]);
    expect(await header(parsed)).toBeNull();
  });

  it.each([
    ['123456; origin="https://example.com"', "non-string code"],
    ['"123456"', "missing origin"],
    ['"123456"; origin=https', "token origin"],
    ['"123456"; origin="null"', "opaque origin"],
    ['"123456"; origin="http://example.com"', "insecure origin"],
    ['"123456"; origin="https://Example.com"', "uppercase origin"],
    ['"123456"; origin="https://example.com:443"', "default port"],
    ['"123456"; origin="https://example.com/"', "trailing slash"],
    ['"123456"; origin="https://example.com/login"', "path"],
    ['""; origin="https://example.com"', "empty code"],
    ['"123456"; origin="https://example.com" junk', "trailing garbage"],
  ])("rejects %s (%s)", async (value) => {
    expect(await header(mail([`OTP-Token: ${value}`]))).toBeNull();
  });
});

describe("body fallback", () => {
  it("guesses from the body, bound to the sender's domain, when the header isn't trusted", async () => {
    const parsed = await mail(
      ['OTP-Token: "481923"; origin="https://bank.test"'],
      "security@accounts.github.com",
    );
    expect(extractOtp(parsed, pass, "Your verification code is 481923")).toEqual({
      code: "481923",
      domain: "github.com",
      origin: null,
    });
  });
});

describe("detectCode", () => {
  it.each([
    ["481923 is your verification code", "", "481923"],
    ["Sign-in attempt", "Your security code is 720518. It expires in 10 minutes.", "720518"],
    ["", "Your one-time passcode: 481 923", "481923"],
    ["Ihr Bestätigungscode", "Ihr Code lautet 336291. Er ist 10 Minuten gültig.", "336291"],
    ["", "Verification code: A1B2C3", "A1B2C3"],
    ["", "Order 998877 shipped. Your verification code is 314159 for pickup.", "314159"],
    ["Sign in to Acme", "Use this code to sign in:\n\n  2026  \n\nIt expires soon.", "2026"],
    ["Your login link", "Hi,\n\n58 21 04\n\n839201\n\nThanks", "839201"],
  ])("finds the code in %j / %j", (subject, body, code) => {
    expect(detectCode(subject, body)).toBe(code);
  });

  it.each([
    ["Invoice 4471 for September", "Your total is 6.38 and the order number is 889321."],
    ["Security update", "Please verify your details before 2026."],
    ["Your code", "------ 000000 ------"],
    ["Verify", "PLEASE CONFIRM NOW"],
    ["Newsletter", "Login to read more.\n\n".concat("x ".repeat(40), "Call us at 5551234")],
  ])("finds nothing in %j / %j", (subject, body) => {
    expect(detectCode(subject, body)).toBeNull();
  });
});

describe("parseSfItem", () => {
  it("parses every bare item type as a parameter", () => {
    const item = parseSfItem(
      '"x"; a=1; b=-2.5; c=tok/en:1; d=:aGk=:; e=?0; f; g=@1700000000; h=%"f%c3%bcr"; i="q\\"\\\\"',
    );
    expect(item?.bare).toEqual({ type: "string", value: "x" });
    expect(Object.fromEntries(item!.params)).toEqual({
      a: { type: "integer", value: 1 },
      b: { type: "decimal", value: -2.5 },
      c: { type: "token", value: "tok/en:1" },
      d: { type: "bytes", value: "aGk=" },
      e: { type: "boolean", value: false },
      f: { type: "boolean", value: true },
      g: { type: "date", value: 1700000000 },
      h: { type: "display", value: "für" },
      i: { type: "string", value: 'q"\\' },
    });
  });

  it.each([
    '"unterminated',
    '"bad \\n escape"',
    '"x"; Origin="y"',
    '"x";',
    '"x"; a=1.2345',
    '"x"; a=1234567890123456',
    '"x"; a=?2',
    '"x"; a=%"%C3"',
    '"x" "y"',
    '"tab\there"',
  ])("rejects %s", (value) => {
    expect(parseSfItem(value)).toBeNull();
  });
});

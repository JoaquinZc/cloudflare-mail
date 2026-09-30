// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { detectCodesAndLinks } from "./detect-codes.ts";

const tracking = (input: Parameters<typeof detectCodesAndLinks>[0]) =>
  detectCodesAndLinks(input).tracking;

describe("tracking carrier", () => {
  const text = "Ihre Sendung ist unterwegs.\nSendungsnummer: 00340434512327126914";

  it("attributes an ambiguous digit run to the sending carrier", () => {
    const [t] = tracking({ from: "paketankuendigung@dhl.de", subject: "Paket", text });
    expect(t?.carrier).toBe("DHL");
  });

  it("uses the only carrier the mail names", () => {
    const [t] = tracking({
      from: "shop@example.com",
      text: "Shipped via FedEx. Tracking number: 123456789012",
    });
    expect(t?.carrier).toBe("FedEx");
    const [d] = tracking({
      from: "shop@example.com",
      text: "Versand mit DHL. Sendungsnummer: 123456789012",
    });
    expect(d?.carrier).toBe("DHL");
  });

  it("recognises a DHL Paket 'Sendung verfolgen' link", () => {
    const [t] = tracking({
      html: '<p>Paket unterwegs</p><a href="https://www.dhl.de/de/privatkunden/pakete-empfangen/verfolgen.html?piececode=00340434512327126914">Sendung verfolgen</a>',
    });
    expect(t).toMatchObject({ carrier: "DHL", number: "00340434512327126914" });
  });
});

import { fireEvent, screen } from "@testing-library/react";

export async function openC2FamilyVShellSection() {
  fireEvent.click(await screen.findByRole("button", { name: /^Family CS \/ VShell 画像$/ }));
  fireEvent.click(screen.getByRole("button", { name: /^VShell TCP/ }));
}

export function openC2EvidenceSection() {
  fireEvent.click(screen.getByRole("button", { name: /^证据 候选表与复核 notes$/ }));
}

export async function openC2VShellDecryptWorkbench() {
  await openC2FamilyVShellSection();
  fireEvent.click(screen.getByRole("button", { name: /^解密 流量解密工作台$/ }));
}

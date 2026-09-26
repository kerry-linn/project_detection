import type { DocumentDetail, DocumentSummary } from "../types/document";
import { request } from "./client";

export function listDocuments(token: string): Promise<DocumentSummary[]> {
  return request<DocumentSummary[]>("/documents", { token });
}

export function getDocument(token: string, documentId: string): Promise<DocumentDetail> {
  return request<DocumentDetail>(`/documents/${encodeURIComponent(documentId)}`, { token });
}

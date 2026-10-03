import type { DocumentDetail, DocumentSummary } from "../types/document";
import { request, requestPage } from "./client";

export function listDocuments(token: string, offset = 0) {
  return requestPage<DocumentSummary>(`/documents${offset ? `?offset=${offset}` : ""}`, token);
}

export function getDocument(token: string, documentId: string): Promise<DocumentDetail> {
  return request<DocumentDetail>(`/documents/${encodeURIComponent(documentId)}`, { token });
}

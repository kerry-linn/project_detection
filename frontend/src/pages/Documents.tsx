import { useState } from "react";
import { Pagination } from "../components/Pagination";
import { Link } from "react-router";

import { listDocuments } from "../api/documents";
import { EmptyState, ErrorNotice, Loading } from "../components/StatusMessage";
import { formatUtc } from "../format";
import { useApi } from "../hooks/useApi";

export function DocumentsPage() {
  const [offset, setOffset] = useState(0);
  const { data: page, error, loading } = useApi((token) => listDocuments(token, offset), `documents:${offset}`);
  const documents = page?.items;

  return (
    <>
      <h1>Documents</h1>
      {page && <><p>Showing {documents?.length} of {page.total} documents</p>
        <Pagination label="documents" offset={offset} total={page.total} onChange={setOffset} /></>}
      {loading && <Loading />}
      {error && <ErrorNotice error={error} />}
      {documents?.length === 0 && <EmptyState>No documents are visible to this account.</EmptyState>}
      {documents && documents.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Title</th>
                <th scope="col">Document ID</th>
                <th scope="col">Owner</th>
                <th scope="col">Updated</th>
              </tr>
            </thead>
            <tbody>
              {documents.map((document) => (
                <tr key={document.document_id}>
                  <td>
                    <Link to={`/documents/${encodeURIComponent(document.document_id)}`}>
                      {document.title}
                    </Link>
                  </td>
                  <td className="mono">{document.document_id}</td>
                  <td className="mono">{document.owner_id}</td>
                  <td className="nowrap">{formatUtc(document.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

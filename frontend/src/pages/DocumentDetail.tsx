import { Link, useParams } from "react-router";

import { getDocument } from "../api/documents";
import { ErrorNotice, Loading } from "../components/StatusMessage";
import { formatUtc } from "../format";
import { useApi } from "../hooks/useApi";

export function DocumentDetailPage() {
  const documentId = useParams().documentId ?? "";
  const { data: document, error, loading } = useApi(
    (token) => getDocument(token, documentId),
    `document:${documentId}`,
  );

  return (
    <>
      <p>
        <Link to="/documents">← All documents</Link>
      </p>
      {loading && <Loading />}
      {error && <ErrorNotice error={error} />}
      {document && (
        <>
          <h1>{document.title}</h1>
          <dl className="facts">
            <dt>Document ID</dt>
            <dd className="mono">{document.document_id}</dd>
            <dt>Organization</dt>
            <dd className="mono">{document.organization_id}</dd>
            <dt>Owner</dt>
            <dd className="mono">{document.owner_id}</dd>
            <dt>Created</dt>
            <dd>{formatUtc(document.created_at)}</dd>
            <dt>Updated</dt>
            <dd>{formatUtc(document.updated_at)}</dd>
          </dl>
          <h2>Content</h2>
          <div className="document-body">{document.body || <span className="muted">(empty)</span>}</div>
        </>
      )}
    </>
  );
}

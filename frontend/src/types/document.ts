export interface DocumentSummary {
  document_id: string;
  organization_id: string;
  owner_id: string;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface DocumentDetail extends DocumentSummary {
  body: string;
}

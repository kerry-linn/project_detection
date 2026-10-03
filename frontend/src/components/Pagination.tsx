interface Props {
  offset: number;
  total: number;
  limit?: number;
  onChange: (offset: number) => void;
  label: string;
}

export function Pagination({ offset, total, limit = 50, onChange, label }: Props) {
  return (
    <nav aria-label={`${label} pages`}>
      <button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Previous {label}
      </button>{" "}
      <button disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
        Next {label}
      </button>
    </nav>
  );
}

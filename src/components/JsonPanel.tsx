import type { DecodedSegment } from "../lib/decode";

export function JsonPanel({ title, segment }: { title: string; segment: DecodedSegment | undefined }) {
  return (
    <div className="json-panel">
      <h2>{title}</h2>
      {!segment ? (
        <p className="empty-note">—</p>
      ) : segment.json ? (
        <pre className="json-pre">{JSON.stringify(segment.json, null, 2)}</pre>
      ) : (
        <p className="panel-error" role="alert">
          {segment.error}
        </p>
      )}
    </div>
  );
}

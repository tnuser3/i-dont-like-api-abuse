"use client";

import { useCallback, useEffect, useState } from "react";

interface RequestEntry {
  path?: string;
  method?: string;
  timestamp?: number;
  userAgent?: string;
  referer?: string;
  ip?: string;
  visitorId?: string;
}

interface FingerprintComponent {
  value?: unknown;
  error?: unknown;
  duration?: number;
}

interface FingerprintEntry {
  deviceId: string;
  visitorId: string;
  visitorIds: string[];
  components: Record<string, FingerprintComponent>;
  componentHashes: string[];
  firstSeen: number;
  lastSeen: number;
}

function formatTime(ts: number) {
  return new Date(ts).toLocaleString();
}

function formatRelative(ts: number) {
  const sec = Math.floor((Date.now() - ts) / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

const PAGE_SIZE = 25;

export default function ManagerPage() {
  const [requests, setRequests] = useState<RequestEntry[]>([]);
  const [fingerprints, setFingerprints] = useState<FingerprintEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"requests" | "fingerprints">("requests");
  const [error, setError] = useState<string>("");
  const [highlightFingerprint, setHighlightFingerprint] = useState<string | null>(null);

  const fetchData = useCallback(async (pageNum = page) => {
    setLoading(true);
    setError("");
    try {
      const [reqRes, fpRes] = await Promise.all([
        fetch(`/api/manager/requests?page=${pageNum}&limit=${PAGE_SIZE}`),
        fetch("/api/manager/fingerprints"),
      ]);

      if (!reqRes.ok) throw new Error("Failed to fetch requests");
      if (!fpRes.ok) throw new Error("Failed to fetch fingerprints");

      const reqData = (await reqRes.json()) as {
        requests: RequestEntry[];
        total: number;
        page: number;
        limit: number;
      };
      const fpData = (await fpRes.json()) as { fingerprints: FingerprintEntry[] };

      setRequests(reqData.requests);
      setFingerprints(fpData.fingerprints);
      setTotal(reqData.total);
      setPage(reqData.page);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load data");
      setRequests([]);
      setFingerprints([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchData(page);
  }, [page]);

  useEffect(() => {
    const id = setInterval(() => fetchData(page), 10000);
    return () => clearInterval(id);
  }, [page, fetchData]);

  const totalPages = Math.ceil(total / PAGE_SIZE) || 1;

  const showFingerprint = (visitorId: string) => {
    setHighlightFingerprint(visitorId);
    setActiveTab("fingerprints");
    setTimeout(() => {
      document.getElementById(`fp-${visitorId}`)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }, 100);
    setTimeout(() => setHighlightFingerprint(null), 2000);
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-200 font-mono">
      <div className="max-w-6xl mx-auto px-6 py-10">
        <header className="mb-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <h1 className="text-2xl font-bold tracking-tight text-white">
            API Manager
          </h1>
          <div className="flex items-center gap-3">
            <button
              onClick={() => fetchData(page)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-neutral-900/80 border border-neutral-800 hover:border-neutral-700 text-neutral-300 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {loading ? "Loading…" : "Refresh"}
            </button>
            <span className="text-neutral-600 text-xs">
              Auto-refresh 10s
            </span>
          </div>
        </header>

        {error && (
          <div className="mb-6 p-4 rounded-lg bg-neutral-900/50 border border-neutral-800 text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="flex gap-2 mb-6 border-b border-neutral-800 pb-2">
          <button
            onClick={() => setActiveTab("requests")}
            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === "requests"
                ? "bg-neutral-900 border border-neutral-800 border-b-neutral-950 -mb-0.5 text-amber-500/90"
                : "bg-neutral-900/30 text-neutral-500 hover:text-neutral-300 border border-neutral-800 border-b-transparent"
            }`}
          >
            Requests ({total})
          </button>
          <button
            onClick={() => setActiveTab("fingerprints")}
            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === "fingerprints"
                ? "bg-neutral-900 border border-neutral-800 border-b-neutral-950 -mb-0.5 text-amber-500/90"
                : "bg-neutral-900/30 text-neutral-500 hover:text-neutral-300 border border-neutral-800 border-b-transparent"
            }`}
          >
            Fingerprints ({fingerprints.length})
          </button>
        </div>

        {activeTab === "requests" && (
          <section className="rounded-xl border border-neutral-800 bg-neutral-900/50 overflow-hidden shadow-lg shadow-black/20">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-800 bg-neutral-900">
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium">Time</th>
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium">Method</th>
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium">Path</th>
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium hidden md:table-cell">IP</th>
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium">Fingerprint</th>
                    <th className="text-left py-3 px-4 text-neutral-400 font-medium max-w-[180px] truncate hidden lg:table-cell">User-Agent</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.length === 0 && !loading && (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-neutral-600">
                        No requests yet
                      </td>
                    </tr>
                  )}
                  {requests.map((r, i) => (
                    <tr
                      key={i}
                      className="border-b border-neutral-800/60 hover:bg-neutral-800/40 transition-colors"
                    >
                      <td className="py-3 px-4 text-neutral-400 text-xs whitespace-nowrap">
                        {r.timestamp ? (
                          <span title={formatTime(r.timestamp)}>
                            {formatRelative(r.timestamp)}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${
                            r.method === "GET"
                              ? "text-amber-500"
                              : r.method === "POST"
                                ? "text-amber-500/90"
                                : "text-neutral-400"
                          }`}
                        >
                          {r.method ?? "—"}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-white font-mono text-xs">
                        {r.path ?? "—"}
                      </td>
                      <td className="py-3 px-4 text-neutral-400 text-xs hidden md:table-cell">
                        {r.ip ?? "—"}
                      </td>
                      <td className="py-3 px-4">
                        {r.visitorId ? (
                          <button
                            type="button"
                            onClick={() => showFingerprint(r.visitorId!)}
                            className="text-amber-500 hover:text-amber-400 text-xs font-mono truncate max-w-[120px] block text-left underline underline-offset-2"
                            title={`View fingerprint ${r.visitorId}`}
                          >
                            {r.visitorId.slice(0, 12)}…
                          </button>
                        ) : (
                          <span className="text-neutral-600">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-neutral-400 text-xs max-w-[180px] truncate hidden lg:table-cell">
                        {r.userAgent ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-neutral-800 bg-neutral-900/80">
                <span className="text-neutral-500 text-sm">
                  Page {page} of {totalPages} ({total} total)
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1 || loading}
                    className="px-3 py-1 rounded bg-neutral-800/50 border border-neutral-700 hover:border-neutral-600 text-neutral-400 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages || loading}
                    className="px-3 py-1 rounded bg-neutral-800/50 border border-neutral-700 hover:border-neutral-600 text-neutral-400 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </section>
        )}

        {activeTab === "fingerprints" && (
          <section className="space-y-4">
            {fingerprints.length === 0 && !loading && (
              <div className="rounded-xl border border-neutral-800 bg-neutral-900/50 py-16 text-center text-neutral-600">
                No fingerprints yet
              </div>
            )}
            {fingerprints.map((fp) => (
              <div
                key={fp.visitorId}
                id={`fp-${fp.visitorId}`}
                className={`rounded-xl border overflow-hidden transition-all duration-300 shadow-md ${
                  highlightFingerprint === fp.visitorId
                    ? "border-amber-500 ring-2 ring-amber-500/60 ring-offset-2 ring-offset-neutral-950 bg-amber-950/20"
                    : "border-neutral-800 bg-neutral-900/50 shadow-black/10"
                }`}
              >
                <div className="p-4 border-b border-neutral-800 bg-neutral-900/30 flex flex-wrap gap-4 items-center">
                  <div>
                    <span className="text-neutral-600 text-xs block">Device ID</span>
                    <span className="text-neutral-200 font-mono text-sm break-all">
                      {fp.deviceId}
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-600 text-xs block">Visitor ID</span>
                    <span className="text-neutral-200 font-mono text-sm break-all">
                      {fp.visitorId}
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-600 text-xs block">First seen</span>
                    <span className="text-neutral-400 text-sm">
                      {formatTime(fp.firstSeen)}
                    </span>
                  </div>
                  <div>
                    <span className="text-neutral-600 text-xs block">Last seen</span>
                    <span className="text-neutral-400 text-sm" title={formatTime(fp.lastSeen)}>
                      {formatRelative(fp.lastSeen)}
                    </span>
                  </div>
                  {fp.visitorIds.length > 1 && (
                    <div>
                      <span className="text-neutral-600 text-xs block">Linked devices</span>
                      <span className="text-neutral-400 text-sm">{fp.visitorIds.length}</span>
                    </div>
                  )}
                </div>
                <div className="p-4">
                  <h4 className="text-neutral-600 text-xs font-medium mb-3">Components</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {Object.entries(fp.components || {}).map(([key, comp]) => (
                      <div
                        key={key}
                        className="p-3 rounded-lg bg-neutral-950/60 border border-neutral-800"
                      >
                        <div className="text-neutral-600 text-xs mb-1">{key}</div>
                        <div className="text-neutral-400 text-xs font-mono break-all">
                          {comp.error ? (
                            <span className="text-red-400">Error</span>
                          ) : comp.value !== undefined && comp.value !== null ? (
                            typeof comp.value === "object"
                              ? JSON.stringify(comp.value).slice(0, 80) + (JSON.stringify(comp.value).length > 80 ? "…" : "")
                              : String(comp.value)
                          ) : (
                            "—"
                          )}
                        </div>
                        {comp.duration !== undefined && (
                          <div className="text-neutral-600 text-xs mt-1">{comp.duration}ms</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </section>
        )}
      </div>
    </div>
  );
}

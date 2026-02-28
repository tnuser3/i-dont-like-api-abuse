"use client";

import { useCallback, useEffect, useState } from "react";
import {
  loadVmFromChallenge,
  vmRunWithOperations,
  type ChallengeResponse,
} from "@/lib/vm-inject";
import { getBehaviourTracker } from "@/lib/entropy";
import { requestChallenge, getVisitorHeaders } from "@/lib/fingerprint-client";
import { readU32LE } from "@/lib/encoding";

type StepStatus = "idle" | "loading" | "ok" | "error";

interface StepState {
  status: StepStatus;
  message?: string;
}

export default function Home() {
  const [challengeState, setChallengeState] = useState<StepState>({
    status: "idle",
  });
  const [vmState, setVmState] = useState<StepState>({ status: "idle" });
  const [runState, setRunState] = useState<StepState>({ status: "idle" });
  const [verifyState, setVerifyState] = useState<StepState>({ status: "idle" });
  const [vmLoaded, setVmLoaded] = useState(false);
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [testOutput, setTestOutput] = useState<string>("");
  const [solvedInteger, setSolvedInteger] = useState<number | null>(null);
  const [error, setError] = useState<string>("");

  const runChallenge = useCallback(async () => {
    setChallengeState({ status: "loading" });
    setError("");
    try {
      const tracker = getBehaviourTracker();
      tracker.record("challenge_request");
      const data = await requestChallenge();
      setChallenge(data);
      setChallengeState({ status: "ok", message: "Challenge received" });
    } catch (e) {
      setError(String(e));
      setChallengeState({ status: "error", message: String(e) });
    }
  }, []);

  const runLoadVm = useCallback(async () => {
    if (!challenge) {
      setError("Fetch challenge first");
      return;
    }
    setVmState({ status: "loading" });
    setError("");
    try {
      await loadVmFromChallenge(challenge);
      setVmLoaded(true);
      setVmState({ status: "ok", message: "VM loaded and ready" });
    } catch (e) {
      setError(String(e));
      setVmState({ status: "error", message: String(e) });
    }
  }, [challenge]);

  const runVmPipeline = useCallback(() => {
    if (!challenge || !vmLoaded) {
      setError("Load VM from challenge first");
      return;
    }
    setRunState({ status: "loading" });
    setError("");
    try {
      const raw = Uint8Array.from(atob(challenge.input), (c) => c.charCodeAt(0));
      const data = new Uint8Array(raw.length);
      data.set(raw);

      const rc = vmRunWithOperations(data, challenge.operations);
      if (rc !== 0) {
        setRunState({ status: "error", message: `vm_run returned ${rc}` });
        setTestOutput("");
        setSolvedInteger(null);
        return;
      }

      const solved = data.length >= 4 ? readU32LE(data, 0) : null;
      if (solved !== null) {
        setSolvedInteger(solved);
        setTestOutput(String(solved));
      } else {
        setSolvedInteger(null);
        setTestOutput("");
      }
      setRunState({
        status: "ok",
        message: solved !== null ? `Solved: ${solved}` : "Need 4+ bytes",
      });
    } catch (e) {
      setError(String(e));
      setRunState({ status: "error", message: String(e) });
      setTestOutput("");
      setSolvedInteger(null);
    }
  }, [challenge, vmLoaded]);

  const runVerify = useCallback(async () => {
    if (!challenge?.token || solvedInteger === null) {
      setError("Run VM on input first");
      return;
    }
    setVerifyState({ status: "loading" });
    setError("");
    try {
      const res = await fetch("/api/challenge/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getVisitorHeaders() },
        body: JSON.stringify({
          token: challenge.token,
          solved: solvedInteger,
        }),
      });
      const data = (await res.json()) as { ok: boolean; error?: string };
      setVerifyState({
        status: data.ok ? "ok" : "error",
        message: data.ok ? "Verified" : data.error ?? "Verification failed",
      });
    } catch (e) {
      setError(String(e));
      setVerifyState({ status: "error", message: String(e) });
    }
  }, [challenge?.token, solvedInteger]);

  useEffect(() => {
    getBehaviourTracker().record("page_view");
    import("@/lib/fingerprint-client").then(({ collectFingerprint }) =>
      collectFingerprint().catch(() => {})
    );
  }, []);

  const statusColor = (s: StepStatus) =>
    s === "ok"
      ? "text-emerald-600 dark:text-emerald-400"
      : s === "error"
        ? "text-red-600 dark:text-red-400"
        : s === "loading"
          ? "text-amber-600 dark:text-amber-400"
          : "text-zinc-500";

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black font-sans">
      <main className="max-w-2xl mx-auto py-12 px-6">
        <div className="flex items-center justify-between mb-2">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
            API challenge pipeline
          </h1>
          <a
            href="/manager"
            className="text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
          >
            Manager →
          </a>
        </div>
        <p className="text-zinc-600 dark:text-zinc-400 text-sm mb-8">
          Challenge (entropy + fingerprint validated) → VM load → Run operations
        </p>

        {error && (
          <div
            className="mb-6 p-4 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 text-sm"
            role="alert"
          >
            {error}
          </div>
        )}

        <div className="space-y-4">
          <section className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 shadow-sm">
            <h2 className="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-2">
              1. Challenge
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-500 mb-3">
              Submit entropy + fingerprint to receive ChaCha-encrypted WASM +
              operations
            </p>
            <button
              onClick={runChallenge}
              disabled={challengeState.status === "loading"}
              className="px-4 py-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-sm font-medium hover:opacity-90 disabled:opacity-60"
            >
              {challengeState.status === "loading" ? "…" : "Fetch challenge"}
            </button>
            <span
              className={`ml-3 text-sm ${statusColor(challengeState.status)}`}
            >
              {challenge && <>{challenge.operations.length} operations</>}
              {challengeState.message && !challenge && challengeState.message}
            </span>
          </section>

          <section className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 shadow-sm">
            <h2 className="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-2">
              2. Load VM
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-500 mb-3">
              Decrypt WASM and instantiate VM
            </p>
            <button
              onClick={runLoadVm}
              disabled={
                vmState.status === "loading" || !challenge
              }
              className="px-4 py-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-sm font-medium hover:opacity-90 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {vmState.status === "loading" ? "…" : "Load VM"}
            </button>
            <span
              className={`ml-3 text-sm ${statusColor(vmState.status)}`}
            >
              {vmState.message}
            </span>
          </section>

          <section className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 shadow-sm">
            <h2 className="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-2">
              3. Run VM
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-500 mb-3">
              Run VM on challenge input with operations; result is integer
            </p>
            <div className="flex flex-wrap items-center gap-3 mb-3">
              <button
                onClick={runVmPipeline}
                disabled={
                  runState.status === "loading" || !vmLoaded
                }
                className="px-4 py-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 text-sm font-medium hover:opacity-90 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {runState.status === "loading" ? "…" : "Run"}
              </button>
              <span
                className={`text-sm ${statusColor(runState.status)}`}
              >
                {runState.message}
              </span>
            </div>
            {(testOutput || solvedInteger !== null) && (
              <div className="mt-2 space-y-2">
                <div className="p-3 rounded-lg bg-zinc-100 dark:bg-zinc-800 font-mono text-xs text-zinc-700 dark:text-zinc-300 break-all">
                  {solvedInteger !== null ? `Solved: ${solvedInteger}` : testOutput}
                </div>
                {solvedInteger !== null && (
                  <div className="flex items-center gap-3">
                    <button
                      onClick={runVerify}
                      disabled={verifyState.status === "loading"}
                      className="px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-500 disabled:opacity-60"
                    >
                      {verifyState.status === "loading" ? "…" : "Verify"}
                    </button>
                    <span className={`text-sm ${statusColor(verifyState.status)}`}>
                      {verifyState.message}
                    </span>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>

        <div className="mt-8 pt-6 border-t border-zinc-200 dark:border-zinc-700">
          <h3 className="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-2">
            One-click run
          </h3>
          <button
            onClick={async () => {
              setError("");
              setVerifyState({ status: "idle" });
              try {
                setChallengeState({ status: "loading" });
                const data = await requestChallenge();
                setChallenge(data);
                setChallengeState({ status: "ok" });

                setVmState({ status: "loading" });
                await loadVmFromChallenge(data);
                setVmLoaded(true);
                setVmState({ status: "ok" });

                setRunState({ status: "loading" });
                const raw = Uint8Array.from(atob(data.input), (c) => c.charCodeAt(0));
                const arr = new Uint8Array(raw.length);
                arr.set(raw);
                const rc = vmRunWithOperations(arr, data.operations);
                if (rc !== 0) throw new Error(`vm_run returned ${rc}`);
                const solved = arr.length >= 4 ? readU32LE(arr, 0) : null;
                if (solved !== null) {
                  setSolvedInteger(solved);
                  setTestOutput(String(solved));
                }
                setRunState({ status: "ok", message: "Done" });

                if (solved !== null) {
                  setVerifyState({ status: "loading" });
                  const verifyRes = await fetch("/api/challenge/verify", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...getVisitorHeaders() },
                    body: JSON.stringify({
                      token: data.token,
                      solved,
                    }),
                  });
                  const verifyData = (await verifyRes.json()) as {
                    ok: boolean;
                    error?: string;
                  };
                  setVerifyState({
                    status: verifyData.ok ? "ok" : "error",
                    message: verifyData.ok ? "Verified" : verifyData.error ?? "Verification failed",
                  });
                }
              } catch (e) {
                setError(String(e));
                setRunState({ status: "error" });
              }
            }}
            className="px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-500"
          >
            Challenge → Load → Run → Verify
          </button>
          <p className="mt-2 text-xs text-zinc-500">
            Fetch challenge, load VM, run on input, verify integer.
          </p>
        </div>
      </main>
    </div>
  );
}

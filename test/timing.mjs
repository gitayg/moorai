// Shared stopwatch helpers for the unit tests that must assert on time.
//
// WHY THIS EXISTS. An absolute millisecond budget measures the machine as much as the code: the same
// assertion that reads ~480-600ms on an idle M-series Mac read 2402ms on a shared GitHub Actions runner
// in the v1.4.2 CI run, and three different timing tests went red across two attempts of that one run
// for reasons that had nothing to do with the code under test. test/detector-hardening.test.mjs already
// solved this once, by hand (see its comment and the "Unit tests" step of .github/workflows/ci.yml);
// these helpers are that pattern, shared, so the next timing test starts from it:
//
//   1. compare against a baseline measured IN THE SAME PROCESS, MICROSECONDS APART — a scaling ratio
//      (cost at 4x the input over cost at 1x) or a null implementation doing the same I/O — so a slow or
//      contended host slows numerator and denominator alike and cancels out;
//   2. take the best of several samples (or the median of paired rounds), interleaved, so one preemption
//      or GC pause cannot decide the result and a load burst lands on both sides of the comparison;
//   3. keep the absolute budget, but OPT-IN: `MOORAI_PERF_ABS=1` on a quiet machine. CI does not set it.

// Set MOORAI_PERF_ABS=1 to run the absolute wall-clock budgets. The value is a `skip` option for test().
export const ABS_SKIP = process.env.MOORAI_PERF_ABS ? false : "wall-clock budget — set MOORAI_PERF_ABS=1 on an idle machine";

export const msOf = (fn) => { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; };

// CPU time this process spent in fn (user + system), in ms. For in-process CPU-bound work it is the
// better stopwatch: time spent descheduled — waiting for a core on a contended host — is not counted.
export const cpuMsOf = (fn) => { const c = process.cpuUsage(); fn(); const d = process.cpuUsage(c); return (d.user + d.system) / 1000; };

export function bestMs(fn, runs = 3) {
  let best = Infinity;
  for (let i = 0; i < runs; i++) best = Math.min(best, msOf(fn));
  return best;
}

export function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// CPU cost of `large` over CPU cost of `small` (cpuMsOf — both are in-process, CPU-bound calls): the best
// of `samples` samples, each sample the mean of `reps` calls of each, the two alternating call by call (so
// a memo keyed on the last input never hits, and a burst lands on both). `reps` is sized so one sample of
// `small` lasts at least `minMs`.
//
// WHY NOT A PLAIN BEST-OF-N OF SINGLE WALL-CLOCK CALLS: under heavy contention it is biased against the
// larger input, because the longer call is the one more likely to contain a stretch spent waiting for a
// core. MEASURED, 240 KB vs 60 KB clipboard scans whose idle ratio is 4.0x: single calls read 9.99x and
// 15.87x; wall-clock samples of >= 5ms read up to 22.86x, and of >= 20ms up to 6.73x. CPU time does not
// count the wait, and short samples are averaged over several calls.
export function scalingRatio(small, large, samples = 3, minMs = 20) {
  const est = Math.max(cpuMsOf(small), 0.001); cpuMsOf(large); // warm both; estimate the small side
  const reps = Math.max(1, Math.ceil(minMs / est));
  let a = Infinity, b = Infinity;
  for (let s = 0; s < samples; s++) {
    let ta = 0, tb = 0;
    for (let i = 0; i < reps; i++) { ta += cpuMsOf(small); tb += cpuMsOf(large); }
    a = Math.min(a, ta / reps); b = Math.min(b, tb / reps);
  }
  return { small: a, large: b, ratio: b / a, reps };
}

// Async latency, paired: `rounds` rounds, each calling every fn once in an order that rotates per round,
// with `gap` ms idle before each call. Returns one array of per-call ms per fn, index-aligned by round,
// so per-round differences can be taken (a load burst during round i lands on every fn of round i).
export async function pairedRounds(fns, rounds, gap = 0) {
  const out = fns.map(() => []);
  for (let r = 0; r < rounds; r++) {
    for (let k = 0; k < fns.length; k++) {
      const i = (r + k) % fns.length;
      if (gap) await new Promise((res) => setTimeout(res, gap));
      const t0 = performance.now();
      await fns[i]();
      out[i].push(performance.now() - t0);
    }
  }
  return out;
}

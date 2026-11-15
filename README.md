# FFmpeg_libavformat_2
# CVE 申请文案 — W1（wtvdec 递归栈耗尽）— 2026-11-15

## Vulnerability description
FFmpeg master (commit 09382db7f5791362dcaf0f4f26fad2bb18cb0dcb) is prone to
stack exhaustion via unbounded recursion in `parse_media_type()`
(libavformat/wtvdec.c:643). When a WTV `SBE2_STREAM_DESC_EVENT` chunk carries
the `ff_mediasubtype_cpfilters_processed` / `ff_format_cpfilters_processed`
GUID pair, the function seeks back and recurses with (size-32) with no depth
limit; recursion depth is bounded only by file size (≈ size/32 nesting
levels). A crafted WTV file crashes any demuxing application with SIGSEGV —
remote deterministic DoS. Minimum crash size measured on default 8 MB stack:
29,200 nesting levels / 950,272 bytes (29,000 levels survives).

## Root cause (validated by human review and container reproduction)
`parse_chunks()` (~wtvdec.c:801/:817) dispatches into `parse_media_type()`;
the CPFilters-processed branch recurses on itself after skipping 32 bytes,
without any recursion counter. The duplicate-sector FAT rejection
(c7eefe19) is not involved — all sectors in the testcase are distinct.

## CWE
CWE-674 (Uncontrolled Recursion) → stack exhaustion, CWE-400-class DoS.

## Affected product / versions
- Product: FFmpeg, libavformat (wtvdec.c).
- Verified present: upstream master 09382db7f5791362dcaf0f4f26fad2bb18cb0dcb
  (2026-11-15); reproduction on 2026-11-12 snapshot, unmodified configure.
- No release known to be fixed.

## Reproduction
- Command: `ffprobe -v warning crash_cpfilters.wtv` (default 8 MB stack)
- Testcase: crash_cpfilters.wtv (950,272 bytes ≈ 29,200 levels at minimum
  crash size; 2,015,232-byte comfort variant also provided). Generator:
  gen_wtv_deep.py.
- Result: SIGSEGV, exit 139 (stack exhaustion). Recursion frames repeat at
  wtvdec.c:643.


## References
- Testcase + generator
- FFmpeg security policy: https://www.ffmpeg.org/security.html

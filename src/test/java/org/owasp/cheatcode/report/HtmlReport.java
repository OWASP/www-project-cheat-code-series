package org.owasp.cheatcode.report;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import com.google.gson.Gson;

import org.owasp.cheatcode.harness.CellResult;

/**
 * The matrix as a self-contained HTML page: no CDN, no external stylesheet, no build step.
 *
 * <p>Colour follows the verdict rather than test pass/fail, so the page reads as a security
 * report. A vulnerable implementation shows red where it discloses the secret even though its
 * test passed - which is the distinction the old red-test-output report could not draw.
 *
 * <p>Clicking a cell opens the evidence behind it: the payload, what the implementation did, and
 * the note explaining why. Those notes are authored next to the expectations in the test classes,
 * so they cannot rot independently of the results.
 */
final class HtmlReport {

    private static final Gson GSON = new Gson();

    private final List<CellResult> cells;

    HtmlReport(List<CellResult> cells) {
        this.cells = cells;
    }

    String render() {
        StringBuilder out = new StringBuilder(64 * 1024);
        out.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
           .append("<meta charset=\"utf-8\">\n")
           .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
           .append("<title>Cheat Code Series — Path Traversal outcome matrix</title>\n")
           .append("<style>\n").append(css()).append("\n</style>\n</head>\n<body>\n");

        renderHeader(out);
        renderSummary(out);

        Map<String, List<CellResult>> byPlatform = new TreeMap<>(
                cells.stream().collect(Collectors.groupingBy(c -> c.platform)));
        for (Map.Entry<String, List<CellResult>> platform : byPlatform.entrySet()) {
            renderMatrix(out, platform.getKey(), platform.getValue());
        }

        renderDetailPanel(out);
        renderLegend(out);
        renderPayloadReference(out);

        out.append("<script id=\"cells\" type=\"application/json\">")
           .append(GSON.toJson(indexed()))
           .append("</script>\n<script>\n").append(script()).append("\n</script>\n")
           .append("</body>\n</html>\n");
        return out.toString();
    }

    // -- sections ------------------------------------------------------------

    private void renderHeader(StringBuilder out) {
        CellResult sample = cells.get(0);
        out.append("<header>\n<h1>Path Traversal — outcome matrix</h1>\n")
           .append("<p class=\"lede\">Every implementation scored against every payload. "
                 + "Colour is the <em>security</em> verdict, not the test result: a red cell on a "
                 + "vulnerable implementation is a passing test, because disclosure is exactly "
                 + "what it was declared to do.</p>\n")
           .append("<p class=\"meta\">Vulnerability class <code>")
           .append(escape(sample.vulnerabilityClass))
           .append("</code> · generated from ").append(cells.size())
           .append(" recorded cells</p>\n</header>\n");
    }

    private void renderSummary(StringBuilder out) {
        Map<String, Integer> byVerdict = new LinkedHashMap<>();
        int mismatched = 0;
        int undeclared = 0;
        for (CellResult cell : cells) {
            byVerdict.merge(cell.verdict, 1, Integer::sum);
            if (CellResult.MISMATCH.equals(cell.status)) {
                mismatched++;
            } else if (CellResult.UNDECLARED.equals(cell.status)) {
                undeclared++;
            }
        }

        out.append("<section class=\"tiles\">\n");
        tile(out, "breach", byVerdict.getOrDefault("BREACH", 0), "reached the secret");
        tile(out, "near", byVerdict.getOrDefault("NEAR_MISS", 0), "blocked by luck, not by code");
        tile(out, "lost", byVerdict.getOrDefault("FUNCTIONALITY_LOST", 0), "legitimate use broken");
        tile(out, "safe", byVerdict.getOrDefault("SAFE", 0), "did the right thing");
        out.append("</section>\n");

        if (mismatched > 0 || undeclared > 0) {
            out.append("<p class=\"warn\"><strong>This report does not describe a green run.</strong> ")
               .append(mismatched).append(" cell(s) diverged from what was declared and ")
               .append(undeclared).append(" have never been declared. Both need a human to look.</p>\n");
        }
    }

    private void tile(StringBuilder out, String kind, int count, String label) {
        out.append("<div class=\"tile ").append(kind).append("\"><span class=\"n\">")
           .append(count).append("</span><span class=\"l\">").append(escape(label))
           .append("</span></div>\n");
    }

    private void renderMatrix(StringBuilder out, String platform, List<CellResult> platformCells) {
        CellResult sample = platformCells.get(0);
        out.append("<section class=\"matrix\">\n<h2>").append(escape(platform))
           .append(" <span class=\"meta\">").append(escape(sample.osName))
           .append(", Java ").append(escape(sample.javaVersion)).append("</span></h2>\n");

        List<CellResult> columnOrder = platformCells.stream()
                .sorted(ReportGenerator.payloadOrder())
                .collect(Collectors.toList());
        Set<String> columns = new LinkedHashSet<>();
        Map<String, CellResult> columnMeta = new LinkedHashMap<>();
        for (CellResult cell : columnOrder) {
            if (columns.add(cell.payloadId)) {
                columnMeta.put(cell.payloadId, cell);
            }
        }

        out.append("<div class=\"scroll\">\n<table>\n<thead>\n<tr><th class=\"rowhead\">Implementation</th>");
        for (String payloadId : columns) {
            CellResult meta = columnMeta.get(payloadId);
            out.append("<th title=\"").append(escape(meta.payloadDisplay)).append("\"><code>")
               .append(escape(meta.payloadShortLabel)).append("</code><span class=\"kind ")
               .append(meta.payloadKind.toLowerCase()).append("\">")
               .append(meta.payloadKind.charAt(0)).append("</span></th>");
        }
        out.append("</tr>\n</thead>\n<tbody>\n");

        Map<String, List<CellResult>> byImplementation = platformCells.stream()
                .collect(Collectors.groupingBy(c -> c.implementation, LinkedHashMap::new,
                         Collectors.toList()));
        List<Map.Entry<String, List<CellResult>>> ordered = new ArrayList<>(byImplementation.entrySet());
        ordered.sort(ReportGenerator.implementationOrder());

        boolean vulnerableGroupOpen = false;
        boolean secureGroupOpen = false;
        for (Map.Entry<String, List<CellResult>> entry : ordered) {
            List<CellResult> rowCells = entry.getValue();
            boolean vulnerable = rowCells.get(0).vulnerableByDesign;
            if (vulnerable && !vulnerableGroupOpen) {
                groupRow(out, "Vulnerable by design", columns.size());
                vulnerableGroupOpen = true;
            } else if (!vulnerable && !secureGroupOpen) {
                groupRow(out, "Secure", columns.size());
                secureGroupOpen = true;
            }

            Map<String, CellResult> byPayload = new LinkedHashMap<>();
            for (CellResult cell : rowCells) {
                byPayload.put(cell.payloadId, cell);
            }

            out.append("<tr><th class=\"rowhead\" title=\"")
               .append(escape(rowCells.get(0).implementationLabel)).append("\">")
               .append(escape(ReportGenerator.shortName(entry.getKey()))).append("</th>");
            for (String payloadId : columns) {
                CellResult cell = byPayload.get(payloadId);
                if (cell == null) {
                    out.append("<td class=\"cell empty\">—</td>");
                    continue;
                }
                out.append("<td class=\"cell v-").append(cell.verdict.toLowerCase())
                   .append(CellResult.MATCH.equals(cell.status) ? "" : " flagged")
                   .append("\" data-key=\"").append(escape(key(cell)))
                   .append("\" tabindex=\"0\" role=\"button\" title=\"")
                   .append(escape(cell.actualOutcome)).append("\">")
                   .append(escape(ReportGenerator.shortCode(cell.actualOutcome)))
                   .append("</td>");
            }
            out.append("</tr>\n");
        }
        out.append("</tbody>\n</table>\n</div>\n</section>\n");
    }

    private void groupRow(StringBuilder out, String label, int span) {
        out.append("<tr class=\"group\"><th class=\"rowhead\" colspan=\"").append(span + 1)
           .append("\">").append(escape(label)).append("</th></tr>\n");
    }

    private void renderDetailPanel(StringBuilder out) {
        out.append("<section id=\"detail\" class=\"detail\" aria-live=\"polite\">\n")
           .append("<p class=\"hint\">Select a cell to see the payload, what the implementation "
                 + "did with it, and why.</p>\n</section>\n");
    }

    private void renderLegend(StringBuilder out) {
        out.append("<section class=\"legend\">\n<h2>Reading the matrix</h2>\n");

        out.append("<h3>Verdict — the colour</h3>\n<ul class=\"verdicts\">\n");
        for (String verdict : new String[] {"BREACH", "NEAR_MISS", "FUNCTIONALITY_LOST", "SAFE"}) {
            out.append("<li><span class=\"swatch v-").append(verdict.toLowerCase())
               .append("\"></span><strong>").append(verdict).append("</strong> — ")
               .append(escape(ReportGenerator.verdictMeaning(verdict))).append("</li>\n");
        }
        out.append("</ul>\n");

        out.append("<h3>Outcome — the code in the cell</h3>\n<dl>\n");
        String[] outcomes = {
            "READ_OK", "SANITIZED_HIT", "REJECTED", "SANITIZED_MISS",
            "UNDETECTED_MISS", "REJECTED_BY_RUNTIME", "SECRET_DISCLOSED"
        };
        for (String outcome : outcomes) {
            out.append("<dt><code>").append(escape(ReportGenerator.shortCode(outcome)))
               .append("</code> <span class=\"full\">").append(outcome).append("</span></dt><dd>")
               .append(escape(ReportGenerator.outcomeMeaning(outcome))).append("</dd>\n");
        }
        out.append("</dl>\n</section>\n");
    }

    private void renderPayloadReference(StringBuilder out) {
        out.append("<section class=\"payloads\">\n<h2>Payloads</h2>\n");
        Set<String> seen = new LinkedHashSet<>();
        cells.stream().sorted(ReportGenerator.payloadOrder()).forEach(cell -> {
            if (!seen.add(cell.payloadId)) {
                return;
            }
            out.append("<article><h3><code>").append(escape(cell.payloadDisplay))
               .append("</code> <span class=\"kind ").append(cell.payloadKind.toLowerCase())
               .append("\">").append(escape(cell.payloadKind)).append("</span></h3>\n<p>")
               .append(escape(cell.payloadDescription)).append("</p>\n");
            if (cell.payloadSource != null) {
                out.append("<p class=\"meta\">Source: ").append(escape(cell.payloadSource)).append("</p>\n");
            }
            out.append("</article>\n");
        });
        out.append("</section>\n");
    }

    // -- data for the client -------------------------------------------------

    private Map<String, CellResult> indexed() {
        Map<String, CellResult> map = new LinkedHashMap<>();
        for (CellResult cell : cells) {
            map.put(key(cell), cell);
        }
        return map;
    }

    private static String key(CellResult cell) {
        return cell.platform + "|" + cell.implementation + "|" + cell.payloadId;
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }

    // -- assets --------------------------------------------------------------

    private static String css() {
        return String.join("\n",
            ":root{--bg:#fbfbfa;--fg:#1d1c1a;--muted:#6b6862;--line:#e0ddd6;--card:#fff;",
            "  --safe:#2f8f5b;--near:#c99000;--lost:#d1702a;--breach:#c2352c;--other:#7a5bbd;}",
            "@media (prefers-color-scheme:dark){:root{--bg:#16151a;--fg:#eae7e1;--muted:#9c988f;",
            "  --line:#33303a;--card:#1f1e25;--safe:#4bbd80;--near:#e0b13a;--lost:#e8925a;",
            "  --breach:#e8635a;--other:#a98be0;}}",
            "*{box-sizing:border-box}",
            "body{margin:0;padding:2rem 1.25rem 4rem;background:var(--bg);color:var(--fg);",
            "  font:16px/1.6 ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;",
            "  max-width:1100px;margin-inline:auto}",
            "h1{font-size:1.65rem;margin:0 0 .5rem}",
            "h2{font-size:1.2rem;margin:2.5rem 0 .75rem;border-bottom:1px solid var(--line);padding-bottom:.4rem}",
            "h3{font-size:.95rem;margin:1.5rem 0 .5rem}",
            "code{font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:.88em}",
            ".lede{max-width:62ch;color:var(--fg)}",
            ".meta{color:var(--muted);font-size:.85rem;font-weight:400}",
            ".warn{border-left:3px solid var(--breach);padding:.6rem .9rem;background:var(--card);",
            "  border-radius:0 6px 6px 0}",
            ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem;margin:1.5rem 0}",
            ".tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem;",
            "  border-left-width:4px}",
            ".tile .n{display:block;font-size:1.9rem;font-weight:650;line-height:1}",
            ".tile .l{display:block;font-size:.8rem;color:var(--muted);margin-top:.25rem}",
            ".tile.breach{border-left-color:var(--breach)}.tile.breach .n{color:var(--breach)}",
            ".tile.near{border-left-color:var(--near)}.tile.near .n{color:var(--near)}",
            ".tile.lost{border-left-color:var(--lost)}.tile.lost .n{color:var(--lost)}",
            ".tile.safe{border-left-color:var(--safe)}.tile.safe .n{color:var(--safe)}",
            ".scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}",
            "table{border-collapse:collapse;width:100%;font-size:.85rem}",
            "th,td{padding:.5rem .6rem;text-align:center;border-bottom:1px solid var(--line);white-space:nowrap}",
            "thead th{position:sticky;top:0;background:var(--card);font-size:.78rem;z-index:1}",
            ".rowhead{text-align:left;font-weight:500;font-family:ui-monospace,Consolas,monospace;",
            "  font-size:.78rem;position:sticky;left:0;background:var(--card);z-index:2}",
            "tr.group th{background:transparent;font-family:inherit;font-size:.78rem;",
            "  text-transform:uppercase;letter-spacing:.06em;color:var(--muted);padding-top:1rem}",
            ".kind{display:inline-block;width:1.1em;height:1.1em;line-height:1.1em;border-radius:3px;",
            "  font-size:.62rem;margin-left:.35rem;color:var(--card);vertical-align:middle}",
            ".kind.legitimate{background:var(--safe)}.kind.attack{background:var(--breach)}",
            ".kind.malformed{background:var(--other)}",
            ".cell{cursor:pointer;font-weight:600;font-size:.76rem;font-family:ui-monospace,Consolas,monospace}",
            ".cell:hover,.cell:focus{outline:2px solid var(--fg);outline-offset:-2px}",
            ".cell.selected{outline:2px solid var(--fg);outline-offset:-2px}",
            ".cell.empty{color:var(--muted);cursor:default}",
            ".cell.flagged::after{content:' !';color:var(--breach)}",
            ".v-safe{color:var(--safe)}.v-near_miss{color:var(--near)}",
            ".v-functionality_lost{color:var(--lost)}.v-breach{color:var(--breach);}",
            ".v-error{color:var(--other)}",
            "td.v-breach{background:color-mix(in srgb,var(--breach) 12%,transparent)}",
            "td.v-near_miss{background:color-mix(in srgb,var(--near) 12%,transparent)}",
            "td.v-functionality_lost{background:color-mix(in srgb,var(--lost) 10%,transparent)}",
            ".detail{margin-top:1.25rem;background:var(--card);border:1px solid var(--line);",
            "  border-radius:10px;padding:1rem 1.15rem;min-height:5rem}",
            ".detail .hint{color:var(--muted);margin:0}",
            ".detail h3{margin-top:0}",
            ".detail dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem .9rem;margin:.75rem 0}",
            ".detail dt{color:var(--muted);font-size:.82rem}",
            ".detail dd{margin:0;font-size:.88rem;word-break:break-word}",
            ".detail .note{border-left:3px solid var(--line);padding-left:.85rem;margin-top:.9rem;",
            "  color:var(--fg);max-width:70ch}",
            ".swatch{display:inline-block;width:.8rem;height:.8rem;border-radius:3px;margin-right:.5rem;",
            "  vertical-align:middle}",
            ".swatch.v-safe{background:var(--safe)}.swatch.v-near_miss{background:var(--near)}",
            ".swatch.v-functionality_lost{background:var(--lost)}.swatch.v-breach{background:var(--breach)}",
            ".verdicts{list-style:none;padding:0}.verdicts li{margin:.35rem 0;font-size:.9rem}",
            "dl dt{margin-top:.6rem;font-size:.85rem}",
            "dl dt .full{color:var(--muted);font-size:.78rem;margin-left:.4rem}",
            "dl dd{margin:.15rem 0 0;font-size:.88rem;color:var(--fg);max-width:72ch}",
            ".payloads article{border-top:1px solid var(--line);padding:.9rem 0}",
            ".payloads h3{margin:0 0 .35rem}",
            ".payloads .kind{width:auto;padding:0 .4rem;font-size:.66rem;letter-spacing:.04em}",
            ".payloads p{margin:.3rem 0;max-width:72ch;font-size:.9rem}"
        );
    }

    private static String script() {
        return String.join("\n",
            "const DATA = JSON.parse(document.getElementById('cells').textContent);",
            "const panel = document.getElementById('detail');",
            "let selected = null;",
            "",
            "function esc(s){",
            "  return String(s === null || s === undefined ? '' : s)",
            "    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');",
            "}",
            "",
            "function row(label, value){",
            "  return value === null || value === undefined || value === ''",
            "    ? '' : '<dt>' + esc(label) + '</dt><dd>' + esc(value) + '</dd>';",
            "}",
            "",
            "function show(key, td){",
            "  const c = DATA[key];",
            "  if (!c) return;",
            "  if (selected) selected.classList.remove('selected');",
            "  selected = td; td.classList.add('selected');",
            "",
            "  const ev = c.evidence || {};",
            "  let html = '<h3>' + esc(c.implementationLabel || c.implementation) + '</h3>';",
            "  html += '<dl>';",
            "  html += row('payload', c.payloadDisplay);",
            "  html += row('outcome', c.actualOutcome);",
            "  html += row('verdict', c.verdict);",
            "  html += row('declared', c.expectedOutcome);",
            "  if (c.status !== 'MATCH') html += row('status', c.status);",
            "  html += row('platform', c.platform + (c.platformSpecificExpectation",
            "    ? ' (declared for this platform specifically)' : ''));",
            "  html += row('input rewritten', ev.inputRewritten);",
            "  html += row('resolved path', ev.resolvedPath);",
            "  html += row('content', ev.contentPreview);",
            "  html += row('threw', ev.exceptionClass);",
            "  html += row('message', ev.exceptionMessage);",
            "  html += '</dl>';",
            "  if (c.note) html += '<p class=\"note\">' + esc(c.note) + '</p>';",
            "  if (c.implementationNote) html += '<p class=\"note meta\">' + esc(c.implementationNote) + '</p>';",
            "  panel.innerHTML = html;",
            "}",
            "",
            "document.querySelectorAll('td.cell[data-key]').forEach(td => {",
            "  td.addEventListener('click', () => show(td.dataset.key, td));",
            "  td.addEventListener('keydown', e => {",
            "    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); show(td.dataset.key, td); }",
            "  });",
            "});"
        );
    }
}

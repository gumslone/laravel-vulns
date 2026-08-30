<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vulnerability Search</title>
    <style>
        :root { color-scheme: light dark; }
        * { box-sizing: border-box; margin: 0; }
        body { font: 15px/1.5 system-ui, -apple-system, sans-serif; background: #f6f7f9; color: #1c1e21; padding: 2rem 1rem; }
        .wrap { max-width: 60rem; margin: 0 auto; }
        h1 { font-size: 1.2rem; margin-bottom: .25rem; }
        .sub { color: #667; font-size: .85rem; margin-bottom: 1.25rem; }
        form { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
        input[type=text] { flex: 1; padding: .6rem .8rem; border: 1px solid #ccd; border-radius: .5rem; font: inherit; font-family: ui-monospace, monospace; font-size: .85rem; }
        button { padding: .6rem 1.1rem; border: 0; border-radius: .5rem; background: #4f46e5; color: #fff; font-weight: 600; cursor: pointer; }
        button:hover { background: #4338ca; }
        .banner { padding: .6rem .9rem; border-radius: .5rem; margin-bottom: 1rem; font-size: .85rem; }
        .banner.error { background: #fde8e8; color: #9b1c1c; }
        .banner.warn { background: #fdf6b2; color: #723b13; }
        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: .5rem; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
        th, td { text-align: left; padding: .55rem .8rem; border-bottom: 1px solid #eef; font-size: .83rem; vertical-align: top; }
        th { background: #fafbfc; color: #556; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }
        tr:last-child td { border-bottom: 0; }
        .id { font-family: ui-monospace, monospace; white-space: nowrap; }
        .id a { color: #4f46e5; text-decoration: none; }
        .id a:hover { text-decoration: underline; }
        .sev { display: inline-block; padding: .05rem .5rem; border-radius: 999px; font-size: .7rem; font-weight: 700; text-transform: uppercase; }
        .sev.critical { background: #fde8e8; color: #9b1c1c; }
        .sev.high { background: #fef0e7; color: #9a3412; }
        .sev.medium { background: #fdf6b2; color: #723b13; }
        .sev.low { background: #e1effe; color: #1e429f; }
        .sev.unknown { background: #eef; color: #556; }
        .tag { display: inline-block; padding: .05rem .45rem; border-radius: .3rem; font-size: .68rem; font-weight: 700; margin-left: .3rem; }
        .tag.kev { background: #9b1c1c; color: #fff; }
        .tag.ransom { background: #581c87; color: #fff; }
        .tag.exploit { background: #9a3412; color: #fff; }
        .tag.withdrawn { background: #556; color: #fff; }
        .num { font-variant-numeric: tabular-nums; white-space: nowrap; }
        .summary { color: #445; }
        .meta { color: #99a; font-size: .75rem; margin-top: 1rem; }
        .fix { color: #057a55; font-size: .78rem; white-space: nowrap; }
        @media (prefers-color-scheme: dark) {
            body { background: #14161a; color: #e5e7eb; }
            input[type=text] { background: #1e2126; border-color: #333a44; color: #e5e7eb; }
            table { background: #1a1d22; box-shadow: none; }
            th { background: #1e2126; color: #9aa; }
            th, td { border-color: #262b33; }
            .summary { color: #b8bec8; }
            .banner.error { background: #3b1219; color: #f4a4a4; }
            .banner.warn { background: #322708; color: #e8d06c; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <h1>Vulnerability Search</h1>
    <p class="sub">Paste a CVE / GHSA / EUVD id, a purl (<code>pkg:npm/lodash@4.17.20</code>), a CPE&nbsp;2.3, a commit sha, or a release/download URL.</p>

    <form method="get" action="">
        <input type="text" name="q" value="{{ $query }}" placeholder="CVE-2021-44228 · pkg:composer/vendor/pkg@1.2.3 · cpe:2.3:a:… · https://github.com/…/releases/…" autofocus>
        <button type="submit">Search</button>
    </form>

    @if ($failure)
        <div class="banner error">{{ $failure }}</div>
    @endif

    @foreach ($sourceErrors as $source => $error)
        <div class="banner warn"><strong>{{ $source }}</strong> failed — results may be incomplete: {{ $error }}</div>
    @endforeach

    @if ($query !== '' && ! $failure)
        @if ($results === [])
            <div class="banner warn">No known vulnerabilities for <code>{{ $query }}</code>@if($sourceErrors !== []) — but {{ count($sourceErrors) }} source(s) failed, treat as inconclusive @endif.</div>
        @else
            <table>
                <thead>
                <tr><th>Advisory</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Fixed in</th><th>Summary</th></tr>
                </thead>
                <tbody>
                @foreach ($results as $vuln)
                    <tr>
                        <td class="id">
                            {{-- Scheme allowlist: sourceUrl is feed-controlled; a
                                 javascript: URL must never become a clickable link. --}}
                            @if ($vuln->sourceUrl && preg_match('#^https?://#i', $vuln->sourceUrl))<a href="{{ $vuln->sourceUrl }}" target="_blank" rel="noopener">{{ $vuln->vulnId }}</a>@else{{ $vuln->vulnId }}@endif
                            @if ($vuln->isKnownExploited)<span class="tag kev" title="CISA Known Exploited Vulnerability">KEV</span>@endif
                            @if ($vuln->usedInRansomware)<span class="tag ransom" title="Known ransomware campaign use">RANSOM</span>@endif
                            @if ($vuln->exploitMaturity()->value !== 'none')<span class="tag exploit" title="Public exploit evidence">{{ strtoupper($vuln->exploitMaturity()->value) }}</span>@endif
                            @if ($vuln->isWithdrawn)<span class="tag withdrawn">WITHDRAWN</span>@endif
                        </td>
                        <td><span class="sev {{ $vuln->severity->value }}">{{ $vuln->severity->value }}</span></td>
                        <td class="num">{{ $vuln->effectiveCvssScore() ?? '—' }}</td>
                        <td class="num">{{ $vuln->epssScore !== null ? number_format($vuln->epssScore * 100, 1).'%' : '—' }}</td>
                        <td class="fix">{{ $vuln->fixedVersions !== [] ? implode(', ', array_slice($vuln->fixedVersions, 0, 3)) : '—' }}</td>
                        <td class="summary">{{ \Illuminate\Support\Str::limit((string) $vuln->summary, 160) }}</td>
                    </tr>
                @endforeach
                </tbody>
            </table>
        @endif
        <p class="meta">{{ count($results) }} result(s) in {{ $elapsedMs }} ms · sources: {{ implode(', ', $sources) }}</p>
    @endif
</div>
</body>
</html>

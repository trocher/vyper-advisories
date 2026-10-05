# Vyper security advisories by version

A static page that shows which [GitHub security advisories](https://github.com/vyperlang/vyper/security/advisories)
affect each version of the Vyper compiler, as a horizontal timeline over versions.

- One row per advisory. Each bar spans the affected versions, is colored by severity, and links to the advisory.
- The header shows how many advisories affect each version, stacked by severity. Click a version, or type one
  into "check version", to list the advisories that affect it. The selected version is kept in the URL
  (`#v=0.3.9`), so you can share the link.
- Filter by severity or keyword, sort by fix version, severity or publish date, and toggle pre-releases.
  By default a pre-release is hidden once its final release exists.
- Export to Markdown, either copied to the clipboard or downloaded as a `.md` file. The toolbar button exports
  the advisories currently listed, with filters and sort applied. The button in a version's panel exports
  "advisories affecting vyper X.Y.Z", ready to paste into an audit report.
- Light and dark themes. The page follows your system setting until you use the toggle, then remembers your choice.

## Data

The page fetches everything at runtime from the public GitHub REST API. It needs no token and no build step:

| What | Endpoint |
|---|---|
| advisories | `GET /repos/vyperlang/vyper/security-advisories?state=published` |
| versions | `GET /repos/vyperlang/vyper/tags` (plus `/releases` for release dates) |

Version ranges such as `>= 0.3.4, < 0.3.10` follow PEP 440 rules, the same rules pip and GitHub use.
For example, `< 0.4.0` does not include `0.4.0rc1`.

Unauthenticated API calls are limited to 60 requests per hour per IP. Each page load uses 3 requests, and the
responses are cached in `localStorage` for 15 minutes. If GitHub rejects a request, the page falls back to the
cached data.

## Colors

Colors come from [vyperlang/vyper-brand](https://github.com/vyperlang/vyper-brand): Vyper Black `#180C25`
background, Sand `#DBCBAB` text, Violet `#9F4CF2` accents, and the Inconsolata typeface.
Severities use brand colors: low = Blue `#75FBFB`, medium = Yellow `#E7FF54`, high = Orange `#FFA800`,
critical = Violet 80% `#B270F5`. The light theme uses Sand 5% / Sand 20% surfaces and darker brand steps for
contrast: Blue 150% `#3B7E7E`, Yellow 120% `#B9CC43`, Orange 120% `#CC8600`, Violet `#9F4CF2`. Each bar also shows a letter badge (C/H/M/L), so you don't have to tell
severities apart by color alone.

## Hosting on GitHub Pages

Push this repository to GitHub. Then open **Settings → Pages → Build and deployment**, choose
**Deploy from a branch**, and select `main` / `/ (root)`.

To run it locally, run `python3 -m http.server` and open <http://localhost:8000>.

## License

[MIT](LICENSE). The license covers this repository's code only. The Vyper logo in `assets/` belongs to the
[Vyper project](https://github.com/vyperlang/vyper-brand), and the advisory data comes from GitHub.
This project is not affiliated with the Vyper team.

# Embedded compliance PDF font

`oxAuditSansSC-Regular.ttf` is a renamed static Regular derivative of Noto Sans SC 2.004. It is embedded in the application and subset into each report, so PDF export works offline and does not depend on installed OS fonts.

- Upstream: [notofonts/noto-cjk](https://github.com/notofonts/noto-cjk)
- Pinned commit: `f8d157532fbfaeda587e826d4cd5b21a49186f7c`
- [Source font](https://raw.githubusercontent.com/notofonts/noto-cjk/f8d157532fbfaeda587e826d4cd5b21a49186f7c/Sans/Variable/TTF/Subset/NotoSansSC-VF.ttf)
- Source SHA-256: `d68bafcb48a2707749396aa12bbbd833cb70401f3a9a689fd2902c7e0d295964`
- Copyright (from the font): © 2014–2021 Adobe (http://www.adobe.com/), with Reserved Font Name 'Source'.
- License: SIL Open Font License 1.1, reproduced in [OFL.txt](OFL.txt), copied from the pinned upstream `Sans/LICENSE`. Copyright and license records remain in the derived font.

Regenerate after downloading the pinned source:

```sh
uv run --with fonttools==4.63.0 python src-tauri/assets/fonts/instantiate.py /path/to/NotoSansSC-VF.ttf
```

The recipe pins the weight to 400, removes variation tables, changes family/PostScript names to `oxAudit Sans SC`, preserves the upstream timestamp for reproducibility, and duplicates cmap aliases as visually identical glyphs. The latter prevents printpdf's one-code-point-per-glyph extraction map from conflating distinct characters (for example a bullet and a middle dot). No font download or Python dependency is required at build or runtime.

## Coverage and limitations

The font covers Latin letters (including precomposed accents) and the Chinese characters in Noto Sans SC. It uses Simplified Chinese regional glyph forms; it is not a promise of every Unicode character or every regional CJK form. Reports retain Unicode text and a PDF ToUnicode mapping for search and extraction. All report fields use actual glyph widths for wrapping, including Chinese without spaces and long evidence paths. Headings use size and color hierarchy with the same Regular face.

PDF export fails with a specific Unicode code point if the font lacks a glyph or the text requires unsupported combining-mark, variation-selector, soft-hyphen, or direction-control handling. Supplementary characters above U+FFFF are rejected because the current PDF library cannot reliably emit their UTF-16 extraction mapping. Compose accented Latin letters before export, or use HTML/JSON for text outside PDF coverage. Tabs become spaces; paragraph breaks and wrapped lines are layout whitespace. No unsupported character is replaced with `?` or a missing-glyph box.

Bundled derived font SHA-256: `52a4e93f2a3526867bf0054c92578fef08737dd801c0ec35a9d0a3df2186c072`.

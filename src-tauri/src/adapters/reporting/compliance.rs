use std::collections::BTreeMap;

use printpdf::{
    Color, FontId, Mm, Op, ParsedFont, PdfDocument, PdfPage, PdfSaveOptions, Point, Pt, Rgb,
    TextItem,
};

use crate::compliance::{ComplianceReportFormat, ComplianceReportMetadata, ComplianceReview};

pub struct ReportDocument {
    pub assessment: oxaudit_compliance::ComplianceAssessment,
    pub reviews: Vec<ComplianceReview>,
    pub metadata: ComplianceReportMetadata,
    pub generated_at_ms: u64,
}

pub struct GeneratedReport {
    pub bytes: Vec<u8>,
    pub warnings: Vec<String>,
}

pub fn generate(
    report: &ReportDocument,
    format: ComplianceReportFormat,
) -> Result<GeneratedReport, String> {
    let bytes = match format {
        ComplianceReportFormat::Json => generate_json(report)?,
        ComplianceReportFormat::Csv => generate_csv(report).into_bytes(),
        ComplianceReportFormat::Markdown => generate_markdown(report).into_bytes(),
        ComplianceReportFormat::Html => generate_html(report).into_bytes(),
        ComplianceReportFormat::Pdf => generate_pdf(report)?,
    };
    let mut warnings = Vec::new();
    if report.reviews.is_empty() {
        warnings.push("No human review decisions are recorded; automated evidence coverage is not a conformity decision.".into());
    }
    Ok(GeneratedReport { bytes, warnings })
}

fn generate_json(report: &ReportDocument) -> Result<Vec<u8>, String> {
    let reviews = if report.metadata.include_reviews {
        serde_json::to_value(&report.reviews).map_err(|error| error.to_string())?
    } else {
        serde_json::Value::Array(Vec::new())
    };
    let mut assessment =
        serde_json::to_value(&report.assessment).map_err(|error| error.to_string())?;
    if !report.metadata.include_evidence {
        if let Some(controls) = assessment
            .get_mut("controls")
            .and_then(serde_json::Value::as_array_mut)
        {
            for control in controls {
                control["evidence"] = serde_json::Value::Array(Vec::new());
            }
        }
    }
    if !report.metadata.include_references {
        if let Some(assessment) = assessment.as_object_mut() {
            assessment.remove("sourceLabel");
            assessment.remove("sourceUrl");
        }
    }
    let value = serde_json::json!({
        "schemaVersion": 1,
        "documentType": "oxAudit compliance readiness report",
        "claimBoundary": "Evidence readiness only - not certification, legal advice, or a conformity determination.",
        "generatedAtMs": report.generated_at_ms,
        "report": report.metadata,
        "assessment": assessment,
        "reviews": reviews
    });
    serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())
}

fn generate_csv(report: &ReportDocument) -> String {
    let latest = latest_reviews(report);
    let mut output = String::from("control_id,reference,title,automated_status,reviewed_status,assurance,evidence_count,evidence_locators,reviewer,review_note,claim_boundary\r\n");
    for control in &report.assessment.controls {
        let review = latest.get(control.control_id.as_str()).copied();
        let evidence = if report.metadata.include_evidence {
            control
                .evidence
                .iter()
                .map(|item| item.locator.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        } else {
            String::new()
        };
        let row = [
            control.control_id.clone(),
            control.reference.clone(),
            control.title.clone(),
            enum_label(control.automated_status),
            review
                .map(|item| enum_label(item.status))
                .unwrap_or_default(),
            format!("{:?}", control.assurance),
            control.evidence.len().to_string(),
            evidence,
            if report.metadata.include_reviews {
                review.map(|item| item.author.clone()).unwrap_or_default()
            } else {
                String::new()
            },
            if report.metadata.include_reviews {
                review.map(|item| item.note.clone()).unwrap_or_default()
            } else {
                String::new()
            },
            "Evidence readiness only - not certification, legal advice, or a conformity determination.".into(),
        ];
        output.push_str(
            &row.iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push_str("\r\n");
    }
    output
}

fn generate_markdown(report: &ReportDocument) -> String {
    let summary = &report.assessment.summary;
    let latest = latest_reviews(report);
    let mut output = format!(
        "# {}\n\n**Organization:** {}  \n**Framework:** {} ({})  \n**Assessment:** `{}`  \n**Target:** `{}`  \n**Assessor:** {}  \n**Classification:** {}  \n**Generated:** {}\n\n> **Readiness boundary:** Evidence coverage is not certification, legal advice, or a determination of conformity.\n\n## Executive summary\n\n{}\n\n## Scope and method\n\n{}\n\nThe bounded collector evaluates filenames, metadata, hashes for eligible evidence documents, and completed oxAudit runs. It does not interpret copyrighted standard text or silently infer human decisions.\n\n## Evidence readiness summary\n\n| Coverage | Supported | Partial | Gap | Manual review | Not applicable |\n|---:|---:|---:|---:|---:|---:|\n| {}% | {} | {} | {} | {} | {} |\n\n## Control matrix\n\n| Reference | Control | Automated evidence | Latest review | Evidence |\n|---|---|---|---|---:|\n",
        md(&report.metadata.title), md(&report.metadata.organization), md(&report.assessment.profile_name), md(&report.assessment.profile_version), md(&report.assessment.id), md(&report.assessment.target_label), md(&report.metadata.assessor), md(&report.metadata.classification), display_time(report.generated_at_ms), md(&report.metadata.executive_summary), md(&report.assessment.metadata.scope), summary.evidence_coverage_percent, summary.supported, summary.partial, summary.gap, summary.manual_review, summary.not_applicable
    );
    for control in &report.assessment.controls {
        let reviewed = latest
            .get(control.control_id.as_str())
            .map(|review| enum_label(review.status))
            .unwrap_or_else(|| {
                if report.metadata.include_reviews {
                    "Not reviewed"
                } else {
                    "Not included"
                }
                .into()
            });
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md(&control.reference),
            md(&control.title),
            enum_label(control.automated_status),
            reviewed,
            control.evidence.len()
        ));
    }
    output.push_str("\n## Detailed observations\n");
    for control in &report.assessment.controls {
        output.push_str(&format!(
            "\n### {} - {}\n\n{}\n\n- Automated evidence: **{}**\n- Rationale: {}\n",
            md(&control.reference),
            md(&control.title),
            md(&control.objective),
            enum_label(control.automated_status),
            md(&control.rationale)
        ));
        if report.metadata.include_evidence {
            if control.evidence.is_empty() {
                output.push_str("- Evidence: none matched\n");
            } else {
                for evidence in &control.evidence {
                    output.push_str(&format!(
                        "- Evidence: `{}` ({}){}\n",
                        md(&evidence.locator),
                        md(&evidence.kind),
                        evidence
                            .content_sha256
                            .as_ref()
                            .map(|hash| format!(", SHA-256 `{}`", md(hash)))
                            .unwrap_or_default()
                    ));
                }
            }
        }
        if report.metadata.include_reviews {
            if let Some(review) = latest.get(control.control_id.as_str()) {
                output.push_str(&format!(
                    "- Latest review: **{}** by {} - {}\n",
                    enum_label(review.status),
                    md(&review.author),
                    md(&review.note)
                ));
            }
        }
    }
    if report.metadata.include_references {
        output.push_str(&format!(
            "\n## Source reference\n\n- [{}]({})\n\n{}\n",
            md(&report.assessment.source_label),
            report.assessment.source_url,
            md(&report.assessment.disclaimer)
        ));
    }
    output
}

fn generate_html(report: &ReportDocument) -> String {
    let latest = latest_reviews(report);
    let summary = &report.assessment.summary;
    let rows = report.assessment.controls.iter().map(|control| {
        let review = latest.get(control.control_id.as_str()).copied();
        let evidence = if report.metadata.include_evidence && !control.evidence.is_empty() {
            format!("<ul>{}</ul>", control.evidence.iter().map(|item| format!("<li><code>{}</code> <span>{}</span></li>", html(&item.locator), html(&item.kind))).collect::<String>())
        } else { "<p class=muted>No matching evidence displayed.</p>".into() };
        let review_html = if report.metadata.include_reviews {
            review.map(|item| format!("<div class=review><b>{}</b> by {}<br>{}</div>", html(&enum_label(item.status)), html(&item.author), html(&item.note))).unwrap_or_else(|| "<p class=muted>No human decision recorded.</p>".into())
        } else { String::new() };
        format!("<article class=control><header><div><span class=ref>{}</span><h3>{}</h3></div><span class=badge>{}</span></header><p>{}</p><p class=muted>{}</p>{}{}</article>", html(&control.reference), html(&control.title), html(&enum_label(control.automated_status)), html(&control.objective), html(&control.rationale), evidence, review_html)
    }).collect::<String>();
    let references = if report.metadata.include_references {
        format!("<section><h2>Source and boundary</h2><p><a href=\"{}\">{}</a></p><p class=notice>{}</p></section>", html_attr(&report.assessment.source_url), html(&report.assessment.source_label), html(&report.assessment.disclaimer))
    } else {
        String::new()
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#d8dee9;--panel:#f7f9fc;--accent:#2563eb;--warn:#92400e}}*{{box-sizing:border-box}}body{{margin:0;background:#eef2f7;color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}}main{{max-width:1040px;margin:32px auto;background:white;box-shadow:0 16px 48px #1e293b18}}.cover{{padding:64px;background:linear-gradient(135deg,#10213f,#1f4b83);color:white}}.eyebrow,.ref{{font-size:11px;text-transform:uppercase;letter-spacing:.12em;font-weight:700}}h1{{font-size:38px;line-height:1.1;margin:18px 0}}h2{{font-size:19px;margin:0 0 16px}}h3{{font-size:15px;margin:4px 0}}.meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:36px}}.meta div{{padding:12px;border:1px solid #ffffff35}}section{{padding:30px 40px;border-bottom:1px solid var(--line)}}.notice{{padding:14px 16px;background:#fff7ed;border-left:4px solid #f59e0b;color:var(--warn)}}.metrics{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}}.metric{{padding:12px;background:var(--panel);border:1px solid var(--line)}}.metric strong{{display:block;font-size:24px}}.control{{padding:20px 0;border-top:1px solid var(--line)}}.control header{{display:flex;justify-content:space-between;gap:16px}}.badge{{height:max-content;padding:4px 9px;border-radius:99px;background:#e8efff;color:#174ea6;font-size:11px;font-weight:700}}.muted{{color:var(--muted)}}code{{overflow-wrap:anywhere}}.review{{padding:12px;background:#eef8f1;border-left:3px solid #22a06b}}footer{{padding:24px 40px;color:var(--muted);font-size:11px}}@media(max-width:700px){{main{{margin:0}}.cover,section{{padding:24px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.meta{{grid-template-columns:1fr}}}}@media print{{body{{background:white}}main{{margin:0;box-shadow:none}}.control{{break-inside:avoid}}}}</style></head><body><main>
<header class="cover"><div class="eyebrow">oxAudit - Compliance Readiness</div><h1>{}</h1><p>{}</p><div class="meta"><div><small>Framework</small><br><b>{} {}</b></div><div><small>Organization</small><br><b>{}</b></div><div><small>Assessor</small><br><b>{}</b></div><div><small>Classification</small><br><b>{}</b></div></div></header>
<section><h2>Readiness boundary</h2><p class="notice">Evidence coverage is not certification, legal advice, or a determination of conformity. Human and legal review remains required.</p><h2>Executive summary</h2><p>{}</p><p class="muted">Target: <code>{}</code><br>Generated: {}</p></section>
<section><h2>Evidence readiness summary</h2><div class="metrics"><div class="metric"><strong>{}%</strong>Coverage</div><div class="metric"><strong>{}</strong>Supported</div><div class="metric"><strong>{}</strong>Partial</div><div class="metric"><strong>{}</strong>Gaps</div><div class="metric"><strong>{}</strong>Manual</div><div class="metric"><strong>{}</strong>N/A</div></div></section>
<section><h2>Detailed controls</h2>{}</section>{}<footer>Assessment {} - generated by oxAudit - {}</footer></main></body></html>"#,
        html(&report.metadata.title),
        html(&report.metadata.title),
        html(&report.metadata.executive_summary),
        html(&report.assessment.profile_name),
        html(&report.assessment.profile_version),
        html(&report.metadata.organization),
        html(&report.metadata.assessor),
        html(&report.metadata.classification),
        html(&report.metadata.executive_summary),
        html(&report.assessment.target_label),
        display_time(report.generated_at_ms),
        summary.evidence_coverage_percent,
        summary.supported,
        summary.partial,
        summary.gap,
        summary.manual_review,
        summary.not_applicable,
        rows,
        references,
        html(&report.assessment.id),
        html(&display_time(report.generated_at_ms))
    )
}

#[derive(Clone, Copy)]
enum PdfStyle {
    Title,
    Heading,
    Body,
    Muted,
    Status,
}

struct PdfLine {
    text: String,
    style: PdfStyle,
}

fn generate_pdf(report: &ReportDocument) -> Result<Vec<u8>, String> {
    let mut lines = Vec::new();
    push_paragraphs(&mut lines, &report.metadata.title, PdfStyle::Title);
    lines.push(PdfLine {
        text: format!(
            "{} - {}",
            report.assessment.profile_name, report.assessment.profile_version
        ),
        style: PdfStyle::Heading,
    });
    lines.push(PdfLine {
        text: format!("Organization: {}", report.metadata.organization),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: format!(
            "Assessor: {} | Classification: {}",
            report.metadata.assessor, report.metadata.classification
        ),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: format!("Generated: {}", display_time(report.generated_at_ms)),
        style: PdfStyle::Muted,
    });
    lines.push(PdfLine {
        text: String::new(),
        style: PdfStyle::Body,
    });
    lines.push(PdfLine {
        text: "READINESS BOUNDARY".into(),
        style: PdfStyle::Heading,
    });
    push_paragraphs(&mut lines, "Evidence coverage is not certification, legal advice, or a determination of conformity. Qualified human review remains required.", PdfStyle::Status);
    lines.push(PdfLine {
        text: "EXECUTIVE SUMMARY".into(),
        style: PdfStyle::Heading,
    });
    push_paragraphs(
        &mut lines,
        &report.metadata.executive_summary,
        PdfStyle::Body,
    );
    lines.push(PdfLine {
        text: "SCOPE".into(),
        style: PdfStyle::Heading,
    });
    push_paragraphs(
        &mut lines,
        &report.assessment.metadata.scope,
        PdfStyle::Body,
    );
    lines.push(PdfLine {
        text: "EVIDENCE READINESS".into(),
        style: PdfStyle::Heading,
    });
    lines.push(PdfLine {
        text: format!(
            "Coverage {}% | Supported {} | Partial {} | Gap {} | Manual {} | N/A {}",
            report.assessment.summary.evidence_coverage_percent,
            report.assessment.summary.supported,
            report.assessment.summary.partial,
            report.assessment.summary.gap,
            report.assessment.summary.manual_review,
            report.assessment.summary.not_applicable
        ),
        style: PdfStyle::Status,
    });
    lines.push(PdfLine {
        text: "CONTROL DETAILS".into(),
        style: PdfStyle::Heading,
    });
    let latest = latest_reviews(report);
    for control in &report.assessment.controls {
        lines.push(PdfLine {
            text: format!("{} - {}", control.reference, control.title),
            style: PdfStyle::Heading,
        });
        lines.push(PdfLine {
            text: format!(
                "Automated evidence: {}",
                enum_label(control.automated_status)
            ),
            style: PdfStyle::Status,
        });
        push_paragraphs(&mut lines, &control.objective, PdfStyle::Body);
        push_paragraphs(&mut lines, &control.rationale, PdfStyle::Muted);
        if report.metadata.include_evidence {
            for evidence in &control.evidence {
                push_paragraphs(
                    &mut lines,
                    &format!("Evidence: {} ({})", evidence.locator, evidence.kind),
                    PdfStyle::Muted,
                );
            }
        }
        if report.metadata.include_reviews {
            if let Some(review) = latest.get(control.control_id.as_str()) {
                push_paragraphs(
                    &mut lines,
                    &format!(
                        "Review: {} by {} - {}",
                        enum_label(review.status),
                        review.author,
                        review.note
                    ),
                    PdfStyle::Body,
                );
            }
        }
        lines.push(PdfLine {
            text: String::new(),
            style: PdfStyle::Body,
        });
    }
    if report.metadata.include_references {
        lines.push(PdfLine {
            text: "SOURCE REFERENCE".into(),
            style: PdfStyle::Heading,
        });
        push_paragraphs(&mut lines, &report.assessment.source_label, PdfStyle::Body);
        push_paragraphs(&mut lines, &report.assessment.source_url, PdfStyle::Muted);
        push_paragraphs(&mut lines, &report.assessment.disclaimer, PdfStyle::Status);
    }
    render_pdf(&report.metadata.title, &report.assessment.id, &lines)
}

// This bundled, static TrueType face works offline on every supported platform.
// Source, transformation recipe, coverage limits, and OFL are in assets/fonts/README.md.
const PDF_FONT: &[u8] = include_bytes!("../../../assets/fonts/oxAuditSansSC-Regular.ttf");
const PDF_TEXT_WIDTH_PT: f32 = 174.0 * 72.0 / 25.4;

impl PdfStyle {
    fn size(self) -> f32 {
        match self {
            Self::Title => 24.0,
            Self::Heading => 11.0,
            Self::Body => 9.2,
            Self::Muted => 8.4,
            Self::Status => 9.0,
        }
    }

    fn height(self) -> f32 {
        match self {
            Self::Title => 13.0,
            Self::Heading => 8.0,
            _ => 6.0,
        }
    }
}

fn render_pdf(title: &str, assessment_id: &str, lines: &[PdfLine]) -> Result<Vec<u8>, String> {
    const TOP: f32 = 267.0;
    const BOTTOM: f32 = 24.0;
    let font = ParsedFont::from_bytes(PDF_FONT, 0, &mut Vec::new())
        .ok_or_else(|| "PDF export could not load its bundled font".to_string())?;
    let lines = layout_pdf_lines(&font, lines)?;
    // IDs also appear in the footer and must not bypass glyph validation.
    pdf_text_width(&font, assessment_id, 7.5)?;
    let mut document = PdfDocument::new(title);
    let font_id = document.add_font(&font);
    let mut page_lines: Vec<Vec<&PdfLine>> = vec![Vec::new()];
    let mut y = TOP;
    for line in &lines {
        let height = line.style.height();
        let heading_needs_detail_space = matches!(line.style, PdfStyle::Heading) && y < 72.0;
        if y - height < BOTTOM || heading_needs_detail_space {
            page_lines.push(Vec::new());
            y = TOP;
        }
        page_lines.last_mut().unwrap().push(line);
        y -= height;
    }
    let total = page_lines.len();
    let mut pages = Vec::with_capacity(total);
    for (index, page) in page_lines.into_iter().enumerate() {
        let mut ops = Vec::new();
        text_op(
            &mut ops,
            "oxAudit | Compliance Readiness",
            18.0,
            284.0,
            8.0,
            &font_id,
            (0.13, 0.29, 0.52),
        );
        let footer = format!("{} | Page {} of {}", assessment_id, index + 1, total);
        if pdf_text_width(&font, &footer, 7.5)? > PDF_TEXT_WIDTH_PT {
            return Err("PDF assessment identifier is too long for the page footer".into());
        }
        text_op(
            &mut ops,
            &footer,
            18.0,
            12.0,
            7.5,
            &font_id,
            (0.40, 0.44, 0.52),
        );
        let mut y = TOP;
        for line in page {
            let color = match line.style {
                PdfStyle::Title => (0.08, 0.16, 0.28),
                PdfStyle::Heading => (0.13, 0.29, 0.52),
                PdfStyle::Body => (0.10, 0.13, 0.19),
                PdfStyle::Muted => (0.40, 0.44, 0.52),
                PdfStyle::Status => (0.55, 0.28, 0.05),
            };
            if !line.text.is_empty() {
                text_op(
                    &mut ops,
                    &line.text,
                    18.0,
                    y,
                    line.style.size(),
                    &font_id,
                    color,
                );
            }
            y -= line.style.height();
        }
        pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
    }
    let mut warnings = Vec::new();
    let bytes = document
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut warnings);
    if let Some(error) = warnings
        .iter()
        .find(|warning| warning.severity == printpdf::PdfParseErrorSeverity::Error)
    {
        return Err(format!("PDF export failed: {}", error.msg));
    }
    // printpdf 0.8 writes Info/Title as an unmarked UTF-8 literal. PDF readers
    // interpret that as PDFDocEncoding, so encode this metadata as UTF-16BE.
    let mut pdf =
        lopdf::Document::load_mem(&bytes).map_err(|error| format!("PDF export: {error}"))?;
    let info_id = pdf
        .trailer
        .get(b"Info")
        .and_then(lopdf::Object::as_reference)
        .map_err(|error| format!("PDF metadata: {error}"))?;
    pdf.get_dictionary_mut(info_id)
        .map_err(|error| format!("PDF metadata: {error}"))?
        .set("Title", lopdf::text_string(title));
    let mut bytes = Vec::new();
    pdf.save_to(&mut bytes)
        .map_err(|error| format!("PDF export: {error}"))?;
    Ok(bytes)
}

fn text_op(
    ops: &mut Vec<Op>,
    text: &str,
    x: f32,
    y: f32,
    size: f32,
    font: &FontId,
    color: (f32, f32, f32),
) {
    ops.extend([
        Op::StartTextSection,
        Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(y)),
        },
        Op::SetFontSize {
            size: Pt(size),
            font: font.clone(),
        },
        Op::SetFillColor {
            col: Color::Rgb(Rgb {
                r: color.0,
                g: color.1,
                b: color.2,
                icc_profile: None,
            }),
        },
        Op::WriteText {
            items: vec![TextItem::Text(text.to_owned())],
            font: font.clone(),
        },
        Op::EndTextSection,
    ]);
}

fn push_paragraphs(lines: &mut Vec<PdfLine>, value: &str, style: PdfStyle) {
    lines.extend(value.lines().map(|paragraph| PdfLine {
        text: paragraph.into(),
        style,
    }));
}

fn pdf_character_width(font: &ParsedFont, character: char, size: f32) -> Result<f32, String> {
    // This renderer places individual glyphs. Combining marks, variation selectors,
    // and format controls require shaping or bidi handling we do not yet provide.
    let needs_shaping = matches!(character as u32,
        0x00ad | 0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff |
        0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f |
        0x20d0..=0x20ff | 0x302a..=0x302f | 0x3099..=0x309a | 0xfe00..=0xfe0f | 0xfe20..=0xfe2f |
        0xe0100..=0xe01ef);
    let glyph = font
        .lookup_glyph_index(character as u32)
        .filter(|glyph| *glyph != 0);
    if needs_shaping || character as u32 > 0xffff || character.is_control() || glyph.is_none() {
        return Err(format!(
            "PDF export does not support character U+{:04X} ({character:?}) with its bundled font and text layout; use HTML or JSON to preserve this text.",
            character as u32
        ));
    }
    // Read hmtx advances, including blank glyphs. printpdf's outline-based
    // get_horizontal_advance returns zero for spaces and underestimates lines.
    let last_metric = font
        .hhea_table
        .as_ref()
        .and_then(|table| table.num_h_metrics.checked_sub(1))
        .ok_or_else(|| "PDF font has no horizontal metrics".to_string())?;
    let offset = usize::from(glyph.unwrap().min(last_metric)) * 4;
    let metric = font
        .hmtx_data
        .get(offset..offset + 2)
        .ok_or_else(|| "PDF font has invalid horizontal metrics".to_string())?;
    let advance = u16::from_be_bytes([metric[0], metric[1]]);
    Ok(advance as f32 / font.font_metrics.units_per_em as f32 * size)
}

fn pdf_text_width(font: &ParsedFont, text: &str, size: f32) -> Result<f32, String> {
    text.chars()
        .map(|character| pdf_character_width(font, character, size))
        .sum()
}

fn layout_pdf_lines(font: &ParsedFont, lines: &[PdfLine]) -> Result<Vec<PdfLine>, String> {
    let mut result = Vec::new();
    for line in lines {
        // Every field, including headings and organization, follows the same measured
        // layout. Character boundaries handle Chinese and long unbroken evidence paths.
        for paragraph in line.text.split('\n') {
            let mut current = String::new();
            let mut width = 0.0;
            for character in
                paragraph
                    .trim_end_matches('\r')
                    .chars()
                    .map(|c| if c == '\t' { ' ' } else { c })
            {
                let advance = pdf_character_width(font, character, line.style.size())?;
                while width + advance > PDF_TEXT_WIDTH_PT && !current.is_empty() {
                    let carry = if let Some(space) = current.rfind(' ').filter(|index| *index > 0) {
                        let carry = current.split_off(space + 1);
                        current.pop();
                        carry
                    } else {
                        String::new()
                    };
                    result.push(PdfLine {
                        text: current,
                        style: line.style,
                    });
                    current = carry;
                    width = pdf_text_width(font, &current, line.style.size())?;
                }
                // A space at a wrap boundary is represented by the line break.
                if character == ' ' && current.is_empty() {
                    continue;
                }
                current.push(character);
                width += advance;
            }
            result.push(PdfLine {
                text: current,
                style: line.style,
            });
        }
    }
    Ok(result)
}

fn latest_reviews(report: &ReportDocument) -> BTreeMap<&str, &ComplianceReview> {
    let mut latest = BTreeMap::new();
    if !report.metadata.include_reviews {
        return latest;
    }
    for review in &report.reviews {
        latest.entry(review.control_id.as_str()).or_insert(review);
    }
    latest
}

fn enum_label<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn display_time(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|time| time.to_rfc3339())
        .unwrap_or_else(|| value.to_string())
}

fn csv_cell(value: &str) -> String {
    let first_non_whitespace = value.trim_start().chars().next();
    let safe = if first_non_whitespace.is_some_and(|character| "=+-@".contains(character)) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}

fn md(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_attr(value: &str) -> String {
    html(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_compliance::{assess, builtin_profile, AssessmentMetadata, EvidenceSnapshot};

    fn fixture() -> ReportDocument {
        let assessment = assess(
            &builtin_profile("gdpr").unwrap(),
            &EvidenceSnapshot {
                root_label: "/project".into(),
                files: vec![],
                completed_runs: vec![],
                collection_limits: vec!["bounded".into()],
            },
            AssessmentMetadata {
                title: "Readiness".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                scope: "Product and service".into(),
            },
            "assessment-test".into(),
            1,
        )
        .unwrap();
        ReportDocument {
            assessment,
            reviews: vec![],
            metadata: ComplianceReportMetadata {
                title: "Privacy Readiness Report".into(),
                organization: "Example".into(),
                assessor: "Reviewer".into(),
                classification: "Confidential".into(),
                executive_summary:
                    "This report summarizes evidence readiness and open human-review work.".into(),
                include_evidence: true,
                include_reviews: true,
                include_references: true,
            },
            generated_at_ms: 1,
        }
    }

    #[test]
    fn every_format_has_a_stable_signature() {
        let report = fixture();
        let json = generate(&report, ComplianceReportFormat::Json)
            .unwrap()
            .bytes;
        let csv = generate(&report, ComplianceReportFormat::Csv)
            .unwrap()
            .bytes;
        let markdown = generate(&report, ComplianceReportFormat::Markdown)
            .unwrap()
            .bytes;
        let html = generate(&report, ComplianceReportFormat::Html)
            .unwrap()
            .bytes;
        let pdf = generate(&report, ComplianceReportFormat::Pdf)
            .unwrap()
            .bytes;
        assert!(json.starts_with(b"{"));
        assert!(csv.starts_with(b"control_id"));
        assert!(markdown.starts_with(b"# "));
        assert!(html.starts_with(b"<!doctype html>"));
        assert!(pdf.starts_with(b"%PDF"));
        if let Ok(output_path) = std::env::var("OXAUDIT_PDF_QA_OUTPUT") {
            let output_path = std::path::PathBuf::from(output_path);
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(output_path, pdf).unwrap();
        }
    }

    #[test]
    fn csv_qualification_is_a_parseable_column_with_quoted_unicode_fields() {
        let mut report = fixture();
        report.assessment.controls[0].title = "隐私, café \"review\"\nnext line".into();
        report.metadata.include_reviews = false;
        report.metadata.include_references = false;
        let generated = generate(&report, ComplianceReportFormat::Csv).unwrap();
        let mut reader = csv::Reader::from_reader(generated.bytes.as_slice());
        let headers = reader.headers().unwrap().clone();
        let boundary = headers
            .iter()
            .position(|header| header == "claim_boundary")
            .expect("CSV must carry its qualification in a regular column");
        let title = headers.iter().position(|header| header == "title").unwrap();
        let rows = reader.records().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(rows.len(), report.assessment.controls.len());
        assert_eq!(&rows[0][title], "隐私, café \"review\"\nnext line");
        for row in rows {
            assert_eq!(row.len(), headers.len());
            assert!(row[boundary].contains("Evidence readiness only"));
            assert!(row[boundary].contains("not certification"));
            assert!(row[boundary].contains("conformity determination"));
        }
    }

    #[test]
    fn pdf_preserves_chinese_and_accented_text_across_pages() {
        let mut report = fixture();
        report.metadata.title = "隐私合规评估 Café résumé".into();
        report.metadata.organization = "上海示例公司 München".into();
        report.metadata.assessor = "审查员 Chloé".into();
        report.metadata.executive_summary = "证据准备情况与人工审核结论 séparées".repeat(100);
        report.assessment.metadata.scope = "产品和服务 périmètre".into();
        report.assessment.controls[0].title = "访问控制 Sécurité".into();
        report.reviews.push(ComplianceReview {
            id: "review-unicode".into(),
            assessment_id: report.assessment.id.clone(),
            control_id: report.assessment.controls[0].control_id.clone(),
            status: oxaudit_compliance::ReadinessStatus::Partial,
            note: "仍需人工核验 données".into(),
            author: "José 审核".into(),
            reviewed_at_ms: 2,
        });
        let bytes = generate(&report, ComplianceReportFormat::Pdf)
            .unwrap()
            .bytes;
        let pdf = PdfDocument::parse(&bytes, &Default::default(), &mut Vec::new()).unwrap();
        assert!(pdf.pages.len() > 2);
        let text = pdf
            .pages
            .iter()
            .flat_map(|page| page.extract_text(&pdf.resources))
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "隐私合规评估 Café résumé",
            "上海示例公司 München",
            "审查员 Chloé",
            "产品和服务 périmètre",
            "访问控制 Sécurité",
            "仍需人工核验 données",
            "José 审核",
        ] {
            assert!(
                text.contains(expected),
                "PDF text lost {expected:?}: {text}"
            );
        }
        assert!(text.contains("not certification"));
        assert!(text.contains(&format!("Page {} of {}", pdf.pages.len(), pdf.pages.len())));
        if let Ok(output_path) = std::env::var("OXAUDIT_UNICODE_PDF_QA_OUTPUT") {
            std::fs::write(output_path, bytes).unwrap();
        }
    }

    #[test]
    fn pdf_metadata_title_preserves_unicode_for_standard_readers() {
        let mut report = fixture();
        report.metadata.title = "隐私合规评估 Café résumé".into();
        let bytes = generate(&report, ComplianceReportFormat::Pdf)
            .unwrap()
            .bytes;
        let pdf = lopdf::Document::load_mem(&bytes).unwrap();
        let info_id = pdf.trailer.get(b"Info").unwrap().as_reference().unwrap();
        let info = pdf.get_dictionary(info_id).unwrap();
        let title = lopdf::decode_text_string(info.get(b"Title").unwrap()).unwrap();
        assert_eq!(title, "隐私合规评估 Café résumé");
    }

    #[test]
    fn pdf_layout_counts_blank_glyph_advances() {
        let font = ParsedFont::from_bytes(PDF_FONT, 0, &mut Vec::new()).unwrap();
        // The pinned face defines the ASCII and nonbreaking spaces as 224/1000 em.
        // Blank glyphs have no outline, but their widths still affect page margins.
        assert!((pdf_text_width(&font, " \u{00a0}", 10.0).unwrap() - 4.48).abs() < 0.001);
    }

    #[test]
    fn pdf_wraps_long_words_and_cjk_inside_page_margins() {
        let font = ParsedFont::from_bytes(PDF_FONT, 0, &mut Vec::new()).unwrap();
        for text in [
            format!("i {}中", "i".repeat(72)),
            "证据路径".repeat(100),
            "https://example.test/".to_owned() + &"long-path/".repeat(100),
        ] {
            let lines = layout_pdf_lines(
                &font,
                &[PdfLine {
                    text: text.clone(),
                    style: PdfStyle::Title,
                }],
            )
            .unwrap();
            for line in &lines {
                let width = pdf_text_width(&font, &line.text, 24.0).unwrap();
                assert!(
                    width <= 493.23,
                    "line exceeds 174 mm content width: {width} pt"
                );
            }
            assert_eq!(
                lines
                    .iter()
                    .map(|line| line.text.as_str())
                    .collect::<String>()
                    .replace(' ', ""),
                text.replace(' ', "")
            );
        }
    }

    #[test]
    fn pdf_keeps_distinct_characters_that_share_an_upstream_font_glyph() {
        let mut report = fixture();
        let expected = "Space A B A\u{00a0}B | hyphens - ‑ | marks • · | Han 一 ⼀";
        report.metadata.executive_summary = expected.into();
        let bytes = generate(&report, ComplianceReportFormat::Pdf)
            .unwrap()
            .bytes;
        let pdf = PdfDocument::parse(&bytes, &Default::default(), &mut Vec::new()).unwrap();
        let text = pdf
            .pages
            .iter()
            .flat_map(|page| page.extract_text(&pdf.resources))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains(expected),
            "PDF conflated distinct code points: {text}"
        );
    }

    #[test]
    fn pdf_rejects_supplementary_characters_instead_of_corrupting_to_unicode_map() {
        let mut report = fixture();
        // Noto Sans SC contains this glyph, but printpdf 0.8 cannot emit its
        // UTF-16 surrogate pair in the extraction map.
        report.metadata.organization = "Chinese \u{2000b}".into();
        let error = generate(&report, ComplianceReportFormat::Pdf)
            .err()
            .expect("unsupported ToUnicode code point must fail the export");
        assert!(error.contains("U+2000B"), "{error}");
    }

    #[test]
    fn pdf_rejects_unsupported_glyphs_without_silent_substitution() {
        let mut report = fixture();
        report.metadata.organization = "Unsupported \u{1f9ea}".into();
        let error = generate(&report, ComplianceReportFormat::Pdf)
            .err()
            .expect("unsupported glyph must fail the export");
        assert!(error.contains("U+1F9EA"), "{error}");
        assert!(error.contains("PDF"), "{error}");
    }

    #[test]
    fn excluded_reviews_do_not_disclose_decisions_in_csv_or_markdown() {
        let mut report = fixture();
        report.reviews.push(ComplianceReview {
            id: "review-private".into(),
            assessment_id: report.assessment.id.clone(),
            control_id: report.assessment.controls[0].control_id.clone(),
            status: oxaudit_compliance::ReadinessStatus::NotApplicable,
            note: "Private reviewer rationale".into(),
            author: "Private reviewer".into(),
            reviewed_at_ms: 2,
        });
        for format in [
            ComplianceReportFormat::Csv,
            ComplianceReportFormat::Markdown,
        ] {
            report.metadata.include_reviews = true;
            let included = String::from_utf8(generate(&report, format).unwrap().bytes).unwrap();
            assert!(included.contains("notApplicable"));
            report.metadata.include_reviews = false;
            let excluded = String::from_utf8(generate(&report, format).unwrap().bytes).unwrap();
            assert!(
                !excluded.contains("notApplicable"),
                "review decision leaked in {format:?}"
            );
            assert!(!excluded.contains("Private reviewer"));
        }
    }

    #[test]
    fn json_respects_source_reference_disclosure_without_removing_claim_boundary() {
        let mut report = fixture();
        report.assessment.source_label = "Private source reference".into();
        report.assessment.source_url = "https://example.test/private-source".into();
        let included: serde_json::Value = serde_json::from_slice(
            &generate(&report, ComplianceReportFormat::Json)
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert_eq!(
            included["assessment"]["sourceLabel"],
            "Private source reference"
        );
        report.metadata.include_references = false;
        let excluded: serde_json::Value = serde_json::from_slice(
            &generate(&report, ComplianceReportFormat::Json)
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert!(excluded["assessment"].get("sourceLabel").is_none());
        assert!(excluded["assessment"].get("sourceUrl").is_none());
        assert!(excluded["claimBoundary"]
            .as_str()
            .unwrap()
            .contains("not certification"));
        assert_eq!(
            excluded["assessment"]["disclaimer"],
            report.assessment.disclaimer
        );
    }

    #[test]
    fn html_escapes_user_controlled_values() {
        let mut report = fixture();
        report.metadata.title = "<script>alert(1)</script>".into();
        let html = String::from_utf8(
            generate(&report, ComplianceReportFormat::Html)
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn csv_cells_neutralize_spreadsheet_formulas() {
        for value in ["=1+1", "+SUM(A1:A2)", "-2+3", "@cmd", " \t=1+1"] {
            let cell = csv_cell(value);
            assert!(
                cell.starts_with("\"'"),
                "formula was not neutralized: {cell}"
            );
            assert!(cell.ends_with('"'));
        }

        assert_eq!(csv_cell("ordinary text"), "\"ordinary text\"");
        assert_eq!(csv_cell("a \"quote\""), "\"a \"\"quote\"\"\"");
    }
}

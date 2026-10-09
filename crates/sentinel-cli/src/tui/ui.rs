use super::app::{safe, App, View};
use ratatui::{prelude::*, widgets::*};
const BG: Color = Color::Rgb(8, 8, 8);
const PANEL: Color = Color::Rgb(8, 8, 8);
const BORDER: Color = Color::Rgb(115, 109, 99);
const TEXT: Color = Color::Rgb(239, 236, 228);
const MUTED: Color = Color::Rgb(166, 153, 130);
const ORANGE: Color = Color::Rgb(222, 140, 71);
const RISK: Color = Color::Rgb(236, 155, 89);
fn panel(title: impl Into<String>) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Plain)
        .title(format!(" {} ", title.into()))
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(PANEL).fg(TEXT))
}
fn paragraph(frame: &mut Frame, area: Rect, title: &str, text: impl Into<String>, scroll: u16) {
    frame.render_widget(
        Paragraph::new(text.into())
            .block(panel(title))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}
fn severity(s: sentinel_core::Severity) -> Color {
    use sentinel_core::Severity::*;
    match s {
        Critical | High => RISK,
        Medium => Color::Rgb(222, 140, 71),
        Low => TEXT,
        Info => MUTED,
    }
}
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::new().style(Style::new().bg(BG).fg(TEXT)), area);
    if area.width < 65 || area.height < 18 {
        paragraph(frame,area,"SENTINEL",format!("Enlarge the terminal to at least 65 x 18.\nCurrent: {} x {}\n\nq quits; running operations remain cancellable with Esc.",area.width,area.height),0);
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .margin(1)
    .split(area);
    let state = match &app.report {
        None => "NOT SCANNED",
        Some(r) if r.outcome != sentinel_core::ScanOutcome::Complete => "INCOMPLETE COVERAGE",
        Some(r) if !r.findings.is_empty() => "REVIEW REQUIRISK",
        Some(_) => "NO FINDINGS IN SCOPE",
    };
    let header = vec![
        Line::from(vec![
            Span::styled(" SENTINEL", Style::new().fg(TEXT).bold()),
            Span::styled(" / LOCAL SECURITY CONSOLE", Style::new().fg(MUTED)),
            Span::styled(format!("    {state}"), Style::new().fg(ORANGE)),
        ]),
        Line::styled(
            format!(" {}", safe(&app.project.to_string_lossy())),
            Style::new().fg(MUTED),
        ),
    ];
    frame.render_widget(
        Paragraph::new(header).block(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(Style::new().fg(BORDER)),
        ),
        rows[0],
    );
    let columns = Layout::horizontal([Constraint::Length(21), Constraint::Min(1)])
        .spacing(1)
        .split(rows[1]);
    navigation(frame, columns[0], app);
    match app.view {
        View::Overview => overview(frame, columns[1], app),
        View::Findings => findings(frame, columns[1], app),
        View::Rules => rules(frame, columns[1], app),
        View::Ai => ai(frame, columns[1], app),
        View::Intelligence => paragraph(
            frame,
            columns[1],
            "Security graph / verification / audit coverage / audit coverage",
            app.intelligence_text.clone(),
            app.scroll,
        ),
    }
    let actions = if app.job.is_some() {
        "Esc cancel"
    } else {
        match app.view {
            View::Overview => "a audit / p project",
            View::Findings => "/ search / e explain / s export",
            View::Rules => "arrows select rule",
            View::Ai => "Alt+m provider / Alt+b preview / Enter send",
            View::Intelligence => "g index / w verify / u coverage / h history / o jobs",
        }
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                format!(" {}", safe(&app.status)),
                Style::new().fg(if app.status_error { ORANGE } else { TEXT }),
            ),
            Line::styled(
                if app.view == View::Ai && !app.navigation_focus {
                    format!(" Type message / {actions} / Alt+? help / Tab sections / Ctrl+C quit")
                } else {
                    format!(
                        " Arrows navigate / Enter open / Tab focus / {actions} / ? help / Q quit"
                    )
                },
                Style::new().fg(MUTED),
            ),
        ]),
        rows[2],
    );
    if app.help {
        let modal = centered(area, 82, 25);
        frame.render_widget(Clear, modal);
        paragraph(frame,modal,"Keyboard guide","NAVIGATE\n  Tab / Shift+Tab           Switch focus\n  Arrows + Enter             Choose and open section\n  1-5                        Open section directly\n  j / k or arrows            Select finding / rule; scroll evidence\n  PgUp / PgDn / Home         Scroll detail / reset\n\nSECURITY\n  a Audit   d Git diff   g Index graph   w Verify patch   u Audit coverage   h Audit history   o Static jobs\n  / Filter findings   p Project path   t Severity threshold\n  x External scanners   v Semgrep config   s JSON export   S SARIF export\n\nCHAT\n  e Explain selected finding   c Explain codebase\n  Alt+m Provider   Alt+l Local model   Alt+n NIM model\n  Alt+p Project context on/off   Alt+r New chat\n  Alt+b Preview shared context   Enter Send message\n\n  Esc Close / cancel operation    Ctrl+C / q Quit\n  Exports create new files. Cloud submission sends the previewed context.\n  ? or Esc closes. Arrows / PgUp / PgDn scroll.",app.help_scroll);
    }
    if let Some(editor) = &app.editor {
        let modal = centered(area, 76, 7);
        frame.render_widget(Clear, modal);
        paragraph(
            frame,
            modal,
            &format!("Edit {:?}", editor.kind),
            format!(
                "{}\n\nEnter save   Esc cancel   Ctrl+U clear",
                safe(&editor.value)
                    .chars()
                    .rev()
                    .take(modal.width.saturating_sub(3) as usize)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>()
            ),
            0,
        );
        let cursor = editor
            .value
            .chars()
            .count()
            .min(modal.width.saturating_sub(3) as usize) as u16;
        frame.set_cursor_position((modal.x + 1 + cursor, modal.y + 1));
    }
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}
/// Deterministic branching contours, restricted to unused sidebar space.
fn marble(frame: &mut Frame, area: Rect) {
    if area.width < 5 || area.height < 4 {
        return;
    }
    for y in 0..area.height {
        let position = |row: u16| {
            (area.width as f32 * 0.25 + row as f32 * 0.32 + (row as f32 * 0.28).sin() * 1.4)
                .clamp(0.0, (area.width - 1) as f32) as u16
        };
        let x = position(y);
        let previous = position(y.saturating_sub(1));
        let glyph = match x.cmp(&previous) {
            std::cmp::Ordering::Greater => "╲",
            std::cmp::Ordering::Less => "╱",
            std::cmp::Ordering::Equal => "│",
        };
        frame.buffer_mut()[(area.x + x, area.y + y)]
            .set_symbol(glyph)
            .set_fg(Color::Rgb(43, 41, 37));
        if y > area.height / 2 {
            let branch = x.saturating_sub((y - area.height / 2) / 2 + 1);
            frame.buffer_mut()[(area.x + branch, area.y + y)]
                .set_symbol(if y % 2 == 0 { "╱" } else { "│" })
                .set_fg(Color::Rgb(29, 28, 25));
        }
    }
}
fn navigation(frame: &mut Frame, area: Rect, app: &App) {
    let block = panel(if app.navigation_focus {
        "SECTIONS / FOCUS"
    } else {
        "SECTIONS"
    });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let items = [
        "Overview",
        "Security findings",
        "Rules",
        "Chat",
        "Investigation",
    ]
    .iter()
    .enumerate()
    .map(|(i, label)| {
        let selected = if app.navigation_focus {
            app.navigation_selected == i
        } else {
            app.view.index() == i
        };
        ListItem::new(format!("{} {}", if selected { ">" } else { " " }, label)).style(
            if selected {
                Style::new().fg(ORANGE).bold()
            } else {
                Style::new().fg(MUTED)
            },
        )
    })
    .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items),
        Rect::new(inner.x, inner.y + 1, inner.width, 5.min(inner.height)),
    );
    if inner.height > 13 {
        marble(
            frame,
            Rect::new(
                inner.x + 1,
                inner.y + 8,
                inner.width.saturating_sub(2),
                inner.height.saturating_sub(12),
            ),
        );
        frame.render_widget(
            Paragraph::new(format!("LOCAL FIRST\nProvider: {}", app.provider_name()))
                .style(Style::new().fg(MUTED)),
            Rect::new(inner.x, inner.y + inner.height - 3, inner.width, 2),
        );
    }
}
fn overview(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::styled("SECURITY SUMMARY", Style::new().fg(TEXT).bold()),
        Line::from(""),
    ];
    if let Some(r) = &app.report {
        let high = r
            .findings
            .iter()
            .filter(|f| f.severity >= sentinel_core::Severity::High)
            .count();
        for (label, value) in [
            ("Scan coverage", format!("{:?}", r.outcome)),
            ("Findings", r.findings.len().to_string()),
            ("High / critical", high.to_string()),
            ("Files scanned", r.files_scanned.to_string()),
        ] {
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<20}"), Style::new().fg(MUTED)),
                Span::styled(value, Style::new().fg(TEXT)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Results concern supported scope; absence is not proof of safety.",
            Style::new().fg(MUTED),
        ));
        for note in r.coverage_notes.iter().take(3) {
            lines.push(Line::styled(safe(note), Style::new().fg(ORANGE)));
        }
    } else {
        lines.extend([
            Line::styled("Not scanned", Style::new().fg(ORANGE)),
            Line::from("Run an audit to inspect this project's supported code."),
            Line::from("No security assessment is available yet."),
        ]);
    }
    lines.extend([
        Line::from(""),
        Line::styled("NEXT ACTION", Style::new().fg(ORANGE)),
        Line::from("a  Audit project    d  Inspect changes"),
        Line::from("g  Index code       w  Verify patch"),
        Line::from("c  Explain codebase p  Change project"),
        Line::from(""),
        Line::styled(
            format!(
                "{} embedded rules / external scanners {} / threshold {}",
                app.rules.len(),
                if app.external { "enabled" } else { "off" },
                app.threshold
            ),
            Style::new().fg(MUTED),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("OVERVIEW"))
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0)),
        area,
    );
}
fn findings(frame: &mut Frame, area: Rect, app: &App) {
    let areas = if area.width >= 85 {
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)])
            .spacing(1)
            .split(area)
    } else {
        Layout::vertical([Constraint::Percentage(48), Constraint::Percentage(52)])
            .spacing(1)
            .split(area)
    };
    let indexes = app.filtered();
    let rows = indexes
        .iter()
        .filter_map(|i| app.report.as_ref()?.findings.get(*i))
        .map(|f| {
            Row::new(vec![
                Cell::from(f.severity.to_string()).style(Style::new().fg(severity(f.severity))),
                Cell::from(safe(&f.title)),
                Cell::from(format!(
                    "{}:{}",
                    f.file.strip_prefix(app.root()).unwrap_or(&f.file).display(),
                    f.line
                )),
            ])
            .height(2)
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Percentage(45),
            Constraint::Min(8),
        ],
    )
    .header(
        Row::new(["SEVERITY", "FINDING", "LOCATION"])
            .style(Style::new().fg(MUTED))
            .bottom_margin(1),
    )
    .row_highlight_style(Style::new().bg(Color::Rgb(43, 30, 20)).fg(TEXT))
    .highlight_symbol("> ")
    .block(panel(format!(
        "Findings {} / filter: {}",
        indexes.len(),
        safe(&app.filter)
    )));
    let mut state = TableState::default().with_selected(if indexes.is_empty() {
        None
    } else {
        Some(app.selected)
    });
    frame.render_stateful_widget(table, areas[0], &mut state);
    if let Some(f) = app.selected_finding() {
        paragraph(frame,areas[1],"Evidence / e explain",format!("{}\n{}  |  confidence {:.0}%\n{}:{}\n\nWHY\n{}\n\nEVIDENCE\n{}\n\nEXECUTION PATH\n{}\n\nFIX\n{}",safe(&f.title),f.severity,f.confidence*100.0,safe(&f.file.display().to_string()),f.line,safe(&f.description),safe(&f.evidence.join("\n")),safe(&f.execution_path.join("\n")),safe(&f.recommendation)),app.scroll);
    } else {
        paragraph(frame,areas[1],"Evidence","No finding selected.\n\nRun an audit, or clear your filter with Esc. A clean list only establishes what the reported coverage supports.",0);
    }
}
fn rules(frame: &mut Frame, area: Rect, app: &App) {
    let areas = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .spacing(1)
        .split(area);
    let items = app
        .rules
        .iter()
        .map(|r| ListItem::new(format!("{}  {}", r.severity, safe(&r.id))))
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.rule_selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(panel(format!("Embedded rules ({})", app.rules.len())))
            .highlight_style(Style::new().bg(Color::Rgb(43, 30, 20)).fg(ORANGE))
            .highlight_symbol("> "),
        areas[0],
        &mut state,
    );
    if let Some(rule) = app.rules.get(app.rule_selected) {
        paragraph(frame,areas[1],"Rule details",format!("{}\n\nSeverity: {}\nLanguages: {}\nMode: {}\n\n{}\n\nPATTERN\n{}\n\nRules run deterministically. Applicability alone is not a finding.",safe(&rule.id),rule.severity,rule.languages.join(", "),rule.mode.as_deref().unwrap_or("pattern"),safe(&rule.message),safe(&serde_json::to_string_pretty(rule).unwrap_or_default())),app.scroll);
    }
}
fn ai(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(4),
    ])
    .spacing(1)
    .split(area);
    paragraph(
        frame,
        rows[0],
        "CHAT / Alt+m provider / Alt+p project context",
        format!(
            "{} | Local: {} | NIM: {} | Context: {}",
            app.provider_name(),
            safe(&app.local_model),
            safe(&app.nim_model),
            if app.ai_finding.is_some() {
                "finding"
            } else if app.chat_context {
                "project"
            } else {
                "off"
            }
        ),
        0,
    );
    paragraph(
        frame,
        rows[1],
        if app.chat_preview.is_some() {
            "Payload preview / Esc return to conversation"
        } else {
            "Conversation / session only / Alt+r new chat"
        },
        app.chat_preview.as_ref().unwrap_or(&app.ai_text).clone(),
        if app.chat_follow && app.chat_preview.is_none() {
            Paragraph::new(app.ai_text.clone())
                .wrap(Wrap { trim: false })
                .line_count(rows[1].width.saturating_sub(2))
                .saturating_sub(rows[1].height.saturating_sub(2) as usize)
                .min(u16::MAX as usize) as u16
        } else {
            app.scroll
        },
    );
    paragraph(
        frame,
        rows[2],
        "Message / Enter send / Tab navigation",
        if app.chat_input.is_empty() {
            "Type a message…".into()
        } else {
            format!("> {}", safe(&app.chat_input))
        },
        0,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{backend::TestBackend, Terminal};
    #[test]
    fn workspace_draws_each_view_and_resizes_without_panics() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        for (width, height) in [(160, 50), (120, 38), (80, 24), (65, 18), (40, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            for view in [
                View::Overview,
                View::Findings,
                View::Rules,
                View::Ai,
                View::Intelligence,
            ] {
                app.view = view;
                terminal.draw(|f| draw(f, &app)).unwrap();
                let text = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect::<String>();
                assert!(text.contains("SENTINEL"));
            }
        }
        app.project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        app.view = View::Overview;
        let mut terminal = Terminal::new(TestBackend::new(120, 38)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        if let Ok(path) = std::env::var("SENTINEL_TUI_SNAPSHOT") {
            if std::env::var("SENTINEL_TUI_SNAPSHOT_VIEW").as_deref() == Ok("chat") {
                app.view = View::Ai;
                app.navigation_selected = 3;
                app.navigation_focus = false;
                terminal.draw(|f| draw(f, &app)).unwrap();
            }
            let buffer = terminal.backend().buffer();
            let cells=buffer.content.iter().map(|c|serde_json::json!({"symbol":c.symbol(),"fg":format!("{:?}",c.fg),"bg":format!("{:?}",c.bg),"bold":c.modifier.contains(Modifier::BOLD)})).collect::<Vec<_>>();
            std::fs::write(
                path,
                serde_json::to_vec(&serde_json::json!({"width":120,"height":38,"cells":cells}))
                    .unwrap(),
            )
            .unwrap();
        }
    }
    #[test]
    fn chat_typing_is_not_a_shortcut_and_context_is_optional() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        app.view = View::Ai;
        app.navigation_focus = false;
        assert!(!app.chat_context);
        for c in "amq?123".chars() {
            assert!(!app.key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
        }
        assert_eq!(app.chat_input, "amq?123");
        assert_eq!(app.provider_name(), "local");
        assert!(!app.help);
        app.paste("hello\x1b\n");
        assert_eq!(app.chat_input, "amq?123hello");
        app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::ALT));
        assert!(app.chat_context);
        app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::ALT));
        assert!(app.chat_input.is_empty());
        assert!(app.chat_history.is_empty());
    }
    #[test]
    fn navigation_requires_selection_and_returns_focus_on_escape() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(app.navigation_focus);
        app.key(key(KeyCode::Down));
        assert_eq!(app.view, View::Overview);
        assert_eq!(app.navigation_selected, 1);
        app.key(key(KeyCode::Enter));
        assert_eq!(app.view, View::Findings);
        assert!(!app.navigation_focus);
        app.key(key(KeyCode::Tab));
        assert!(app.navigation_focus);
        app.key(key(KeyCode::Char('/')));
        assert!(!app.navigation_focus);
        assert!(app.editor.is_some());
        app.key(key(KeyCode::Esc));
        app.key(key(KeyCode::Esc));
        assert!(app.navigation_focus);
        assert!(app.key(key(KeyCode::Char('Q'))));
    }
    #[test]
    fn keyboard_selection_provider_and_editor_sanitize_paste() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        assert!(!app.key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE)));
        assert_eq!(app.view, View::Ai);
        app.key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::ALT));
        assert_eq!(app.provider_name(), "nim");
        app.key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::ALT));
        app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.help_scroll, 8);
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.help);
        app.key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::ALT));
        app.editor.as_mut().unwrap().value.clear();
        app.paste("question\x1b\n");
        assert_eq!(app.editor.as_ref().unwrap().value, "question");
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.question, "question");
        assert!(app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::ALT)));
    }
}

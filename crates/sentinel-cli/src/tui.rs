mod app;
mod job;
mod line;
mod ui;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyEventKind},
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    time::Duration,
};
struct Screen;
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}
pub fn run(project: PathBuf) -> Result<i32> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return line::run();
    }
    let mut app = app::App::new(project)?;
    terminal::enable_raw_mode()?;
    let _screen = Screen;
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        drop(Screen);
        previous(info);
    }));
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    loop {
        app.tick();
        terminal.draw(|frame| ui::draw(frame, &app))?;
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if app.key(key) {
                        break;
                    }
                }
                Event::Paste(text) => app.paste(&text),
                _ => {}
            }
        }
    }
    drop(app);
    terminal.show_cursor()?;
    Ok(0)
}

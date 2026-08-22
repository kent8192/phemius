use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::project::{InitAnswers, initialize_project};
use crate::repl::{Repl, ReplOutcome};

#[derive(Parser, Debug)]
#[command(name = "phemius", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<TopLevelCommand>,
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub project: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum TopLevelCommand {
    Init {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
    },
    Eval {
        #[arg(value_name = "PROJECT", default_value = ".")]
        project: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplCommand {
    Help,
    Status,
    Mode {
        mode: Option<ReplMode>,
    },
    Plan {
        request: Option<String>,
    },
    Write {
        request: Option<String>,
    },
    Review {
        request: Option<String>,
    },
    Revise {
        id: Option<String>,
    },
    Diff {
        id: Option<String>,
    },
    Approve {
        id: String,
    },
    Reject {
        id: String,
    },
    Resolve {
        id: String,
        reason: String,
    },
    Model {
        role: Option<String>,
        id: Option<String>,
    },
    Cost,
    Compact,
    Resume,
    Skills,
    Skill {
        name: String,
    },
    Clean,
    Quit,
    NaturalLanguage(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplMode {
    Work,
    Consult,
}

pub fn parse_repl_command(input: &str) -> Result<ReplCommand> {
    if !input.starts_with('/') {
        if let Some(name) = input.strip_prefix('$') {
            return parse_skill(name);
        }
        return Ok(ReplCommand::NaturalLanguage(input.into()));
    }

    let mut words = input[1..].split_whitespace();
    let Some(command) = words.next() else {
        bail!("REPL command is required");
    };
    let rest = words.collect::<Vec<_>>();

    match command {
        "help" => no_arguments(rest, ReplCommand::Help),
        "status" => no_arguments(rest, ReplCommand::Status),
        "mode" => parse_mode(rest),
        "plan" => Ok(ReplCommand::Plan {
            request: join_optional(rest),
        }),
        "write" => Ok(ReplCommand::Write {
            request: join_optional(rest),
        }),
        "review" => Ok(ReplCommand::Review {
            request: join_optional(rest),
        }),
        "revise" => Ok(ReplCommand::Revise {
            id: one_optional(rest)?,
        }),
        "diff" => Ok(ReplCommand::Diff {
            id: one_optional(rest)?,
        }),
        "approve" => Ok(ReplCommand::Approve {
            id: one_required(rest, "changeset ID")?,
        }),
        "reject" => Ok(ReplCommand::Reject {
            id: one_required(rest, "changeset ID")?,
        }),
        "resolve" => parse_resolve(rest),
        "model" => parse_model(rest),
        "cost" => no_arguments(rest, ReplCommand::Cost),
        "compact" => no_arguments(rest, ReplCommand::Compact),
        "resume" => no_arguments(rest, ReplCommand::Resume),
        "skills" => no_arguments(rest, ReplCommand::Skills),
        "clean" => no_arguments(rest, ReplCommand::Clean),
        "quit" => no_arguments(rest, ReplCommand::Quit),
        _ => bail!("unknown REPL command: /{command}"),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    if matches!(cli.command, Some(TopLevelCommand::Init { .. })) {
        eprint!("Project title: ");
        io::stderr()
            .flush()
            .context("failed to prompt for project title")?;
    }
    let stdin = io::stdin();
    run_with_input(cli, &mut stdin.lock()).await
}

pub async fn run_with_input(cli: Cli, input: &mut impl BufRead) -> Result<()> {
    if let Some(TopLevelCommand::Init { path }) = &cli.command {
        let mut title = String::new();
        input
            .read_line(&mut title)
            .context("failed to read project title")?;
        initialize_project(path, &InitAnswers::minimal(title.trim()))?;
    } else if cli.command.is_none() {
        let mut repl = Repl::new();
        for line in input.lines() {
            let line = line.context("failed to read REPL input")?;
            match repl.handle_async(&line).await? {
                ReplOutcome::Quit => break,
                ReplOutcome::Continue => {}
                ReplOutcome::Message(message)
                | ReplOutcome::AgentText(message)
                | ReplOutcome::AwaitingConfirmation(message)
                | ReplOutcome::Error(message) => println!("{message}"),
            }
        }
    }
    Ok(())
}

fn parse_skill(name: &str) -> Result<ReplCommand> {
    if name.is_empty() || name.split_whitespace().count() != 1 {
        bail!("skill name is required");
    }
    Ok(ReplCommand::Skill { name: name.into() })
}

fn no_arguments(arguments: Vec<&str>, command: ReplCommand) -> Result<ReplCommand> {
    if arguments.is_empty() {
        Ok(command)
    } else {
        bail!("command does not accept arguments")
    }
}

fn one_optional(arguments: Vec<&str>) -> Result<Option<String>> {
    match arguments.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some((*value).into())),
        _ => bail!("command accepts at most one ID"),
    }
}

fn one_required(arguments: Vec<&str>, description: &str) -> Result<String> {
    one_optional(arguments)?.ok_or_else(|| anyhow::anyhow!("{description} is required"))
}

fn join_optional(arguments: Vec<&str>) -> Option<String> {
    (!arguments.is_empty()).then(|| arguments.join(" "))
}

fn parse_mode(arguments: Vec<&str>) -> Result<ReplCommand> {
    let mode = match one_optional(arguments)?.as_deref() {
        None => None,
        Some("work") => Some(ReplMode::Work),
        Some("consult") => Some(ReplMode::Consult),
        Some(_) => bail!("mode must be work or consult"),
    };
    Ok(ReplCommand::Mode { mode })
}

fn parse_resolve(arguments: Vec<&str>) -> Result<ReplCommand> {
    let [id, disposition, reason @ ..] = arguments.as_slice() else {
        bail!("finding ID, false-positive disposition, and reason are required");
    };
    if *disposition != "false-positive" || reason.is_empty() {
        bail!("resolve requires: /resolve <finding-id> false-positive <reason>");
    }
    Ok(ReplCommand::Resolve {
        id: (*id).into(),
        reason: reason.join(" "),
    })
}

fn parse_model(arguments: Vec<&str>) -> Result<ReplCommand> {
    let (role, id) = match arguments.as_slice() {
        [] => (None, None),
        [id] => (None, Some((*id).into())),
        [role, id] => (Some((*role).into()), Some((*id).into())),
        _ => bail!("model accepts an optional role and model ID"),
    };
    Ok(ReplCommand::Model { role, id })
}

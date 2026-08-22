//! Human-facing REPL and trusted command routing.
//!
//! Slash commands are parsed before any model is consulted.  Natural-language text is always
//! returned as agent text and can never approve, resolve, clean, persist a model choice, or
//! enter unrestricted execution.

use std::collections::VecDeque;

use anyhow::{Result, bail};

use crate::{
    cli::{ReplCommand, ReplMode, parse_repl_command},
    workflow::{AgentRole, CostConfirmationRequired, RunController},
};

/// Input after the authority boundary has classified it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutedInput {
    /// A parsed trusted slash or explicit `$skill` command.
    Command(ReplCommand),
    /// Text that may be sent to the coordinator as a request, never as authority.
    AgentText(String),
}

/// Routes one line without allowing natural language to impersonate a command.
pub fn route_input(input: &str) -> Result<RoutedInput> {
    if input.starts_with('/') || input.starts_with('$') {
        Ok(RoutedInput::Command(parse_repl_command(input)?))
    } else {
        Ok(RoutedInput::AgentText(input.into()))
    }
}

/// Result of handling one REPL line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplOutcome {
    /// Continue accepting input without a user-visible message.
    Continue,
    /// Return a status or confirmation message.
    Message(String),
    /// A coordinator request was accepted without granting trusted authority.
    Coordinator(String),
    /// A consult-mode command was classified as read-only.
    ReadOnly(String),
    /// Natural language was passed to the coordinator as ordinary text.
    AgentText(String),
    /// A destructive or security-sensitive action needs explicit confirmation.
    AwaitingConfirmation(String),
    /// The user requested termination.
    Quit,
    /// A trusted action failed.
    Error(String),
}

/// Minimal in-memory REPL state.
pub struct Repl {
    mode: ReplMode,
    controller: Option<RunController>,
    history: VecDeque<String>,
    ambiguous_request: bool,
}

impl Default for Repl {
    fn default() -> Self {
        Self::new()
    }
}

impl Repl {
    /// Starts in work mode with no persistent history and no implicit model backend.
    pub fn new() -> Self {
        Self {
            mode: ReplMode::Work,
            controller: None,
            history: VecDeque::new(),
            ambiguous_request: false,
        }
    }

    /// Attaches a controller to this trusted UI.
    pub fn with_controller(controller: RunController) -> Self {
        let mut repl = Self::new();
        repl.controller = Some(controller);
        repl
    }

    /// Returns the active mode.
    pub const fn mode(&self) -> ReplMode {
        self.mode
    }

    /// Returns the number of lines retained in memory only.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Returns whether the trusted REPL is attached to a project controller.
    pub fn has_controller(&self) -> bool {
        self.controller.is_some()
    }

    /// Returns whether the last model request stopped ambiguously.
    pub const fn has_ambiguous_request(&self) -> bool {
        self.ambiguous_request
    }

    /// Handles a synchronous command or routes natural language to the coordinator.
    pub fn handle(&mut self, input: &str) -> Result<ReplOutcome> {
        self.history.push_back(input.into());
        while self.history.len() > 64 {
            self.history.pop_front();
        }
        let routed = route_input(input)?;
        match routed {
            RoutedInput::AgentText(text) => {
                if self.mode == ReplMode::Work
                    && let Some(controller) = self.controller.as_mut()
                {
                    return Ok(match controller.record_coordinator_request(text.clone()) {
                        Ok(message) => ReplOutcome::Coordinator(message),
                        Err(error) => ReplOutcome::Error(error.to_string()),
                    });
                }
                Ok(ReplOutcome::AgentText(text))
            }
            RoutedInput::Command(command) => self.handle_command(command),
        }
    }

    /// Handles a potentially asynchronous write/review request.
    pub async fn handle_async(&mut self, input: &str) -> Result<ReplOutcome> {
        let routed = route_input(input)?;
        match routed {
            RoutedInput::Command(ReplCommand::Write { request }) => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::Error("consult mode is read-only".into()));
                }
                let (chapter, confirmed) = parse_write_request(request)?;
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::Error(
                        "no writing controller is attached".into(),
                    ));
                };
                if confirmed {
                    controller.confirm_cost_warning();
                }
                match controller.write_chapter(&chapter).await {
                    Ok(run) => Ok(ReplOutcome::Message(format!(
                        "candidate {} is {:?}; use /approve {} after review",
                        chapter,
                        run.state,
                        run.changeset.id.as_str()
                    ))),
                    Err(error) if error.downcast_ref::<CostConfirmationRequired>().is_some() => {
                        Ok(ReplOutcome::AwaitingConfirmation(format!(
                            "{}; repeat /write {chapter} --confirm to continue",
                            error
                        )))
                    }
                    Err(error) => {
                        self.ambiguous_request = error.to_string().contains("ambiguous");
                        Ok(ReplOutcome::Error(error.to_string()))
                    }
                }
            }
            RoutedInput::AgentText(text) if self.mode == ReplMode::Work => {
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::AgentText(text));
                };
                match controller
                    .run_coordinator_request(AgentRole::StoryArchitect, text)
                    .await
                {
                    Ok(response) => Ok(ReplOutcome::Coordinator(response)),
                    Err(error) => {
                        self.ambiguous_request = error.to_string().contains("ambiguous");
                        Ok(ReplOutcome::Error(error.to_string()))
                    }
                }
            }
            RoutedInput::Command(
                command @ (ReplCommand::Plan { .. }
                | ReplCommand::Review { .. }
                | ReplCommand::Revise { .. }
                | ReplCommand::Diff { .. }),
            ) => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::ReadOnly(
                        "consult mode: coordinator request is read-only".into(),
                    ));
                }
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::ReadOnly(
                        "no writing controller is attached; request was not executed".into(),
                    ));
                };
                let role = match command {
                    ReplCommand::Plan { .. } => AgentRole::StoryArchitect,
                    ReplCommand::Review { .. } => AgentRole::CanonCritic,
                    ReplCommand::Revise { .. } => AgentRole::Reviser,
                    ReplCommand::Diff { .. } => AgentRole::Validator,
                    _ => unreachable!(),
                };
                let request = coordinator_request(command);
                match controller.run_coordinator_request(role, request).await {
                    Ok(response) => Ok(ReplOutcome::Coordinator(response)),
                    Err(error) => {
                        self.ambiguous_request = error.to_string().contains("ambiguous");
                        Ok(ReplOutcome::Error(error.to_string()))
                    }
                }
            }
            _ => self.handle(input),
        }
    }

    fn handle_command(&mut self, command: ReplCommand) -> Result<ReplOutcome> {
        match command {
            ReplCommand::Help => Ok(ReplOutcome::Message(
                "work commands: /plan /write /review /revise /diff /approve /reject /resolve /model /cost /compact /resume /clean /quit".into(),
            )),
            ReplCommand::Status => Ok(ReplOutcome::Message(self.status_message())),
            ReplCommand::Mode { mode } => {
                if let Some(mode) = mode {
                    self.mode = mode;
                }
                Ok(ReplOutcome::Message(format!("mode: {}", self.mode.name())))
            }
            command @ (ReplCommand::Plan { .. }
            | ReplCommand::Review { .. }
            | ReplCommand::Revise { .. }
            | ReplCommand::Diff { .. }
            | ReplCommand::Skills
            | ReplCommand::Skill { .. }
            | ReplCommand::Compact) => {
                if self.mode == ReplMode::Consult {
                    Ok(ReplOutcome::ReadOnly(
                        "consult mode: coordinator request is read-only".into(),
                    ))
                } else if self.controller.is_none() {
                    Ok(ReplOutcome::ReadOnly(
                        "no writing controller is attached; request was not executed".into(),
                    ))
                } else {
                    let request = coordinator_request(command);
                    let controller = self
                        .controller
                        .as_mut()
                        .expect("controller was checked above");
                    match controller.record_coordinator_request(request) {
                        Ok(message) => Ok(ReplOutcome::Coordinator(message)),
                        Err(error) => Ok(ReplOutcome::Error(error.to_string())),
                    }
                }
            }
            ReplCommand::Write { .. } => {
                if self.mode == ReplMode::Consult {
                    Ok(ReplOutcome::Error("consult mode is read-only".into()))
                } else if self.controller.is_none() {
                    Ok(ReplOutcome::Error(
                        "no writing controller is attached".into(),
                    ))
                } else {
                    Ok(ReplOutcome::Coordinator(
                        "use the asynchronous REPL runner for /write".into(),
                    ))
                }
            }
            ReplCommand::Approve { id } => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::Error("consult mode is read-only".into()));
                }
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::Error("no writing controller is attached".into()));
                };
                match controller.approve_changeset_trusted(&id) {
                    Ok(()) => Ok(ReplOutcome::Message(format!("approved {id}"))),
                    Err(error) => Ok(ReplOutcome::Error(error.to_string())),
                }
            }
            ReplCommand::Reject { id } => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::Error("consult mode is read-only".into()));
                }
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::Error("no writing controller is attached".into()));
                };
                match controller.reject_changeset_trusted(&id) {
                    Ok(()) => Ok(ReplOutcome::Message(format!("rejected {id}"))),
                    Err(error) => Ok(ReplOutcome::Error(error.to_string())),
                }
            }
            ReplCommand::Resolve { id, reason } => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::Error("consult mode is read-only".into()));
                }
                let Some(controller) = self.controller.as_mut() else {
                    return Ok(ReplOutcome::Error("no writing controller is attached".into()));
                };
                match controller.resolve_false_positive(&id, reason) {
                    Ok(()) => Ok(ReplOutcome::Message(format!("resolved {id} as false-positive"))),
                    Err(error) => Ok(ReplOutcome::Error(error.to_string())),
                }
            }
            ReplCommand::Model { role, id } => {
                if self.mode == ReplMode::Consult {
                    return Ok(ReplOutcome::Error("consult mode is read-only".into()));
                }
                self.handle_model(role, id)
            }
            ReplCommand::Cost => Ok(ReplOutcome::Message(self.cost_message())),
            ReplCommand::Resume => {
                if self.ambiguous_request {
                    let outcome = ReplOutcome::Message(
                        "the previous request is ambiguous; choose retry, switch model, or stop".into(),
                    );
                    if self.mode == ReplMode::Consult {
                        Ok(ReplOutcome::ReadOnly(
                            "consult mode: choose retry, switch model, or stop; no request was resent".into(),
                        ))
                    } else {
                        Ok(outcome)
                    }
                } else {
                    let Some(controller) = self.controller.as_mut() else {
                        return Ok(ReplOutcome::Message(
                            "no ambiguous request or durable project checkpoint is pending".into(),
                        ));
                    };
                    if self.mode == ReplMode::Consult {
                        return Ok(ReplOutcome::ReadOnly(
                            "consult mode: latest checkpoint is available only as read-only status".into(),
                        ));
                    }
                    match controller.resume_checkpoint() {
                        Ok(Some(checkpoint)) => Ok(ReplOutcome::Message(format!(
                            "latest checkpoint loaded at event offset {} (cost {} microdollars); state reconstruction is required before generation, manual resolution is required",
                            checkpoint.last_event_offset,
                            checkpoint.cost.as_u64()
                        ))),
                        Ok(None) => Ok(ReplOutcome::Message(
                            "no durable project checkpoint is pending".into(),
                        )),
                        Err(error) => Ok(ReplOutcome::Error(error.to_string())),
                    }
                }
            }
            ReplCommand::Clean => {
                if self.mode == ReplMode::Consult {
                    Ok(ReplOutcome::Error("consult mode is read-only".into()))
                } else {
                    Ok(ReplOutcome::AwaitingConfirmation(
                        "clean requires an explicit human confirmation".into(),
                    ))
                }
            }
            ReplCommand::Quit => Ok(ReplOutcome::Quit),
            ReplCommand::NaturalLanguage(text) => Ok(ReplOutcome::AgentText(text)),
        }
    }

    fn handle_model(&mut self, role: Option<String>, id: Option<String>) -> Result<ReplOutcome> {
        let Some(id) = id else {
            if self.mode == ReplMode::Consult {
                return Ok(ReplOutcome::Error("consult mode is read-only".into()));
            }
            if self.controller.is_none() {
                return Ok(ReplOutcome::Error(
                    "no writing controller is attached".into(),
                ));
            }
            return Ok(ReplOutcome::Message("model selection is manual".into()));
        };
        let Some(controller) = self.controller.as_mut() else {
            return Ok(ReplOutcome::Error(
                "no writing controller is attached".into(),
            ));
        };
        let role = role.as_deref().map(parse_role).transpose()?;
        controller.set_model(role, id.clone())?;
        Ok(ReplOutcome::Message(format!("model set to {id}")))
    }

    fn status_message(&self) -> String {
        format!(
            "mode: {}; history: {}",
            self.mode.name(),
            self.history.len()
        )
    }

    fn cost_message(&self) -> String {
        let Some(controller) = self.controller.as_ref() else {
            return "cost: no controller".into();
        };
        let status = controller.cost_status();
        format!(
            "cost chapter={} microdollars, run={} microdollars, warning={}",
            status.chapter.as_u64(),
            status.run.as_u64(),
            status.warning
        )
    }
}

fn coordinator_request(command: ReplCommand) -> String {
    match command {
        ReplCommand::Plan { request } => format!("plan {}", request.unwrap_or_default()),
        ReplCommand::Review { request } => format!("review {}", request.unwrap_or_default()),
        ReplCommand::Revise { id } => format!("revise {}", id.unwrap_or_default()),
        ReplCommand::Diff { id } => format!("diff {}", id.unwrap_or_default()),
        ReplCommand::Skills => "skills".into(),
        ReplCommand::Skill { name } => format!("skill {name}"),
        ReplCommand::Compact => "compact".into(),
        _ => unreachable!("coordinator_request called for a non-coordinator command"),
    }
}

fn parse_write_request(request: Option<String>) -> Result<(String, bool)> {
    let mut chapter = None;
    let mut confirmed = false;
    for word in request.as_deref().unwrap_or("chapter_1").split_whitespace() {
        if word == "--confirm" {
            ensure_not_confirmed(&mut confirmed)?;
        } else if chapter.replace(word).is_some() {
            bail!("/write accepts one chapter ID and optional --confirm");
        }
    }
    Ok((chapter.unwrap_or("chapter_1").into(), confirmed))
}

fn ensure_not_confirmed(confirmed: &mut bool) -> Result<()> {
    if *confirmed {
        bail!("/write accepts --confirm only once");
    }
    *confirmed = true;
    Ok(())
}

fn parse_role(role: &str) -> Result<AgentRole> {
    match role {
        "architect" | "story-architect" => Ok(AgentRole::StoryArchitect),
        "writer" => Ok(AgentRole::Writer),
        "reviser" => Ok(AgentRole::Reviser),
        "validator" => Ok(AgentRole::Validator),
        "character" | "character-voice" => Ok(AgentRole::CharacterVoiceCritic),
        "canon" | "canon-critic" => Ok(AgentRole::CanonCritic),
        "reader-pull" => Ok(AgentRole::ReaderPullCritic),
        "story-editor" => Ok(AgentRole::StoryEditorCritic),
        "style" | "naturalness-style" => Ok(AgentRole::NaturalnessStyleCritic),
        "source" | "source-adherence" => Ok(AgentRole::SourceAdherenceCritic),
        _ => bail!("unknown workflow role {role}"),
    }
}

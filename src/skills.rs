//! Metadata-first discovery for project and user skills.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

/// Startup-visible skill metadata. Skill bodies are not loaded during discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillMetadata {
    /// Stable skill selection name.
    pub name: String,
    /// Human-readable short description.
    pub description: String,
}

/// A selected full skill document and its content hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedSkill {
    /// Metadata selected at startup.
    pub metadata: SkillMetadata,
    /// Complete `SKILL.md` bytes decoded as UTF-8.
    pub body: String,
    /// SHA-256 of `body` bytes.
    pub sha256: String,
}

/// A hashed resource explicitly referenced by a loaded skill.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillResource {
    /// Resource path relative to the selected skill directory.
    pub path: PathBuf,
    /// Decoded resource body.
    pub body: String,
    /// SHA-256 of the resource bytes for the execution receipt.
    pub sha256: String,
}

/// A metadata-only catalog. Earlier discovery roots take precedence.
#[derive(Clone, Debug, Default)]
pub struct SkillCatalog {
    skills: BTreeMap<String, SkillEntry>,
}

#[derive(Clone, Debug)]
struct SkillEntry {
    metadata: SkillMetadata,
    path: PathBuf,
}

impl SkillCatalog {
    /// Discovers direct `SKILL.md` files and `<name>/SKILL.md` children in precedence order.
    pub fn discover<I, P>(roots: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut catalog = Self::default();
        for root in roots {
            let root = root.as_ref();
            if !root.exists() {
                continue;
            }
            let root = root
                .canonicalize()
                .with_context(|| format!("failed to resolve skill root {}", root.display()))?;
            for skill_path in skill_paths(&root)? {
                let metadata = read_metadata(&skill_path)?;
                catalog
                    .skills
                    .entry(metadata.name.clone())
                    .or_insert(SkillEntry {
                        metadata,
                        path: skill_path,
                    });
            }
        }
        Ok(catalog)
    }

    /// Looks up startup-visible metadata without reading the skill body.
    pub fn get(&self, name: &str) -> Option<&SkillMetadata> {
        self.skills.get(name).map(|entry| &entry.metadata)
    }

    /// Loads one explicitly selected skill body and its receipt hash.
    pub fn load(&self, name: &str) -> Result<LoadedSkill> {
        let entry = self
            .skills
            .get(name)
            .with_context(|| format!("unknown skill {name}"))?;
        let bytes = read_regular(&entry.path)?;
        let body = String::from_utf8(bytes.clone()).context("SKILL.md must be valid UTF-8")?;
        Ok(LoadedSkill {
            metadata: entry.metadata.clone(),
            body,
            sha256: crate::changeset::sha256_bytes(&bytes),
        })
    }

    /// Loads one explicit, relative resource below the selected skill directory.
    pub fn load_resource(&self, name: &str, relative: &Path) -> Result<SkillResource> {
        validate_relative(relative)?;
        let entry = self
            .skills
            .get(name)
            .with_context(|| format!("unknown skill {name}"))?;
        let directory = entry
            .path
            .parent()
            .context("SKILL.md has no parent directory")?;
        let path = secure_resource_path(directory, relative)?;
        let bytes = read_regular(&path)?;
        let body =
            String::from_utf8(bytes.clone()).context("skill resource must be valid UTF-8")?;
        Ok(SkillResource {
            path: relative.to_path_buf(),
            body,
            sha256: crate::changeset::sha256_bytes(&bytes),
        })
    }
}

/// Loads project hierarchy instructions, preferring `AGENTS.md` at each level over `CLAUDE.md`.
pub fn load_hierarchical_instructions(
    project_root: &Path,
    target: &Path,
) -> Result<Vec<SkillResource>> {
    let root = project_root
        .canonicalize()
        .context("failed to resolve project root")?;
    let target = target
        .canonicalize()
        .context("failed to resolve instruction target")?;
    ensure!(
        target.starts_with(&root),
        "instruction target escapes project root"
    );
    let relative = target.strip_prefix(&root).expect("checked prefix");
    let mut current = root;
    let mut result = Vec::new();
    load_instruction_at(&current, &mut result)?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("instruction target has unsafe component");
        };
        current.push(component);
        load_instruction_at(&current, &mut result)?;
    }
    Ok(result)
}

fn load_instruction_at(directory: &Path, result: &mut Vec<SkillResource>) -> Result<()> {
    let agents = directory.join("AGENTS.md");
    let candidate = if agents.exists() {
        agents
    } else {
        directory.join("CLAUDE.md")
    };
    if !candidate.exists() {
        return Ok(());
    }
    let bytes = read_regular(&candidate)?;
    let body = String::from_utf8(bytes.clone()).context("instruction file must be valid UTF-8")?;
    result.push(SkillResource {
        path: candidate,
        body,
        sha256: crate::changeset::sha256_bytes(&bytes),
    });
    Ok(())
}

fn skill_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let direct = root.join("SKILL.md");
    if direct.exists() {
        paths.push(secure_resource_path(root, Path::new("SKILL.md"))?);
    }
    for entry in std::fs::read_dir(root)
        .with_context(|| format!("failed to list skill root {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let path = entry.path().join("SKILL.md");
        if path.exists() {
            let child = entry.file_name();
            paths.push(secure_resource_path(
                root,
                Path::new(&child).join("SKILL.md").as_path(),
            )?);
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_metadata(path: &Path) -> Result<SkillMetadata> {
    let file = File::open(path)
        .with_context(|| format!("failed to open skill metadata {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    ensure!(
        reader.read_line(&mut line)? > 0 && line.trim_end() == "---",
        "SKILL.md metadata must begin with ---"
    );
    let mut name = None;
    let mut description = None;
    loop {
        line.clear();
        ensure!(
            reader.read_line(&mut line)? > 0,
            "SKILL.md metadata is not terminated"
        );
        if line.trim_end() == "---" {
            break;
        }
        let Some((key, value)) = line.trim_end().split_once(':') else {
            bail!("invalid SKILL.md metadata line");
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "name" => name = Some(value),
            "description" => description = Some(value),
            _ => {}
        }
    }
    let name = name.context("SKILL.md metadata requires name")?;
    ensure!(!name.is_empty(), "skill name must not be empty");
    Ok(SkillMetadata {
        name,
        description: description.context("SKILL.md metadata requires description")?,
    })
}

fn secure_resource_path(root: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative(relative)?;
    let path = root.join(relative);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect skill resource {}", relative.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "skill resource must be a regular file"
    );
    let resolved = path.canonicalize()?;
    ensure!(
        resolved.starts_with(root),
        "skill resource escapes its skill root"
    );
    Ok(resolved)
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "skill resource must be a regular file"
    );
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn validate_relative(path: &Path) -> Result<()> {
    ensure!(
        !path.is_absolute() && !path.as_os_str().is_empty(),
        "skill resource path must be relative"
    );
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("skill resource path escapes the skill directory");
        }
    }
    Ok(())
}

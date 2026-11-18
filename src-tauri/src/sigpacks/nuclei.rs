//! Loading the templates of a Nuclei pack. The pack store uses it to count
//! what an import holds; the Template scan uses it to get the templates it
//! runs. Both must agree, so there is one loader.

use oxaudit_nuclei::{LoadLimits, Template, TemplateError};

use super::PackFile;

/// A template and the pack file it came from.
#[derive(Debug, Clone)]
pub struct LoadedTemplate {
    /// Forward-slash path inside the pack.
    pub file: String,
    pub template: Template,
}

/// A pack's YAML files, loaded.
#[derive(Debug, Default)]
pub struct PackTemplates {
    /// One per distinct template id, in file path order.
    pub templates: Vec<LoadedTemplate>,
    /// Files that are YAML but could not be loaded as a template: `(file, message)`.
    pub errors: Vec<(String, String)>,
    /// YAML files with no top-level `id` (workflows, configs, CI files):
    /// clearly not templates, counted and not reported as errors.
    pub ignored: usize,
    /// `(file, id, first file with that id)`: later copies are dropped.
    pub duplicates: Vec<(String, String, String)>,
}

pub fn load_templates(files: &[PackFile]) -> PackTemplates {
    let mut ordered: Vec<&PackFile> = files.iter().collect();
    ordered.sort_by(|a, b| a.path.cmp(&b.path));
    let mut out = PackTemplates::default();
    let mut first_by_id: std::collections::HashMap<String, String> = Default::default();
    for file in ordered {
        match Template::load(&file.text, &file.path, LoadLimits::default()) {
            Ok(template) => {
                if let Some(first) = first_by_id.get(&template.id) {
                    out.duplicates
                        .push((file.path.clone(), template.id.clone(), first.clone()));
                    continue;
                }
                first_by_id.insert(template.id.clone(), file.path.clone());
                out.templates.push(LoadedTemplate {
                    file: file.path.clone(),
                    template,
                });
            }
            Err(TemplateError::MissingId | TemplateError::NotAMapping) => out.ignored += 1,
            Err(error) => out.errors.push((file.path.clone(), error.to_string())),
        }
    }
    out
}

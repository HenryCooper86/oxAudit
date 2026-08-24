use once_cell::sync::Lazy;
use regex::Regex;

/// A compiled source-code vulnerability pattern rule.
pub struct SourceRule {
    pub id: &'static str,
    pub name: &'static str,
    /// languages this rule applies to (lowercase language names)
    pub languages: &'static [&'static str],
    pub severity: &'static str,
    pub cwe: &'static str,
    pub regex: Regex,
    pub message: &'static str,
    pub recommendation: &'static str,
}

macro_rules! srule {
    ($id:literal, $name:literal, $langs:expr, $sev:literal, $cwe:literal, $re:literal, $msg:literal, $rec:literal) => {
        SourceRule {
            id: $id,
            name: $name,
            languages: $langs,
            severity: $sev,
            cwe: $cwe,
            regex: Regex::new($re).expect(concat!("invalid regex for ", $id)),
            message: $msg,
            recommendation: $rec,
        }
    };
}

/// Generic rule — applies to every language.
const ANY: &[&str] = &[];

pub static SOURCE_RULES: Lazy<Vec<SourceRule>> = Lazy::new(|| {
    vec![
        // ---------------------------------------------------------- JavaScript
        srule!("js-eval", "eval() usage", &["javascript"], "high", "CWE-95", r"(?:^|[^.\w$])(eval\s*\()", "The eval() function executes arbitrary strings as code. If any part of the argument is attacker-controlled this is arbitrary code execution (RCE).", "Avoid eval() entirely. Use JSON.parse for data, or Function constructors only with trusted, static code."),
        srule!("js-function-ctor", "Function() constructor", &["javascript"], "high", "CWE-95", r"\bnew\s+Function\s*\(", "The Function constructor compiles a string as code at runtime, equivalent to eval() and a common RCE sink.", "Remove the dynamic Function() call; refactor to static functions and lookups (e.g. a switch/map of handlers)."),
        srule!("js-inner-html", "innerHTML assignment", &["javascript"], "medium", "CWE-79", r"\.(?:innerHTML|outerHTML)\s*=", "Assigning to innerHTML/outerHTML with unsanitized input leads to DOM-based XSS.", "Build DOM nodes with createElement/textContent or use a framework's escaping (React JSX). Never interpolate user input into innerHTML."),
        srule!("js-dangerously-set-inner-html", "dangerouslySetInnerHTML", &["javascript"], "medium", "CWE-79", r"dangerouslySetInnerHTML", "React's dangerouslySetInnerHTML bypasses React's XSS protections; the value is inserted as raw HTML.", "Avoid it. If unavoidable, sanitize the HTML with DOMPurify before assigning."),
        srule!("js-document-write", "document.write()", &["javascript"], "medium", "CWE-79", r"document\.write\s*\(", "document.write() with dynamic content is an XSS sink and also breaks page rendering.", "Remove document.write() and render content via DOM APIs or the framework."),
        srule!("js-child-process", "child_process usage", &["javascript"], "high", "CWE-78", r#"(?:child_process|require\s*\(\s*['"]child_process['"]\s*\))[\s\S]{0,240}?\b(?:exec|execSync|spawn|spawnSync|fork)\s*\("#, "The child_process module executes system commands. If arguments include user input, this is OS command injection.", "Prefer execFile/spawn with an argument array (no shell) and validate/whitelist all inputs. Never pass a user-controlled command string to a shell."),
        srule!("js-exec-concat", "exec() with string concat", &["javascript"], "high", "CWE-78", r"\b(?:exec|execSync)\s*\(\s*[^)]*(?:\+|\$\{|`)", "exec()/execSync() run commands through a shell; string concatenation or template literals in the command are classic command-injection sinks.", "Use execFile/spawn with explicit argument arrays and no shell interpretation."),
        srule!("js-sql-concat", "SQL query built by concatenation", &["javascript"], "high", "CWE-89", r"\b(?:query|execute|exec|run)\s*\(\s*[^)]*\+\s*", "SQL strings assembled with + concatenation are a SQL-injection sink.", "Use parameterized queries / prepared statements. Never interpolate values into SQL strings."),
        srule!("js-weak-hash", "Weak hash (MD5/SHA-1)", &["javascript"], "medium", "CWE-327", r#"createHash\s*\(\s*['"](?:md5|sha1)['"]"#, "MD5 and SHA-1 are cryptographically broken and must not be used for security purposes (passwords, signatures, integrity).", "Use SHA-256/SHA-512 or a dedicated password hasher (bcrypt/argon2/scrypt)."),
        srule!("js-postmessage-wildcard", "postMessage wildcard origin", &["javascript"], "low", "CWE-345", r#"postMessage\s*\([^)]*,\s*['"]\*['"]"#, "postMessage() with targetOrigin '*' lets any window receive the message, potentially leaking sensitive data.", "Pass the specific expected origin instead of '*'."),

        // ------------------------------------------------------------ Python
        srule!("py-eval", "eval() usage", &["python"], "high", "CWE-95", r"(?:^|[^.\w])(eval\s*\()", "eval() executes arbitrary Python expressions; attacker-controlled input becomes code execution.", "Avoid eval()/exec(); use ast.literal_eval for trusted literals or a proper parser for the data format."),
        srule!("py-exec", "exec() usage", &["python"], "high", "CWE-95", r"(?:^|[^.\w])(exec\s*\()", "exec() executes arbitrary Python code strings; any dynamic input is a code-execution primitive.", "Replace with static code; if dynamic evaluation is truly required, sandbox it (e.g. RestrictedPython) and document the risk."),
        srule!("py-pickle", "pickle.load(s) — unsafe deserialization", &["python"], "high", "CWE-502", r"(?:pickle|cPickle)\s*\.\s*loads?\s*\(", "pickle deserialization can execute arbitrary code embedded in the payload (pickle is not a safe format).", "Never unpickle untrusted data. Use JSON/msgpack for untrusted input, or verify authenticity with a signature first."),
        srule!("py-yaml-load", "yaml.load() — unsafe deserialization", &["python"], "high", "CWE-502", r"yaml\s*\.\s*load\s*\(", "yaml.load() without an explicit safe Loader can construct arbitrary Python objects and execute code.", "Use yaml.safe_load() (or CSafeLoader) — never yaml.load() on untrusted YAML."),
        srule!("py-subprocess-shell", "subprocess with shell=True", &["python"], "high", "CWE-78", r"(?:subprocess\s*\.\s*)?(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True", "shell=True routes commands through /bin/sh, enabling shell metacharacter injection when arguments contain user input.", "Use shell=False with an argument list; build commands as argv arrays, never strings."),
        srule!("py-os-system", "os.system()", &["python"], "high", "CWE-78", r"os\s*\.\s*system\s*\(", "os.system() runs a string through the shell — a command-injection sink.", "Replace with subprocess.run([...], shell=False) and validate inputs."),
        srule!("py-sql-fstring", "SQL with f-string", &["python"], "high", "CWE-89", r#"(?:execute|executemany|executescript)\s*\(\s*f['"]"#, "F-string SQL queries embed values directly into the statement — SQL injection.", "Use parameterized queries (? placeholders / %s with driver params)."),
        srule!("py-sql-concat", "SQL with string concatenation", &["python"], "high", "CWE-89", r"(?:execute|executemany)\s*\(\s*[^)]*\+", "SQL statements assembled with + concatenation are a SQL-injection sink.", "Use parameterized queries with bound parameters."),
        srule!("py-verify-false", "TLS verification disabled", &["python"], "medium", "CWE-295", r"(?:requests|httpx)\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False", "Disabling TLS certificate verification (verify=False) exposes traffic to man-in-the-middle attacks.", "Keep verification enabled; if a self-signed cert must be used, pin the CA bundle explicitly."),
        srule!("py-weak-hash", "Weak hash (MD5/SHA-1)", &["python"], "medium", "CWE-327", r"(?:hashlib\s*\.\s*(?:md5|sha1)|(?:md5|sha1)\s*\()", "MD5 and SHA-1 are cryptographically broken for security purposes.", "Use hashlib.sha256/sha512, or a password hasher like argon2/bcrypt for credentials."),

        // --------------------------------------------------------------- Java
        srule!("java-runtime-exec", "Runtime.exec()", &["java"], "high", "CWE-78", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "Runtime.exec() runs a system command; with user input it becomes command injection.", "Avoid external commands; if required use ProcessBuilder with an argument list and validate inputs."),
        srule!("java-process-builder", "ProcessBuilder usage", &["java"], "medium", "CWE-78", r"(?:new\s+)?ProcessBuilder\s*\(", "ProcessBuilder launches external processes. It is safe with static arguments but becomes dangerous when arguments include untrusted input.", "Pass arguments as a List (never concatenate into a shell string) and validate/whitelist inputs."),
        srule!("java-sql-concat", "SQL built with concatenation", &["java"], "high", "CWE-89", r"(?:Statement|PreparedStatement)[^;]{0,80}\s*\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*[^)]*(?:\+|String\.format)", "SQL statements built with + or String.format are SQL-injection sinks.", "Always use PreparedStatement with ? placeholders and bind parameters."),
        srule!("java-deserialization", "Unsafe deserialization", &["java"], "high", "CWE-502", r"(?:ObjectInputStream|XMLDecoder|ObjectInput)[^;]{0,80}\s*readObject\s*\(", "readObject()/XMLDecoder deserialization of untrusted data can lead to RCE via gadget chains.", "Do not deserialize untrusted data; use safe formats (JSON) with strict schemas, or an allow-listed deserialization filter."),
        srule!("java-cipher-ecb", "Cipher in ECB mode", &["java"], "medium", "CWE-327", r#"Cipher\s*\.\s*getInstance\s*\(\s*['"][^'"]*\/ECB\/"#, "ECB mode leaks patterns in ciphertext and is not semantically secure.", "Use AES-GCM (or CBC with HMAC) and a random IV."),
        srule!("java-weak-hash", "Weak hash (MD5/SHA-1)", &["java"], "medium", "CWE-327", r#"MessageDigest\s*\.\s*getInstance\s*\(\s*['"](?:MD5|SHA-1)['"]"#, "MD5 and SHA-1 are cryptographically broken.", "Use SHA-256+ or a password hasher (BCrypt/Argon2)."),

        // ----------------------------------------------------------------- Go
        srule!("go-exec-shell", "exec.Command with a shell", &["go"], "high", "CWE-78", r#"exec\.Command\s*\(\s*['"](?:sh|bash)['"]"#, "exec.Command launching sh/bash to build commands from strings is a command-injection sink.", "Invoke the target binary directly with an argument slice; avoid shell interpreters."),
        srule!("go-sql-concat", "SQL built with concatenation", &["go"], "high", "CWE-89", r"(?:db|sql|tx|stmt)\s*\.\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\s*\([^)]*(?:\+|fmt\.Sprintf)", "SQL statements assembled with + or fmt.Sprintf are SQL-injection sinks.", "Use database/sql prepared statements with ? placeholders."),
        srule!("go-weak-hash", "Weak hash (MD5/SHA-1)", &["go"], "medium", "CWE-327", r"(?:md5|sha1)\s*\.\s*(?:New|Sum)", "MD5 and SHA-1 are cryptographically broken.", "Use crypto/sha256 or crypto/sha512, or a password hasher (bcrypt/argon2)."),

        // ------------------------------------------------------------ C / C++
        srule!("c-strcpy", "strcpy() — buffer overflow", &["c", "cpp"], "high", "CWE-120", r"\bstrcpy\s*\(", "strcpy() has no bounds checking and is a classic buffer-overflow sink.", "Use strncpy with explicit bounds, or safer APIs (strlcpy/snprintf), or std::string."),
        srule!("c-strcat", "strcat() — buffer overflow", &["c", "cpp"], "high", "CWE-120", r"\bstrcat\s*\(", "strcat() has no bounds checking and can overflow the destination buffer.", "Use strncat with explicit size or std::string append."),
        srule!("c-sprintf", "sprintf() without bounds", &["c", "cpp"], "medium", "CWE-120", r"\bsprintf\s*\(", "sprintf() writes without a size limit and can overflow the buffer.", "Use snprintf() with the buffer size, or std::string streams."),
        srule!("c-gets", "gets() — unbounded read", &["c", "cpp"], "high", "CWE-242", r"\bgets\s*\(", "gets() reads an unbounded line into a fixed buffer — always exploitable stack overflow.", "Use fgets() with a size limit or getline()."),
        srule!("c-system", "system()", &["c", "cpp"], "medium", "CWE-78", r"\bsystem\s*\(", "system() passes a string to the shell; with untrusted content it is command injection.", "Use execve/posix_spawn with an argument array and no shell."),
        srule!("c-scanf-unsafe", "scanf with %s", &["c", "cpp"], "medium", "CWE-120", r#"\bscanf\s*\(\s*['"][^'"]*%s"#, "%s in scanf has no width limit and can overflow the buffer.", "Use fgets() or scanf with a field width (e.g. %63s)."),

        // ---------------------------------------------------------------- PHP
        srule!("php-eval", "eval() usage", &["php"], "high", "CWE-95", r"\beval\s*\(", "eval() executes PHP code strings — a direct RCE sink when anything is dynamic.", "Remove eval(); use static code and data structures."),
        srule!("php-shell", "Shell execution functions", &["php"], "high", "CWE-78", r"\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(", "These functions execute shell commands; untrusted input is command injection.", "Avoid shell calls; validate/whitelist inputs and use escapeshellarg for arguments."),
        srule!("php-exec", "exec() usage", &["php"], "medium", "CWE-78", r"\bexec\s*\(", "exec() runs shell commands; verify arguments are never user-controlled.", "Prefer non-shell alternatives; always validate inputs."),
        srule!("php-sql-concat", "SQL built with concatenation", &["php"], "high", "CWE-89", r"(?:->query|->exec|mysqli?_query|pg_query)\s*\([^)]*(?:\$|\.)", "SQL statements built with PHP variables/concatenation are SQL-injection sinks.", "Use PDO prepared statements with bound parameters."),
        srule!("php-file-inclusion", "User-controlled file inclusion", &["php"], "high", "CWE-98", r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_?(?:GET|POST|REQUEST|COOKIE)", "Including files from request parameters enables Local/Remote File Inclusion (LFI/RFI).", "Never include files based on user input; use an allow-list of templates/views."),
        srule!("php-unserialize", "unserialize() of untrusted data", &["php"], "high", "CWE-502", r"\bunserialize\s*\(", "unserialize() on untrusted data can trigger object injection / RCE via magic methods.", "Never unserialize untrusted input; use JSON with strict validation."),

        // --------------------------------------------------------------- Ruby
        srule!("rb-eval", "eval() usage", &["ruby"], "high", "CWE-95", r"\beval\s*\(", "eval() executes Ruby code strings — RCE when anything is dynamic.", "Remove eval(); parse data with JSON/YAML-safe parsers."),
        srule!("rb-system", "system() call", &["ruby"], "high", "CWE-78", r"\bsystem\s*\(", "system() runs a string through the shell — command injection sink.", "Use Open3.capture3 with an argument array and validate inputs."),
        srule!("rb-sql-concat", "SQL built with interpolation", &["ruby"], "high", "CWE-89", r"(?:execute|query)\s*\([^)]*(?:\+|#\{)", "SQL with string interpolation (#{}) or concatenation is a SQL-injection sink.", "Use ActiveRecord parameterized queries / prepared statements with ? bindings."),
        srule!("rb-marshal", "Marshal.load of untrusted data", &["ruby"], "high", "CWE-502", r"Marshal\s*\.\s*(?:load|restore)", "Marshal.load can instantiate arbitrary objects and execute code.", "Never Marshal.load untrusted data; use JSON."),

        // --------------------------------------------------------------- Rust
        srule!("rs-command-sh", "Command::new with a shell", &["rust"], "high", "CWE-78", r#"Command::new\s*\(\s*['"](?:sh|bash)['"]\)"#, "Spawning sh/bash to execute constructed command strings is a command-injection sink.", "Invoke the program directly with .arg() values — never pass a command string to a shell."),
        srule!("rs-sql-format", "SQL built with format!/+", &["rust"], "high", "CWE-89", r"(?:query|execute|execute_batch|execute_many)\s*\([^)]*(?:format!|write!|\+)", "SQL statements assembled with format! or + are SQL-injection sinks.", "Use sqlx/rusqlite bound parameters (? or $1)."),
        srule!("rs-weak-hash", "md5::compute usage", &["rust"], "medium", "CWE-327", r"\bmd5::compute\b", "MD5 is cryptographically broken.", "Use sha2 or blake3 for hashing, or a password hasher (argon2/bcrypt)."),

        // ------------------------------------------------------------ Generic
        srule!("gen-hardcoded-password", "Hardcoded password assignment", ANY, "medium", "CWE-259", r#"(?i)\b(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,64}['"]"#, "A password is assigned a literal value in code — hardcoded credentials.", "Store credentials in environment variables / a secrets manager and rotate this one."),
        srule!("gen-weak-crypto", "Weak crypto primitive (md5/sha1)", ANY, "medium", "CWE-327", r"(?i)\b(?:md5|sha1)\s*\(", "Usage of the broken MD5/SHA-1 algorithms for security purposes.", "Use SHA-256/512 or a dedicated KDF/password hasher."),
    ]
});

/// A single pattern hit.
pub struct PatternHit {
    pub rule_index: usize,
    pub offset: usize,
    pub match_text: String,
}

/// Scan content for rules matching `language` ("" or None = generic rules only
/// apply to every language via the empty languages slice).
pub fn scan_content(content: &str, language: &str) -> Vec<PatternHit> {
    let mut hits = Vec::new();
    for (i, rule) in SOURCE_RULES.iter().enumerate() {
        if !rule.languages.is_empty() && !rule.languages.contains(&language) {
            continue;
        }
        for captures in rule.regex.captures_iter(content) {
            // Rust's regex has no lookbehind, so a rule that must exclude a
            // preceding character has to consume it — `(?:^|[^.\w$])eval\s*\(`
            // is how `parser.eval(` is told apart from the builtin. Reporting
            // that match verbatim would shift the finding one column left and
            // change its text depending on what precedes it, which moves the
            // fingerprint. When a rule captures group 1, that group is the
            // finding; the rest is context the rule needed in order to decide.
            let span = captures.get(1).or_else(|| captures.get(0));
            let Some(span) = span else { continue };
            hits.push(PatternHit {
                rule_index: i,
                offset: span.start(),
                match_text: span.as_str().to_string(),
            });
        }
    }
    hits
}

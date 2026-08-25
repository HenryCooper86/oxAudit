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
        srule!("js-weak-hash", "Weak hash (MD5/SHA-1)", &["javascript"], "medium", "CWE-327", r#"(?i)createHash\s*\(\s*['"](?:md[245]|sha-?1)['"]"#, "MD5 and SHA-1 are cryptographically broken and must not be used for security purposes (passwords, signatures, integrity).", "Use SHA-256/SHA-512 or a dedicated password hasher (bcrypt/argon2/scrypt)."),
        srule!("js-postmessage-wildcard", "postMessage wildcard origin", &["javascript"], "low", "CWE-345", r#"postMessage\s*\([^)]*,\s*['"]\*['"]"#, "postMessage() with targetOrigin '*' lets any window receive the message, potentially leaking sensitive data.", "Pass the specific expected origin instead of '*'."),

        // ------------------------------------------------------------ Python
        srule!("py-eval", "eval() usage", &["python"], "high", "CWE-95", r"(?:^|[^.\w])(eval\s*\()", "eval() executes arbitrary Python expressions; attacker-controlled input becomes code execution.", "Avoid eval()/exec(); use ast.literal_eval for trusted literals or a proper parser for the data format."),
        srule!("py-exec", "exec() usage", &["python"], "high", "CWE-95", r"(?:^|[^.\w])(exec\s*\()", "exec() executes arbitrary Python code strings; any dynamic input is a code-execution primitive.", "Replace with static code; if dynamic evaluation is truly required, sandbox it (e.g. RestrictedPython) and document the risk."),
        srule!("py-pickle", "pickle.load(s) — unsafe deserialization", &["python"], "high", "CWE-502", r"(?:pickle|cPickle)\s*\.\s*loads?\s*\(", "pickle deserialization can execute arbitrary code embedded in the payload (pickle is not a safe format).", "Never unpickle untrusted data. Use JSON/msgpack for untrusted input, or verify authenticity with a signature first."),
        srule!("py-yaml-load", "yaml.load() — unsafe deserialization", &["python"], "high", "CWE-502", r"yaml\s*\.\s*load\s*\(", "yaml.load() without an explicit safe Loader can construct arbitrary Python objects and execute code.", "Use yaml.safe_load() (or CSafeLoader) — never yaml.load() on untrusted YAML."),
        srule!("py-subprocess-shell", "subprocess with shell=True", &["python"], "high", "CWE-78", r"(?:subprocess\s*\.\s*)?(?:run|call|Popen|check_output|check_call)\s*\([\s\S]{0,200}?shell\s*=\s*True", "shell=True routes commands through /bin/sh, enabling shell metacharacter injection when arguments contain user input.", "Use shell=False with an argument list; build commands as argv arrays, never strings."),
        srule!("py-os-system", "os.system()", &["python"], "high", "CWE-78", r"os\s*\.\s*system\s*\(", "os.system() runs a string through the shell — a command-injection sink.", "Replace with subprocess.run([...], shell=False) and validate inputs."),
        srule!("py-sql-fstring", "SQL with f-string", &["python"], "high", "CWE-89", r#"(?:execute|executemany|executescript)\s*\(\s*f['"]"#, "F-string SQL queries embed values directly into the statement — SQL injection.", "Use parameterized queries (? placeholders / %s with driver params)."),
        srule!("py-sql-concat", "SQL with string concatenation", &["python"], "high", "CWE-89", r"(?:execute|executemany)\s*\(\s*[^)]*\+", "SQL statements assembled with + concatenation are a SQL-injection sink.", "Use parameterized queries with bound parameters."),
        srule!("py-verify-false", "TLS verification disabled", &["python"], "medium", "CWE-295", r"(?:requests|httpx)\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False", "Disabling TLS certificate verification (verify=False) exposes traffic to man-in-the-middle attacks.", "Keep verification enabled; if a self-signed cert must be used, pin the CA bundle explicitly."),
        srule!("py-weak-hash", "Weak hash (MD5/SHA-1)", &["python"], "medium", "CWE-327", r"(?:hashlib\s*\.\s*(?:md5|sha1)|(?:md5|sha1)\s*\()", "MD5 and SHA-1 are cryptographically broken for security purposes.", "Use hashlib.sha256/sha512, or a password hasher like argon2/bcrypt for credentials."),

        // --------------------------------------------------------------- Java
        srule!("java-runtime-exec", "Runtime.exec()", &["java", "kotlin"], "high", "CWE-78", r"(?s)\bRuntime\b\s*(?:\.\s*getRuntime\s*\(\s*\)|\w+\s*=).{0,200}?(\.\s*exec\s*\()", "Runtime.exec() runs a system command; with user input it becomes command injection.", "Avoid external commands; if required use ProcessBuilder with an argument list and validate inputs."),
        srule!("java-process-builder", "ProcessBuilder usage", &["java", "kotlin"], "medium", "CWE-78", r"(?:new\s+)?ProcessBuilder\s*\(", "ProcessBuilder launches external processes. It is safe with static arguments but becomes dangerous when arguments include untrusted input.", "Pass arguments as a List (never concatenate into a shell string) and validate/whitelist inputs."),
        srule!("java-sql-concat", "SQL built with concatenation", &["java", "kotlin"], "high", "CWE-89", r"(?:Statement|PreparedStatement)[^;]{0,80}\s*\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*[^)]*(?:\+|String\.format)|(\.\s*(?:prepareStatement|prepareCall|executeQuery|executeUpdate|execute)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*[,)])", "SQL statements built with + or String.format are SQL-injection sinks.", "Always use PreparedStatement with ? placeholders and bind parameters."),
        srule!("java-xss-response", "Unescaped value written to the response", &["java", "kotlin"], "high", "CWE-79", r"(?:getWriter|getOutputStream)\s*\(\s*\)\s*(\.\s*(?:print|println|printf|write|format|append)\s*\()", "Writing an untrusted value into the response body without escaping it lets a crafted value close the surrounding markup and run as script in the victim's browser. A format method is worse still: an attacker-controlled format string reads the argument list.", "Escape on output for the context you are writing into — ESAPI's encodeForHTML for element text, encodeForHTMLAttribute inside an attribute — and never pass an untrusted value as a format string."),
        srule!("java-ldap-injection", "LDAP filter built by concatenation", &["java", "kotlin"], "high", "CWE-90", r"(?s)\bDirContext\b.{0,800}?(\.\s*search\s*\()", "An LDAP filter assembled by concatenation cannot separate the value from the filter syntax, so a crafted value rewrites the query — `*)(uid=*` turns an authentication check into a match on every entry.", "Use a parameterised filter with {0} placeholders and pass the values as the filterArgs array, or escape with ESAPI's encodeForLDAP."),
        srule!("java-xpath-injection", "XPath expression built by concatenation", &["java", "kotlin"], "high", "CWE-643", r"(?s)\bXPath\b.{0,300}?(\.\s*(?:evaluate|compile)\s*\()", "An XPath expression assembled by concatenation cannot separate the value from the query syntax, so a crafted value selects nodes the query was never meant to return.", "Bind values with XPathVariableResolver and reference them as $name, or escape with ESAPI's encodeForXPath."),
        srule!("java-insecure-cookie", "Cookie sent without the Secure flag", &["java", "kotlin"], "medium", "CWE-614", r"\.\s*setSecure\s*\(\s*false\s*\)", "A cookie without the Secure attribute is sent over plain HTTP as well as HTTPS, so anyone on the network path can read it. For a session cookie that is the session.", "Call setSecure(true), and set HttpOnly and SameSite while you are there. Prefer configuring this once for the whole application rather than per cookie."),
        srule!("java-trust-boundary", "Untrusted value used as a session attribute name", &["java", "kotlin"], "medium", "CWE-501", r"(?s)\bgetSession\s*\(\s*\).{0,200}?(\.\s*(?:setAttribute|putValue)\s*\()", "The session is trusted storage and a request value is not. Letting an attacker choose the attribute name lets them overwrite entries the application later reads back as its own — a role, a user id, an authentication flag.", "Use a fixed set of attribute names chosen by the application, and validate any request value before it is stored."),
        srule!("java-deserialization", "Unsafe deserialization", &["java", "kotlin"], "high", "CWE-502", r"(?:ObjectInputStream|XMLDecoder|ObjectInput)[^;]{0,80}\s*readObject\s*\(", "readObject()/XMLDecoder deserialization of untrusted data can lead to RCE via gadget chains.", "Do not deserialize untrusted data; use safe formats (JSON) with strict schemas, or an allow-listed deserialization filter."),
        srule!("java-cipher-ecb", "Cipher in ECB mode", &["java"], "medium", "CWE-327", r#"Cipher\s*\.\s*getInstance\s*\(\s*['"][^'"]*\/ECB\/"#, "ECB mode leaks patterns in ciphertext and is not semantically secure.", "Use AES-GCM (or CBC with HMAC) and a random IV."),
        srule!("java-weak-cipher", "Broken cipher algorithm", &["java", "kotlin"], "high", "CWE-327", r#"(?:Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*['"](?:DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)\b"#, "DES and Triple DES have key sizes small enough to brute force, and RC2, RC4, and Blowfish have structural weaknesses. The mode does not matter: `DES/CBC/PKCS5Padding` is broken because DES is broken.", "Use AES-256 in GCM mode. For key derivation use PBKDF2, scrypt, or Argon2."),
        // As with the digest above, the algorithm is often a configuration key
        // rather than a literal. Firing only on a resolved value keeps this
        // from reporting every `Cipher.getInstance(alg)` in a codebase.
        srule!("java-configured-weak-cipher", "Broken cipher algorithm named in configuration", &["java", "kotlin"], "high", "CWE-327", r"(?:Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(", "The cipher this call is given resolves to DES, Triple DES, RC2, RC4, or Blowfish. The mode does not matter: `DES/CBC/PKCS5Padding` is broken because DES is broken.", "Use AES-256 in GCM mode, and change the configured value as well as the code."),
        srule!("java-weak-prng", "Non-cryptographic random number generator", &["java", "kotlin"], "low", "CWE-330", r#"new\s+(?:java\s*\.\s*util\s*\.\s*)?\bRandom\s*\(|\bMath\s*\.\s*random\s*\(|\bThreadLocalRandom\s*\.\s*current\s*\("#, "java.util.Random is a linear congruential generator: its entire future output is derivable from a couple of observed values. This does not say the value is security-relevant — it says nothing here proves it is not, and that is a question only a person can answer.", "If this value is a token, key, nonce, salt, or session identifier, use java.security.SecureRandom. If it is a simulation, sample, or animation, dismiss this with a reason."),
        srule!("java-weak-hash", "Weak hash (MD5/SHA-1)", &["java"], "medium", "CWE-327", r#"(?i)MessageDigest\s*\.\s*getInstance\s*\(\s*['"](?:MD[245]|SHA-?1)['"]"#, "MD5 and SHA-1 are cryptographically broken.", "Use SHA-256+ or a password hasher (BCrypt/Argon2)."),
        // The literal form above and this one match at the same offset, so
        // `SUPERSEDES` keeps `getInstance("MD5")` from being reported twice.
        // This one carries the finding when the name is not written at the
        // call: it fires only when the value resolves, and only when what it
        // resolves to is broken.
        srule!("java-configured-weak-hash", "Weak hash (MD5/SHA-1) named in configuration", &["java"], "medium", "CWE-327", r"MessageDigest\s*\.\s*getInstance\s*\(", "The digest algorithm this call is given resolves to MD5 or SHA-1, which are cryptographically broken.", "Use SHA-256+ or a password hasher (BCrypt/Argon2), and change the configured value as well as the code."),

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

        // ------------------------------------------- CWE-22 path traversal
        //
        // Matched on something being joined into a path rather than on a file
        // being read at all. Flagging every read would bury the user under the
        // most common operation in most programs; concatenating into a path is
        // the shape that actually traverses out of it.
        srule!("js-path-traversal", "Path built by concatenation", &["javascript"], "high", "CWE-22", r#"(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|unlink|sendFile)\s*\([^)]{0,120}(?:\+|\$\{)|path\s*\.\s*(?:join|resolve)\s*\([^)]{0,120}\b(?:req|request|params|query|body|argv)\b"#, "A filesystem path assembled from untrusted input can be steered out of its intended directory with ../ segments, exposing or overwriting arbitrary files.", "Resolve the path and verify it is still inside the intended root (path.resolve then startsWith), or index into an allow-list instead of accepting a name."),
        srule!("py-path-traversal", "Path built by concatenation", &["python"], "high", "CWE-22", r#"(?:open|os\s*\.\s*remove|os\s*\.\s*unlink|shutil\s*\.\s*(?:copy|move|rmtree)|send_file)\s*\(\s*[^)]{0,120}(?:\+|%\s|\.format\(|f['"])"#, "A filesystem path assembled from untrusted input can be steered out of its intended directory with ../ segments.", "Use os.path.realpath and confirm the result is under the intended root, or map an identifier to a known filename instead of joining input."),
        // Matched on the sink alone, not on a visible concatenation. The
        // concatenation is usually a statement earlier — `fileName = ROOT +
        // param;` then `new File(fileName)` — and requiring it inside the
        // parens made this rule unfirable on 133 of the 133 path traversals in
        // the OWASP Benchmark. What keeps it quiet is the CWE-22 entry in
        // `REQUIRES_EXTERNAL_ORIGIN`: the path has to trace to a request, argv
        // or the environment, not merely to a parameter, because taking a path
        // is what a file helper does.
        //
        // Alternatives run longest-first: matching is leftmost-first, so
        // `File` listed ahead of `FileInputStream` would truncate the reported
        // text to the shorter name.
        srule!("java-path-traversal", "File path from untrusted input", &["java"], "high", "CWE-22", r"(?:new\s+(?:[\w.]*\.)?(?:FileInputStream|FileOutputStream|RandomAccessFile|FileReader|FileWriter|File)|(?:[\w.]*\.)?Paths\s*\.\s*get|(?:[\w.]*\.)?Files\s*\.\s*(?:readAllBytes|readAllLines|readString|writeString|write|delete|deleteIfExists|copy|move|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter))\s*\(", "A filesystem path taken from a request, argv, or the environment can be steered out of its intended directory with ../ segments, exposing or overwriting arbitrary files.", "Resolve the path with getCanonicalPath() and verify the result still startsWith the intended root, or index into an allow-list instead of accepting a name."),
        srule!("go-path-traversal", "Path built by concatenation", &["go"], "high", "CWE-22", r#"(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|Remove|Create)|ioutil\s*\.\s*ReadFile)\s*\(\s*[^)]{0,120}(?:\+|fmt\s*\.\s*Sprintf)"#, "A filesystem path assembled from untrusted input can be steered out of its intended directory with ../ segments.", "Use filepath.Clean and confirm the result is still inside the intended root, or accept an identifier rather than a path."),

        // ------------------------------------------------------ CWE-918 SSRF
        //
        // The sink is a request whose destination is not a fixed literal.
        // Reaching the network is ordinary; letting a caller choose where is
        // not. Dataflow decides whether the destination is actually reachable
        // by an attacker, so the rule only has to spot a non-literal target.
        srule!("js-ssrf", "Request to a caller-supplied URL", &["javascript"], "high", "CWE-918", r#"\b(?:fetch|got)\s*\(\s*[A-Za-z_$]|axios\s*(?:\.\s*(?:get|post|put|delete|request))?\s*\(\s*[A-Za-z_$]|https?\s*\.\s*request\s*\(\s*[A-Za-z_$]"#, "The destination of this request is not a fixed literal. If a caller can choose it, the server can be aimed at internal services and cloud metadata endpoints it can reach but the caller cannot.", "Resolve the URL against an allow-list of hosts, and refuse addresses that are private, loopback, or link-local after DNS resolution."),
        srule!("py-ssrf", "Request to a caller-supplied URL", &["python"], "high", "CWE-918", r#"(?:requests|httpx)\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(\s*[A-Za-z_]|urlopen\s*\(\s*[A-Za-z_]"#, "The destination of this request is not a fixed literal. If a caller can choose it, the server can be aimed at internal services and cloud metadata endpoints.", "Validate the URL against an allow-list of hosts and block private, loopback, and link-local addresses after resolution."),
        srule!("go-ssrf", "Request to a caller-supplied URL", &["go"], "high", "CWE-918", r#"(?:http|client)\s*\.\s*(?:Get|Post|Head)\s*\(\s*[A-Za-z_]"#, "The destination of this request is not a fixed literal. If a caller can choose it, the server can be aimed at internal services and cloud metadata endpoints.", "Validate the URL against an allow-list of hosts and block private, loopback, and link-local addresses after resolution."),

        // --------------------------------------------------- CWE-611 XXE
        //
        // Guarded rules: the defect is that entity resolution was left on, so
        // the fix living elsewhere in the file disproves the finding. See
        // RULE_GUARDS.
        srule!("java-xxe", "XML parser resolves external entities", &["java", "kotlin"], "high", "CWE-611", r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\s*\.\s*newInstance\s*\(|\bnew\s+SAXReader\s*\(", "An XML parser left at its default configuration resolves external entities, so a crafted document can read local files, reach internal network services, or exhaust memory through entity expansion.", "Disable DOCTYPE declarations: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true), and switch off external general and parameter entities."),
        srule!("py-xxe", "XML parser resolves external entities", &["python"], "high", "CWE-611", r"\b(?:xml\s*\.\s*etree\s*\.\s*ElementTree|xml\s*\.\s*dom\s*\.\s*minidom|xml\s*\.\s*sax|ET)\s*\.\s*(?:parse|fromstring|parseString)\s*\(", "Python's standard-library XML parsers resolve external entities, so a crafted document can read local files or reach internal network services.", "Use the defusedxml package, which provides drop-in replacements with entity resolution disabled."),

        // ----------------------------- CWE-338 weak randomness for security
        //
        // Intent is the whole difficulty: Math.random() for animation jitter
        // is fine and for a session token is not. Matched on what the value is
        // called, within a bounded window, rather than on the call alone.
        srule!("js-insecure-random", "Predictable randomness for a secret", &["javascript"], "high", "CWE-338", r"(?i)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|uuid|verifier)\w*\s*[:=][^;\n]{0,80}?(Math\s*\.\s*random\s*\()", "Math.random() is a fast pseudo-random generator, not a cryptographic one. Its output is predictable from previous values, so anything derived from it can be guessed.", "Use crypto.randomUUID() or crypto.getRandomValues() in the browser, or crypto.randomBytes() in Node."),
        srule!("py-insecure-random", "Predictable randomness for a secret", &["python"], "high", "CWE-338", r"(?is)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|verifier)\w*[\s\S]{0,160}?(\brandom\s*\.\s*(?:random|randint|choice|choices|randrange|getrandbits|shuffle)\s*\()", "The random module is a Mersenne Twister, not a cryptographic generator. Its output is predictable from previous values, so anything derived from it can be guessed.", "Use the secrets module: secrets.token_urlsafe(), secrets.token_hex(), or secrets.choice()."),
        srule!("java-insecure-random", "Predictable randomness for a secret", &["java"], "high", "CWE-338", r"(?is)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|verifier)\w*[\s\S]{0,160}?(\bnew\s+(?:java\s*\.\s*util\s*\.\s*)?Random\s*\()", "java.util.Random is a linear congruential generator, not a cryptographic one. Its output is predictable from previous values, so anything derived from it can be guessed.", "Use java.security.SecureRandom, and prefer SecureRandom.getInstanceStrong() where blocking is acceptable."),
        srule!("kt-insecure-random", "Predictable randomness for a secret", &["kotlin"], "high", "CWE-338", r"(?is)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|verifier)\w*[\s\S]{0,160}?(\bRandom\s*(?:\.\s*\w+)*\s*\(|\bMath\s*\.\s*random\s*\()", "kotlin.random.Random and java.util.Random are linear congruential generators, not cryptographic ones, so a value derived from one is predictable to anybody who has seen earlier output.", "Use java.security.SecureRandom, or SecureRandom().asKotlinRandom() to keep the Kotlin API."),
        srule!("cs-process-start", "Process.Start with a built command", &["csharp"], "high", "CWE-78", r"\bProcess\s*\.\s*Start\s*\(", "Process.Start hands its arguments to the operating system, and with UseShellExecute the string is parsed by a shell first, so untrusted content becomes command injection.", "Pass ProcessStartInfo.ArgumentList rather than a single Arguments string, and leave UseShellExecute false."),
        srule!("cs-sql-concat", "SQL built with concatenation", &["csharp"], "critical", "CWE-89", r#"(?:SqlCommand|OleDbCommand|NpgsqlCommand|MySqlCommand)\s*\(\s*[$@]?"[^"]*"\s*\+|CommandText\s*=\s*[$@]?"[^"]*"\s*\+"#, "A query assembled by concatenation cannot distinguish data from syntax, so a crafted value rewrites the statement.", "Use SqlParameter and placeholders; never concatenate or interpolate values into CommandText."),
        srule!("cs-deserialization", "Unsafe deserialization", &["csharp"], "critical", "CWE-502", r"\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\s*\(|\bJavaScriptSerializer\s*\([\s\S]{0,80}?SimpleTypeResolver", "These formatters reconstruct arbitrary types named by the payload, so deserializing untrusted data is remote code execution. BinaryFormatter is obsolete and removed in .NET 9.", "Use System.Text.Json or a contract-based serializer that never resolves types from the payload."),
        srule!("cs-xxe", "XML reader resolves external entities", &["csharp"], "high", "CWE-611", r"\bXmlTextReader\s*\(|DtdProcessing\s*\.\s*Parse|ProhibitDtd\s*=\s*false", "An XML reader that processes DTDs resolves external entities, so a crafted document can read local files or reach internal services.", "Set DtdProcessing = DtdProcessing.Prohibit and XmlResolver = null, or use XmlReader.Create with secure defaults."),
        srule!("cs-weak-crypto", "Weak hash or cipher", &["csharp"], "medium", "CWE-327", r"\b(?:MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed|Cng)?\s*\.\s*Create\s*\(|new\s+(?:MD5|SHA1|DES|TripleDES|RC2)(?:CryptoServiceProvider|Managed|Cng)\s*\(", "MD5 and SHA-1 are broken for collision resistance; DES, Triple DES, and RC2 have key sizes or structures that no longer resist attack.", "Use SHA-256 or better for hashing, and AES for encryption."),
        srule!("cs-insecure-random", "Predictable randomness for a secret", &["csharp"], "high", "CWE-338", r"(?is)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|verifier)\w*[\s\S]{0,160}?(\bnew\s+Random\s*\()", "System.Random is a deterministic pseudo-random generator seeded from the clock, so a value derived from one is predictable to anybody who can guess when it was created.", "Use RandomNumberGenerator.GetBytes or RandomNumberGenerator.GetInt32 from System.Security.Cryptography."),
        srule!("swift-insecure-random", "Predictable randomness for a secret", &["swift"], "high", "CWE-338", r"(?is)(?:^|[^A-Za-z0-9])(?:token|secret|api[_-]?key|nonce|salt|password|session|csrf|otp|verifier)\w*[\s\S]{0,160}?(\barc4random_uniform\s*\(|\barc4random\s*\(|\.random\s*\(\s*in\s*:|\brandom\s*\(\s*\))", "Swift's random() and arc4random are fast general-purpose generators, not cryptographic ones, so a value derived from one should not be treated as unguessable.", "Use SecRandomCopyBytes, or CryptoKit's SymmetricKey(size:) when generating key material."),
        srule!("swift-weak-crypto", "Weak hash or cipher", &["swift"], "medium", "CWE-327", r"\bInsecure\s*\.\s*(?:MD5|SHA1)\b|\bCC_(?:MD5|SHA1)\s*\(|kCCAlgorithm(?:DES|3DES|RC4)\b", "MD5 and SHA-1 are broken for collision resistance, and DES, Triple DES, and RC4 no longer resist attack. CryptoKit names these Insecure precisely because they are.", "Use SHA256 from CryptoKit for hashing and AES-GCM for encryption."),
        srule!("swift-trust-bypass", "TLS certificate validation bypassed", &["swift"], "high", "CWE-295", r"URLCredential\s*\(\s*trust\s*:|SecTrustSetExceptions\s*\(|\.serverTrust\s*!", "Accepting the server's own trust object answers the TLS challenge with whatever certificate was presented, so any network position becomes a man-in-the-middle.", "Let the system evaluate the challenge, or pin a known certificate with SecTrustEvaluateWithError before accepting."),

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
        srule!("rs-sql-format", "SQL built with format!/+", &["rust"], "high", "CWE-89", r#"(?:query|execute|execute_batch|execute_many)\s*\(\s*[^;]{0,160}?(?:format!|write!|"\s*\+|\+\s*")"#, "SQL statements assembled with format! or + are SQL-injection sinks.", "Use sqlx/rusqlite bound parameters (? or $1)."),
        srule!("rs-weak-hash", "md5::compute usage", &["rust"], "medium", "CWE-327", r"\bmd5::compute\b", "MD5 is cryptographically broken.", "Use sha2 or blake3 for hashing, or a password hasher (argon2/bcrypt)."),

        // ------------------------------------------------------------ Generic
        srule!("gen-hardcoded-password", "Hardcoded password assignment", ANY, "medium", "CWE-259", r#"(?i)\b(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,64}['"]"#, "A password is assigned a literal value in code — hardcoded credentials.", "Store credentials in environment variables / a secrets manager and rotate this one."),
        srule!("gen-weak-crypto", "Weak crypto primitive (md5/sha1)", ANY, "medium", "CWE-327", r"(?i)\b(?:md5|sha1)\s*\(", "Usage of the broken MD5/SHA-1 algorithms for security purposes.", "Use SHA-256/512 or a dedicated KDF/password hasher."),
    ]
});

/// A single pattern hit.
/// Patterns that, present anywhere in the file, disprove a rule.
///
/// Some defects are the *absence* of hardening rather than the presence of a
/// call. An XML parser resolves external entities unless it is told not to, so
/// a rule for that has to be able to see the fix — and the fix is usually
/// several lines from the construction it protects, which a single regex over
/// one match cannot reach.
///
/// Deliberately file-scoped and deliberately blunt. A file that disables
/// entity resolution anywhere is treated as having done so everywhere, which
/// can hide a second unhardened parser in the same file. The alternative —
/// reporting every parser in every file that ever hardens one — is the noise
/// that gets a rule switched off.
const RULE_GUARDS: &[(&str, &str)] = &[
    (
        "java-xxe",
        r"(?:disallow-doctype-decl|external-general-entities|external-parameter-entities|setExpandEntityReferences\s*\(\s*false|FEATURE_SECURE_PROCESSING|setXIncludeAware\s*\(\s*false)",
    ),
    ("py-xxe", r"\bdefusedxml\b"),
    // ArgumentList hands the OS an argv, which is this rule's own remediation.
    ("cs-process-start", r"\bArgumentList\b"),
    // Canonicalising and then checking containment is exactly what this rule's
    // remediation text asks for. A file that does it is answering the question
    // the finding would ask, and reporting it means reporting the fix.
    (
        "java-path-traversal",
        r"(?:getCanonicalPath|toRealPath|normalize)\s*\(\s*\)[\s\S]{0,160}?startsWith\s*\(",
    ),
];

/// Compiled once; a guard is checked for every file a guarded rule matches in.
static COMPILED_GUARDS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    RULE_GUARDS
        .iter()
        .map(|(rule, pattern)| (*rule, Regex::new(pattern).expect("invalid guard pattern")))
        .collect()
});

/// The guard for a rule, if it has one.
///
/// Evaluated by the caller rather than here, because whether the hardening is
/// real depends on it being code: a comment explaining that `defusedxml`
/// exists is not the same as importing it, and matching raw text could not
/// tell the two apart.
/// Rules where exactly one argument is the injection vector.
///
/// The default is that any tainted argument taints the call, which is right
/// for `exec(a, b)` where every argument reaches the shell. It is wrong where
/// one argument is the query and the rest are not:
/// `xp.evaluate(expression, document)` was reported for a constant expression
/// because the document beside it is a parameter, and `ctx.search(base,
/// filter, args, controls)` was reported for a parameterised filter because
/// the values bound to its placeholders are — correctly — attacker-controlled.
/// The second case flagged this rule's own remediation.
/// Deliberately not `java-xss-response`. Every argument to a writer reaches
/// the output, and the position varies with the overload —
/// `format(Locale.US, param, obj)` puts the format string second. Pinning it
/// to the first argument cost 71 true positives on the Benchmark.
const SINK_ARGUMENT: &[(&str, usize)] = &[
    ("java-ldap-injection", 1),
    ("java-xpath-injection", 0),
    // The *name*, not the value. Storing a request value in the session under
    // a fixed key is what every login form does; letting an attacker choose
    // the key is what lets them overwrite `isAdmin`. Judging this call by
    // every argument reports the first and buries the second.
    ("java-trust-boundary", 0),
];

/// Which argument carries the injection, when only one of them does.
pub fn sink_argument(rule_id: &str) -> Option<usize> {
    SINK_ARGUMENT
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, index)| *index)
}

/// Algorithm names that are broken for the uses these rules are about.
///
/// Compared after normalising away case and separators, so `SHA-1`, `SHA1`
/// and `sha_1` are one entry.
const BROKEN_DIGESTS: &[&str] = &["md2", "md4", "md5", "sha0", "sha1"];

/// Ciphers that are broken whatever mode is bolted onto them.
const BROKEN_CIPHERS: &[&str] = &[
    "des",
    "desede",
    "tripledes",
    "rc2",
    "rc4",
    "arcfour",
    "blowfish",
];

/// Rules whose finding depends on the *value* of one argument, not its taint.
///
/// `MessageDigest.getInstance(algorithm)` is a defect when `algorithm` is MD5
/// and correct when it is SHA-256, and the name is frequently not written at
/// the call. 40 of the OWASP Benchmark's hash cases read it out of
/// `benchmark.properties`, where the literal in the source is a strong default
/// that the file overrides with MD5 — so the source read on its own gets the
/// answer exactly backwards.
///
/// Unresolvable means silent, which is the opposite of this scanner's usual
/// direction. The finding asserts that a broken algorithm is in use; asserting
/// that without knowing the algorithm would be making it up. A tainted or
/// merely unknown argument is a different weakness and would need its own
/// rule to say so.
const RESOLVED_ARGUMENT_VALUES: &[(&str, usize, &[&str])] = &[
    ("java-configured-weak-hash", 0, BROKEN_DIGESTS),
    ("java-configured-weak-cipher", 0, BROKEN_CIPHERS),
];

/// The argument whose value decides a rule, and the values that make it fire.
pub fn resolved_argument_values(rule_id: &str) -> Option<(usize, &'static [&'static str])> {
    RESOLVED_ARGUMENT_VALUES
        .iter()
        .find(|(id, _, _)| *id == rule_id)
        .map(|(_, index, values)| (*index, *values))
}

/// Case and separators carry no meaning in an algorithm name.
pub fn names_algorithm(value: &str, candidates: &[&str]) -> bool {
    let normalized: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    // `DES/ECB/PKCS5Padding` names its algorithm before the first slash; a
    // digest name has no slash and is unaffected.
    let head = normalized.split('/').next().unwrap_or(&normalized);
    candidates.contains(&head)
}

/// Rules whose sink is only a shell sink in its single-string form.
///
/// Ruby's `system`, `exec`, and `spawn` run a command through the shell when
/// given one string and hand the OS an argv when given several. The rules
/// recommend the argv form as the remediation, so firing on it reports the fix
/// as the defect.
///
/// Deliberately not a general rule about argument counts: C's `system()` takes
/// exactly one argument and is a shell sink regardless, and Python's
/// `subprocess` family is keyed on `shell=True` rather than on shape.
const ARGV_SAFE_RULES: &[&str] = &["rb-system"];

/// Does an argument vector take this rule's sink out of the shell?
pub fn argv_form_is_safe(rule_id: &str) -> bool {
    ARGV_SAFE_RULES.contains(&rule_id)
}

pub fn guard_pattern(rule_id: &str) -> Option<&'static Regex> {
    COMPILED_GUARDS
        .iter()
        .find(|(guarded, _)| *guarded == rule_id)
        .map(|(_, pattern)| pattern)
}

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
    drop_superseded(&mut hits);
    hits
}

/// A specific rule and the broader one it stands in for at the same site.
///
/// `java-insecure-random` says a *secret* was built from a weak generator and
/// is high severity; `java-weak-prng` says only that the generator is weak and
/// asks a person to decide. Both describe the same call, so reporting both
/// means the reviewer answers the broad question twice and the precise finding
/// is diluted by the vague one sitting next to it.
const SUPERSEDES: &[(&str, &str)] = &[
    ("java-insecure-random", "java-weak-prng"),
    ("kt-insecure-random", "java-weak-prng"),
    // Both match at `MessageDigest`. The literal form names the algorithm in
    // its own match text, which is the more useful of two identical findings.
    ("java-weak-hash", "java-configured-weak-hash"),
    ("java-weak-cipher", "java-configured-weak-cipher"),
];

/// Remove a broad hit wherever the specific rule already fired at that offset.
fn drop_superseded(hits: &mut Vec<PatternHit>) {
    if hits.len() < 2 {
        return;
    }
    let specific: Vec<(usize, &str)> = hits
        .iter()
        .filter_map(|hit| {
            let id = SOURCE_RULES[hit.rule_index].id;
            SUPERSEDES
                .iter()
                .find(|(precise, _)| *precise == id)
                .map(|(_, broad)| (hit.offset, *broad))
        })
        .collect();
    if specific.is_empty() {
        return;
    }
    hits.retain(|hit| {
        let id = SOURCE_RULES[hit.rule_index].id;
        !specific
            .iter()
            .any(|(offset, broad)| *broad == id && *offset == hit.offset)
    });
}

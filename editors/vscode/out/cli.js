"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.supportsCacheDir = supportsCacheDir;
exports.scanArguments = scanArguments;
/**
 * Whether this oxaudit-cli accepts `scan --cache-dir`, read from its own
 * `scan --help` text. Asking the binary is exact: a version comparison would
 * have to guess which release introduced the flag, and would be wrong for a
 * build from source.
 */
function supportsCacheDir(scanHelp) {
    return /(^|\s)--cache-dir(\s|$)/m.test(scanHelp);
}
/**
 * The arguments for one workspace scan. `cacheDir` is passed only when the
 * caller established that the CLI accepts it: an older CLI treats an unknown
 * flag as a usage error and would not scan at all.
 */
function scanArguments(folder, cacheDir) {
    const args = ['scan', folder, '--format', 'json', '--quiet'];
    if (cacheDir) {
        args.push('--cache-dir', cacheDir);
    }
    return args;
}
//# sourceMappingURL=cli.js.map
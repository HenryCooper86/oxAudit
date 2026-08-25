<?php
// Never call eval($_GET['x']) here — it is remote code execution.
# Older style comment: exec($cmd) was removed in 2019.
/* shell_exec($cmd) is likewise forbidden. */

$POLICY = "Do not use eval() or system($cmd) in this codebase.";

function render(): string {
    return 'safe';
}

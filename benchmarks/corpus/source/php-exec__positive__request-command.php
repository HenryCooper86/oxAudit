<?php
function convert(array $request) {
    exec($request['file'], $output);
    return $output;
}

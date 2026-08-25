<?php
function render(array $request) {
    return eval($request['expr']);
}

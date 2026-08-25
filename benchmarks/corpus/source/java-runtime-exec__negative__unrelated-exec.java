class Reporting {
    // The rule anchors on a Runtime being acquired, not on the word appearing.
    // A RuntimeException nearby must not turn an unrelated exec into a
    // command-injection finding.
    void run(QueryEngine engine, String query) {
        try {
            engine.start();
        } catch (RuntimeException error) {
            engine.exec(query);
        }
    }
}

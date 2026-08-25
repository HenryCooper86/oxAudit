class Maintenance {
    void listing() throws Exception {
        // Every element is a literal, so the array is a constant. This needs
        // no naming convention to decide, unlike a SCREAMING_CASE field.
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(new String[] {"ls", "-la"});
    }
}

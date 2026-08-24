class Maintenance {
    void listing() throws Exception {
        // A fixed command with nothing interpolated has nothing to inject into.
        Runtime.getRuntime().exec("ls -la");
    }
}

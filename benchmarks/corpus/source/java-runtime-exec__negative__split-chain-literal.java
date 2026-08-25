class Maintenance {
    void listing() throws Exception {
        Runtime runtime = Runtime.getRuntime();
        runtime.exec("ls -la");
    }
}

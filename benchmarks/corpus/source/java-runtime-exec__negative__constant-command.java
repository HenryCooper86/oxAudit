class AdminDiagnostics {
    void status() throws Exception {
        Runtime.getRuntime().exec("/usr/bin/uptime");
    }
}

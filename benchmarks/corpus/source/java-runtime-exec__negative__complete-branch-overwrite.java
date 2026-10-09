class LocalCommand {
    void run(boolean useVersion, String input) throws Exception {
        String command = input;
        if (useVersion) command = "java -version";
        else command = "java --help";
        Runtime.getRuntime().exec(command);
    }
}

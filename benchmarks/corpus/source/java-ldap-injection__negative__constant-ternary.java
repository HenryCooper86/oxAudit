class LocalDirectory {
    void run(javax.naming.directory.DirContext context, String input) throws Exception {
        int window = 7;
        String filter = window * 3 == 21 ? "(uid=guest)" : input;
        context.search("ou=people", filter, new javax.naming.directory.SearchControls());
    }
}

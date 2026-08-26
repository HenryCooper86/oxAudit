class Cache {
    // Deliberately NOT reported: `update` on something that is not a JDBC
    // template is just a method called update.
    void refresh(Registry registry, String key) {
        registry.update(key + "-refreshed");
    }
}

class Lottery {
    int draw() throws Exception {
        return java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);
    }
}

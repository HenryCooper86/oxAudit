class Tokens {
    /*
     * Historical: this used Random() to build a session token, which is a
     * predictable generator. Replaced with SecureRandom in 2024.
     */
    private val generator = java.security.SecureRandom()

    fun newSessionToken(): String = generator.nextLong().toString(16)
}

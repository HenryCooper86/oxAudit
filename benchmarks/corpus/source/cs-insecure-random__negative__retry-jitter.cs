class Backoff {
    // Jitter spreads retries out; predicting it gains an attacker nothing.
    public int JitterMilliseconds() {
        var random = new Random();
        return random.Next(0, 250);
    }
}

class Lottery {
    int draw() {
        // No variable here is named like a secret, so the narrower
        // java-insecure-random rule stays quiet. That the generator is not
        // cryptographic is still true and still worth a person deciding.
        return new java.util.Random().nextInt(99);
    }
}

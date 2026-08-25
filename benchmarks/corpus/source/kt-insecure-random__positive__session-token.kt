import kotlin.random.Random

class Sessions {
    fun newSessionToken(): String {
        return Random.nextLong().toString(16)
    }
}

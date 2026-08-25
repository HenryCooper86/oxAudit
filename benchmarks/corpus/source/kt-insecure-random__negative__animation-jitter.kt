import kotlin.random.Random

class Shimmer {
    // Visual jitter on a loading placeholder; predicting it gains nothing.
    fun frameOffset(): Int = Random.nextInt(0, 16)
}

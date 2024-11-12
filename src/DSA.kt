import java.math.BigInteger
import java.security.SecureRandom

data class Keys(
    val p: BigInteger,
    val q: BigInteger,
    val g: BigInteger,
    val privateKey: BigInteger,
    val publicKey: BigInteger
)

object DSA {
    private val random = SecureRandom()

    // Генерация параметров DSA: p, q, g, privateKey, publicKey
    fun generateKeys(): Keys {
        val q = BigInteger.probablePrime(160, random)
        val p = BigInteger.probablePrime(1024, random).nextProbablePrime()
        val h = BigInteger.valueOf(2)
        val g = h.modPow((p - BigInteger.ONE) / q, p)

        // Приватный и публичный ключи
        val privateKey = BigInteger(q.bitLength(), random).mod(q) // Приватный ключ
        val publicKey = g.modPow(privateKey, p) // Публичный ключ

        return Keys(p, q, g, privateKey, publicKey)
    }

    // Подпись сообщения
    fun signMessage(
        message: ByteArray,
        p: BigInteger,
        q: BigInteger,
        g: BigInteger,
        privateKey: BigInteger
    ): Pair<BigInteger, BigInteger> {
        val hash = BigInteger(1, SHA256.computeHash(message))
        // println("hash = $hash")
        var r: BigInteger
        var s: BigInteger

        do {
            val k = BigInteger(q.bitLength(), random).mod(q) // Случайное значение k
            r = g.modPow(k, p).mod(q) // r = (g^k mod p) mod q
            s = k.modInverse(q).multiply(hash + privateKey.multiply(r)).mod(q) // s = k^(-1) * (h + privateKey * r) mod q
        } while (r == BigInteger.ZERO || s == BigInteger.ZERO) // Если r или s равны 0, то повторяем попытку

        println("r = $r, s = $s, hash = $hash")
        return Pair(r, s)
    }

    // Проверка подписи
    fun verifySignature(
        message: ByteArray,
        r: BigInteger,
        s: BigInteger,
        p: BigInteger,
        q: BigInteger,
        g: BigInteger,
        publicKey: BigInteger
    ): Boolean {
        if (r <= BigInteger.ZERO || r >= q || s <= BigInteger.ZERO || s >= q) return false // Подпись невалидна, если r или s находятся вне диапазона
        val hash = BigInteger(1, SHA256.computeHash(message))
        // println("hash = $hash")
        val w = try {
            s.modInverse(q)
        } catch (e: ArithmeticException) {
            println("Ошибка: Не удаётся вычислить обратное значение для s = $s по модулю q = $q")
            return false
        }
        val u1 = hash.multiply(w).mod(q)
        val u2 = r.multiply(w).mod(q)
        val v = (g.modPow(u1, p) * publicKey.modPow(u2, p)).mod(p).mod(q)
        println("r = $r, s = $s, hash = $hash, w = $w, u1 = $u1, u2 = $u2")
        println("v = $v, r = $r")
        return v == r
    }
}

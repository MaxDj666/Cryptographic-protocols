import java.math.BigInteger
import java.security.SecureRandom

class DSA {
    var q: BigInteger
    var p: BigInteger
    var g: BigInteger
    private var privateKey: BigInteger? = null
    var publicKey: BigInteger? = null
    private val random = SecureRandom()

    init {
        // Параметры p, q, g — большие простые числа. Они фиксированы для данной системы.
        q = BigInteger.probablePrime(160, random)  // Порядок подгруппы (160 битов)
        p = BigInteger.probablePrime(1024, random) // Модуль (1024 бита)
        g = BigInteger.valueOf(2).modPow((p.subtract(BigInteger.ONE)).divide(q), p) // Генератор g
    }

    // Генерация пары ключей (закрытого и открытого ключей)
    fun generateKeys() {
        privateKey = BigInteger(160, random).mod(q) // Закрытый ключ x < q
        publicKey = g.modPow(privateKey, p)                 // Открытый ключ y = g^x mod p
    }

    fun getPublicKey(): Pair<BigInteger, BigInteger> {
        return Pair(p, publicKey!!)
    }

    // Подписываем сообщение
    fun signMessage(message: ByteArray): Pair<BigInteger, BigInteger> {
        // Хэшируем сообщение с помощью SHA-256
        val messageHash = sha256(message)
        val h = BigInteger(1, messageHash)
        println("Хэш на стороне клиента: $h")

        // Генерация временного ключа k
        var k: BigInteger
        var r: BigInteger

        do {
            k = BigInteger(160, random).mod(q) // Случайное k < q
            r = g.modPow(k, p).mod(q)                  // r = (g^k mod p) mod q
        } while (r == BigInteger.ZERO)

        // s = (k^(-1) * (h + x * r)) mod q
        val s: BigInteger = k.modInverse(q).multiply(h.add(privateKey!!.multiply(r))).mod(q)
        return Pair(r, s)
    }

    // Проверка подписи
    fun verifySignature(message: ByteArray, r: BigInteger, s: BigInteger): Boolean {
        // Проверка, что 0 < r < q и 0 < s < q
        if (r <= BigInteger.ZERO || r >= q || s <= BigInteger.ZERO || s >= q) {
            return false
        }

        val messageHash = sha256(message) // Хэшируем сообщение с помощью SHA-256
        val h = BigInteger(1, messageHash)
        println("Хэш на стороне сервера: $h")

        // Вычисление w = s^(-1) mod q
        val w = s.modInverse(q)
        val u1 = h.multiply(w).mod(q) // u1 = h * w mod q
        val u2 = r.multiply(w).mod(q) // u2 = r * w mod q

        // v = ((g^u1 * y^u2) mod p) mod q
        val v = (g.modPow(u1, p).multiply(publicKey!!.modPow(u2, p)).mod(p)).mod(q)

        // Подпись верна, если v == r
        return v == r
    }

    private fun sha256(message: ByteArray): ByteArray {
        return SHA256().hash(message)
    }
}

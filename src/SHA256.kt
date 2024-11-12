import java.nio.ByteBuffer
import java.nio.ByteOrder

object SHA256 {
    // Инициализирующие константы (взяты из первых 32 битов дробных частей корней простых чисел)
    private val H = intArrayOf(
        0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
        0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19
    )

    // Константы (взяты из первых 32 битов дробных частей корней первых 64 простых чисел)
    private val K = intArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(), 0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 
        0xab1c5ed5.toInt(), 0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe.toInt(), 
        0x9bdc06a7.toInt(), 0xc19bf174.toInt(), 0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc, 
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 
        0xbf597fc7.toInt(), 0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 
        0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(), 0xa2bfe8a1.toInt(), 
        0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(), 0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 
        0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
        0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(), 0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt()
    )

    /*private fun padMessage(message: ByteArray): ByteArray {
        val messageLenBits = message.size * 8
        val paddingLength = (448 - (messageLenBits + 1) % 512 + 512) % 512
        val paddedMessage = ByteArray(message.size + paddingLength / 8 + 8)
        System.arraycopy(message, 0, paddedMessage, 0, message.size)
        paddedMessage[message.size] = 0x80.toByte()
        ByteBuffer.wrap(paddedMessage, paddedMessage.size - 8, 8).order(ByteOrder.BIG_ENDIAN).putLong(messageLenBits.toLong())
        return paddedMessage
    }*/

    private fun processBlock(block: ByteArray, hash: IntArray) {
        val w = IntArray(64)
        val buffer = ByteBuffer.wrap(block).order(ByteOrder.BIG_ENDIAN)
        for (i in 0..<16) w[i] = buffer.int
        for (i in 16..<64) {
            val s0 = Integer.rotateRight(w[i - 15], 7) xor Integer.rotateRight(w[i - 15], 18) xor (w[i - 15] ushr 3)
            val s1 = Integer.rotateRight(w[i - 2], 17) xor Integer.rotateRight(w[i - 2], 19) xor (w[i - 2] ushr 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        }
        var a = hash[0]
        var b = hash[1]
        var c = hash[2]
        var d = hash[3]
        var e = hash[4]
        var f = hash[5]
        var g = hash[6]
        var h = hash[7]
        for (i in 0..<64) {
            val s1 = Integer.rotateRight(e, 6) xor Integer.rotateRight(e, 11) xor Integer.rotateRight(e, 25)
            val ch = (e and f) xor (e.inv() and g)
            val temp1 = h + s1 + ch + K[i] + w[i]
            val s0 = Integer.rotateRight(a, 2) xor Integer.rotateRight(a, 13) xor Integer.rotateRight(a, 22)
            val maj = (a and b) xor (a and c) xor (b and c)
            val temp2 = s0 + maj
            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2
        }
        hash[0] += a
        hash[1] += b
        hash[2] += c
        hash[3] += d
        hash[4] += e
        hash[5] += f
        hash[6] += g
        hash[7] += h
    }

    fun computeHash(message: ByteArray): ByteArray {
        // Шаг 1: Подготовка padding и длины
        val messageLengthBits = message.size * 8
        val paddingLength = (64 - (message.size + 8) % 64) % 64
        val paddedMessage = ByteArray(message.size + paddingLength + 8)

        // Копируем исходное сообщение
        System.arraycopy(message, 0, paddedMessage, 0, message.size)

        // Добавляем бит '1' после сообщения
        paddedMessage[message.size] = 0x80.toByte()

        // Заполняем последние 8 байтов длиной исходного сообщения в битах
        for (i in 0..<8) {
            paddedMessage[paddedMessage.size - 1 - i] = (messageLengthBits shr (8 * i) and 0xFF).toByte()
        }

        // Шаг 2: Обработка блоков по 64 байта
        val hash = H.copyOf()
        val block = ByteArray(64)
        for (i in paddedMessage.indices step 64) {
            System.arraycopy(paddedMessage, i, block, 0, 64)
            processBlock(block, hash)
        }

        // Шаг 3: Возврат хэша
        val output = ByteBuffer.allocate(32)
        hash.forEach { output.putInt(it) }
        return output.array()
    }
}

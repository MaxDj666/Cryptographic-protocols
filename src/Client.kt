import java.io.*
import java.net.Socket
import java.math.BigInteger
import java.security.SecureRandom

fun main() {
    val serverAddress = "localhost"
    val port = 9999

    try {
        val socket = Socket(serverAddress, port)
        println("Подключено к серверу по адресу $serverAddress:$port")

        val input = BufferedReader(InputStreamReader(socket.getInputStream()))
        val output = PrintWriter(socket.getOutputStream(), true)

        // Приём публичного ключа от сервера
        val publicEHex = input.readLine()
        val publicNHex = input.readLine()
        if (publicEHex == null || publicNHex == null) {
            println("Не удалось получить публичный ключ от сервера.")
            socket.close()
            return
        }
        println("Получен публичный ключ от сервера.")
        val publicE = BigInteger(publicEHex, 16)
        val publicN = BigInteger(publicNHex, 16)
        val publicKey = Pair(publicE, publicN)
        println("Публичный ключ (e): $publicE")
        println("Публичный ключ (n): $publicN")

        // Генерация ключей DSA
        val (params, keys) = DSA.generateKeys()
        val (p, q) = params
        val (g, y) = keys
        val x = BigInteger(160, SecureRandom()).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE) // Приватный ключ
        println("""
            p = $p
            q = $q
            g = $g
            y = $y
        """.trimIndent())

        // Отправка параметров p, q, g и y серверу
        output.println(p.toString(16)) // Отправляем p
        output.println(q.toString(16)) // Отправляем q
        output.println(g.toString(16)) // Отправляем g
        output.println(y.toString(16)) // Отправляем y

        // Инициализация RSA и DES
        val rsa = RSA()
        val des = DES()

        while (true) {
            // Ввод сообщения пользователем
            val message: String = getUserInput().trim()

            if (message.equals("quit", ignoreCase = true)) {
                println("Завершение работы клиента.")
                break
            }

            // Проверка, что сообщение не пустое
            if (message.isEmpty()) {
                println("Ошибка: сообщение не должно быть пустым. Попробуйте ещё раз.")
                continue
            }

            // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
            val desKeyHex = generateRandomHexString(16)
            println("Сгенерированный ключ DES: $desKeyHex")

            // Шифрование ключа DES с помощью публичного ключа RSA сервера
            val desKeyBigInt = BigInteger(desKeyHex, 16)
            val encryptedDesKey = rsa.encrypt(desKeyBigInt, publicKey)
            val encryptedDesKeyHex = encryptedDesKey.toString(16)
            println("Зашифрованный ключ DES (hex): $encryptedDesKeyHex")

            // Шифрование сообщения с помощью DES в режиме ECB
            val encryptedMessageECB = des.ecbEncrypt(message, desKeyHex)
            println("Зашифрованное сообщение (ECB, hex): $encryptedMessageECB")

            // Создаем цифровую подпись для сообщения
            val (r, s) = DSA.signMessage(message.toByteArray(Charsets.UTF_8), p, q, g, x)
            val rHex = r.toString(16)
            val sHex = s.toString(16)

            // Отправка на сервер
            output.println(encryptedDesKeyHex)
            output.println(encryptedMessageECB)
            output.println(rHex)
            output.println(sHex)
            println("Отправлено зашифрованное сообщение на сервер.\n")
        }

        // Закрытие соединения
        socket.close()
        println("Соединение закрыто.")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}

/**
 * Функция для получения ввода пользователя с проверкой длины.
 * Максимальная длина сообщения: произвольная, но делится на 8 символов.
 */
fun getUserInput(): String {
    println("Введите сообщение (любая длина) или 'quit' для выхода:")
    val input = readlnOrNull()?.trim() ?: ""
    return input
}

/**
 * Генерация случайной шестнадцатеричной строки заданной длины.
 */
fun generateRandomHexString(length: Int): String {
    val chars = "0123456789ABCDEF"
    val rnd = SecureRandom()
    return (1..length)
        .map { chars[rnd.nextInt(chars.length)] }
        .joinToString("")
}

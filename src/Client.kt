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

        // Инициализация RSA и DES
        val rsa = RSA()
        val des = DES()

        while (true) {
            // Ввод сообщения пользователем
            val message: String = getUserInput()

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

            // Отправка зашифрованного ключа DES и зашифрованного сообщения на сервер
            output.println(encryptedDesKeyHex)
            output.println(encryptedMessageECB)
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

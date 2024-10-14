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

        // Ввод сообщения пользователем
        val message: String = getUserInput()

        // Преобразование сообщения в шестнадцатеричный формат
        val des = DES()
        val messageHex = des.asciiToHex(message)
        // Дополнение сообщения до 16 шестнадцатеричных символов (8 байт)
        val paddedMessageHex = messageHex.padEnd(16, '0')
        println("Сообщение в шестнадцатеричном виде: $paddedMessageHex")

        // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
        val desKeyHex = generateRandomHexString(16)
        println("Сгенерированный ключ DES: $desKeyHex")

        // Шифрование ключа DES с помощью публичного ключа RSA сервера
        val desKeyBigInt = BigInteger(desKeyHex, 16)
        val rsa = RSA()
        val encryptedDesKey = rsa.encrypt(desKeyBigInt, publicKey)
        val encryptedDesKeyHex = encryptedDesKey.toString(16)
        println("Зашифрованный ключ DES (hex): $encryptedDesKeyHex")

        // Шифрование сообщения с помощью DES
        val encryptedMessageHex = des.encrypt(paddedMessageHex, desKeyHex)
        println("Зашифрованное сообщение (hex): $encryptedMessageHex")

        // Отправка зашифрованного ключа DES и зашифрованного сообщения на сервер
        output.println(encryptedDesKeyHex)
        output.println(encryptedMessageHex)
        println("Отправлены зашифрованный ключ DES и зашифрованное сообщение на сервер.")

        // Закрытие соединения
        socket.close()
        println("Соединение закрыто.")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}

/**
 * Функция для получения ввода пользователя с проверкой длины.
 * Максимальная длина сообщения: 8 символов.
 */
fun getUserInput(): String {
    while (true) {
        println("Введите сообщение (максимум 8 символов):")
        val input = readlnOrNull()

        if (input == null) {
            println("Ошибка чтения ввода. Попробуйте ещё раз.")
            continue
        }

        if (input.length > 8) {
            println("Ошибка: сообщение должно содержать не более 8 символов. Попробуйте ещё раз.")
            continue
        }

        // Дополнение сообщения пробелами до 8 символов, если необходимо
        return input.padEnd(8, ' ')
    }
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

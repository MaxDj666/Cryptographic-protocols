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

        // Подготовка сообщения
        val message = "Hello!!!" // Должно быть не более 8 символов (64 бита)
        val des = DES()
        val messageHex = des.asciiToHex(message)
        if (messageHex.length > 16) {
            println("Сообщение слишком длинное для одного блока DES (максимум 8 символов).")
            socket.close()
            return
        }
        // Дополнение сообщения до 16 шестнадцатеричных символов
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

// Генерация случайной шестнадцатеричной строки заданной длины
fun generateRandomHexString(length: Int): String {
    val chars = "0123456789ABCDEF"
    val rnd = SecureRandom()
    return (1..length)
        .map { chars[rnd.nextInt(chars.length)] }
        .joinToString("")
}

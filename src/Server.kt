import java.io.*
import java.net.ServerSocket
import java.math.BigInteger

fun main() {
    val port = 9999
    val serverSocket = ServerSocket(port)
    println("Сервер запущен и слушает порт $port")

    while (true) {
        val clientSocket = serverSocket.accept()
        println("Клиент подключился: ${clientSocket.inetAddress.hostAddress}")

        // Обработка клиента в отдельном потоке
        Thread {
            try {
                val input = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val output = PrintWriter(clientSocket.getOutputStream(), true)

                // Инициализация RSA
                val rsa = RSA()

                // Отправка публичного ключа клиенту (e и n в шестнадцатеричном формате)
                val publicEHex = rsa.publicKey.first.toString(16)
                val publicNHex = rsa.publicKey.second.toString(16)
                output.println(publicEHex)
                output.println(publicNHex)
                println("Отправлен публичный ключ клиенту.")

                // Приём зашифрованного ключа DES
                val encryptedDesKeyHex = input.readLine()
                if (encryptedDesKeyHex == null) {
                    println("Клиент отключился до отправки ключа DES.")
                    clientSocket.close()
                    return@Thread
                }
                println("Получен зашифрованный ключ DES: $encryptedDesKeyHex")

                // Приём зашифрованного сообщения
                val encryptedMessageHex = input.readLine()
                if (encryptedMessageHex == null) {
                    println("Клиент отключился до отправки сообщения.")
                    clientSocket.close()
                    return@Thread
                }
                println("Получено зашифрованное сообщение: $encryptedMessageHex")

                // Расшифровка ключа DES с помощью приватного ключа RSA
                val encryptedDesKey = BigInteger(encryptedDesKeyHex, 16)
                val decryptedDesKeyBigInt = rsa.decrypt(encryptedDesKey)
                var decryptedDesKeyHex = decryptedDesKeyBigInt.toString(16)

                // Убедимся, что ключ DES имеет 16 шестнадцатеричных символов (64 бита)
                decryptedDesKeyHex = decryptedDesKeyHex.padStart(16, '0')
                println("Расшифрованный ключ DES: $decryptedDesKeyHex")

                // Расшифровка сообщения с помощью DES
                val des = DES()
                val decryptedMessageHex = des.decrypt(encryptedMessageHex, decryptedDesKeyHex)
                val decryptedMessage = des.hexToASCII(decryptedMessageHex)
                println("Расшифрованное сообщение: $decryptedMessage")

                // Закрытие соединения
                clientSocket.close()
                println("Соединение с клиентом закрыто.\n")

            } catch (e: Exception) {
                e.printStackTrace()
                clientSocket.close()
            }
        }.start()
    }
}

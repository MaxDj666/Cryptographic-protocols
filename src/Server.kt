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

                // Инициализация RSA и DES
                val rsa = RSA()
                val des = DES()

                // Отправка публичного ключа клиенту (e и n в шестнадцатеричном формате)
                val publicEHex = rsa.publicKey.first.toString(16)
                val publicNHex = rsa.publicKey.second.toString(16)
                output.println(publicEHex)
                output.println(publicNHex)
                println("Отправлен публичный ключ клиенту.")

                // Приём параметров p, q, g и dsaPublicKey от клиента
                val pHex = input.readLine()
                val qHex = input.readLine()
                val gHex = input.readLine()
                val dsaPublicKeyHex = input.readLine()

                val p = BigInteger(pHex, 16)
                val q = BigInteger(qHex, 16)
                val g = BigInteger(gHex, 16)
                val dsaPublicKey = BigInteger(dsaPublicKeyHex, 16)
                println("""
                    p = $p
                    q = $q
                    g = $g
                    dsaPublicKey = $dsaPublicKey
                """.trimIndent())

                while (true) {
                    // Приём зашифрованного ключа DES
                    val encryptedDesKeyHex = input.readLine()
                    if (encryptedDesKeyHex == null) {
                        println("Клиент отключился.")
                        break
                    }
                    println("Получен зашифрованный ключ DES: $encryptedDesKeyHex")

                    // Приём зашифрованного сообщения
                    val encryptedMessageHex = input.readLine()
                    if (encryptedMessageHex == null) {
                        println("Клиент отключился до отправки сообщения.")
                        break
                    }
                    println("Получено зашифрованное сообщение: $encryptedMessageHex")

                    // Приём подписи
                    val rHex = input.readLine() ?: break
                    val sHex = input.readLine() ?: break

                    // Расшифровка ключа DES с помощью приватного ключа RSA
                    val encryptedDesKey = BigInteger(encryptedDesKeyHex, 16)
                    val decryptedDesKeyBigInt = rsa.decrypt(encryptedDesKey)
                    var decryptedDesKeyHex = decryptedDesKeyBigInt.toString(16)

                    // Убедимся, что ключ DES имеет 16 шестнадцатеричных символов (64 бита)
                    decryptedDesKeyHex = decryptedDesKeyHex.padStart(16, '0')
                    println("Расшифрованный ключ DES: $decryptedDesKeyHex")

                    // Расшифровка сообщения с помощью DES в режиме ECB
                    val decryptedMessage = des.ecbDecrypt(encryptedMessageHex, decryptedDesKeyHex)
                    println("Расшифрованное сообщение: $decryptedMessage")

                    val r = BigInteger(rHex, 16)
                    val s = BigInteger(sHex, 16)

                    // Проверка цифровой подписи
                    val isValidSignature = DSA.verifySignature(
                        decryptedMessage.trim().toByteArray(Charsets.UTF_8), r, s, p, q, g, dsaPublicKey
                    )

                    if (isValidSignature) {
                        println("Подпись верна.")
                    } else {
                        println("Ошибка проверки подписи!")
                    }
                }

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

import com.google.gson.Gson
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type
import java.io.File
import java.security.MessageDigest

val gson = Gson()

fun main(args: Array<String>) {
    val command = args[0]
    when (command) {
        "info" -> {
            val torrentFile = args[1]
            decodeTorrentFile(torrentFile)
        }
        "decode" -> {
            val bencodedValue = args[1]
            val decoded = decodeBencode(bencodedValue)
            println(gson.toJson(decoded))
            return
        }
        else -> println("Unknown command $command")
    }
}

fun decodeTorrentFile(torrentFile: String) {
    val fileBytes = File(torrentFile).readBytes()
    val bencode = Bencode()
    val torrentData = bencode.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>
    val url = torrentData["announce"]
    val info = torrentData["info"] as Map<*, *>

    val encoded:ByteArray = bencode.encode(info)
    val infoData = bencode.decode(encoded, Type.DICTIONARY) as Map<String, Any>
    val json = gson.toJson(infoData)

    val bytes = MessageDigest.getInstance("SHA-1").digest(json.toByteArray())
    val result = StringBuilder(bytes.size * 2)
    val HEX_CHARS = "0123456789abcdef"
    bytes.forEach {
        val i = it.toInt()
        result.append(HEX_CHARS[i shr 4 and 0x0f])
        result.append(HEX_CHARS[i and 0x0f])
    }
    val length = info["length"]

    println("Tracker URL: $url")
    println("Length: $length")
    println("Info Hash: $result")
}
fun decodeBencode(benCodedValue: String): Any {
    val bencode = Bencode()
    return when {
        benCodedValue[0].isDigit() -> bencode.decode(benCodedValue.toByteArray(), Type.STRING)
        benCodedValue[0] == 'i' -> bencode.decode(benCodedValue.toByteArray(), Type.NUMBER)
        benCodedValue[0] == 'l' -> bencode.decode(benCodedValue.toByteArray(), Type.LIST)
        benCodedValue[0] == 'd' -> bencode.decode(benCodedValue.toByteArray(), Type.DICTIONARY)
        else -> return ""
    }
}

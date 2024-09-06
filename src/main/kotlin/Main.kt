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
    //Decode the non UTF-16 data normally
    val bencode = Bencode(false)
    val torrentData = bencode.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>
    val url = torrentData["announce"]
    val info = torrentData["info"] as Map<*, *>
    val length = info["length"]

    //We need to preserve UTF-16 for the info section.
    val bencode2 = Bencode(true)
    val infoData = bencode2.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>
    val map = infoData["info"] as Map<*, *>
    val encodedInfo = bencode2.encode(map)

    //Calculate the SHA-1
    val digest = MessageDigest.getInstance("SHA-1")
    val bytes = digest.digest(encodedInfo)
    val result = StringBuilder(bytes.size * 2)
    val HEX_CHARS = "0123456789abcdef"
    bytes.forEach {
        val i = it.toInt()
        result.append(HEX_CHARS[i shr 4 and 0x0f])
        result.append(HEX_CHARS[i and 0x0f])
    }

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

import com.google.gson.Gson
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type
import java.io.File
import java.nio.ByteBuffer
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
    val pieceLength = info["piece length"]
    val pieces = info["pieces"]
    val charset = Charsets.UTF_8
    //val test = charset.decode(pieces as ByteBuffer).toString()
    //printMap(torrentData)

    //We need to preserve UTF-16 for the info section.
    val bencode2 = Bencode(true)
    val infoData = bencode2.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>

    val map = infoData["info"] as Map<*, *>

    var index = 0
    val list = mutableListOf<String>()

    val buffer = map["pieces"] as ByteBuffer

    val byteArray = buffer.array()
    val string = byteArray.toHexString()
    println(string)
    while ((index * 20) + 20 <= byteArray.size) {
        val chunk = byteArray.sliceArray(index * 20..<(index * 20) + 20)
        list.add(chunk.toHexString())
        index += 1
    }

    val encodedInfo = bencode2.encode(map)
    val digest = MessageDigest.getInstance("SHA-1")
    val bytes = digest.digest(encodedInfo)
    val result = myHexString(bytes)

    println("Tracker URL: $url")
    println("Length: $length")
    println("Info Hash: $result")
    println("Piece Length: $pieceLength")
    println("Piece Hashes: \n${list.joinToString(separator = "\n")}")
}

fun myHexString(bytes:ByteArray): String {
    val result = StringBuilder(bytes.size * 2)
    val HEX_CHARS = "0123456789abcdef"
    bytes.forEach {
        val i = it.toInt()
        result.append(HEX_CHARS[i shr 4 and 0x0f])
        result.append(HEX_CHARS[i and 0x0f])
    }
    return result.toString()
}

fun ByteArray.toHexString(): String {
    return if (this.size > 20) {
        "ByteArray(${this.size} bytes)"
    } else {
        this.joinToString("") { "%02x".format(it) }
    }
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

import com.google.gson.Gson
import java.math.BigInteger
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type
import java.io.File
import java.io.FileInputStream
val gson = Gson()

fun main(args: Array<String>) {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    //println("Logs from your program will appear here!")
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
    val torrentData = bencode.decode(fileBytes, Type.DICTIONARY)
    val url = torrentData["announce"]
    val info = torrentData["info"] as MutableMap<*, *>
    val length = info["length"]

    println("Tracker URL: $url")
    println("Length: $length")
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

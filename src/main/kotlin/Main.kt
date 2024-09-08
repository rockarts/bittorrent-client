import com.google.gson.Gson
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.PrintWriter
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.net.URLEncoder

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
        "peers" -> {
            val torrentFile = args[1]
            val info = decodeTorrentFile(torrentFile, true)
            getPeers(info)
        }
        "handshake" -> {
            val torrentFile = args[1]
            val peer = args[2]
            val info = decodeTorrentFile(torrentFile, true)
            val infoHash = info.get("info_hash").toString()

            val address = peer.split(":")
            val host = address[0]
            val port = address[1].toInt()

            val peers = mutableListOf<String>() //getPeers(info)
            performHandshake(peers, host, port, infoHash)
        }
        else -> println("Unknown command $command")
    }
}

fun performHandshake(peers: MutableList<String>, host:String, port:Int, infoHash:String) {
//    val firstPeer = peers[0]
//    val address = firstPeer.split(":")
//    val host = address[0]
//    val port = address[1].toInt()
    val socket = Socket(host, port)
    val outputStream = DataOutputStream(socket.getOutputStream())
    val inputStream = DataInputStream(socket.getInputStream())
    try {
        val protocolName = "BitTorrent protocol"
        val reserved = ByteArray(8) // 8 reserved bytes, all set to 0
        // Convert infoHash and peerId from hex string to ByteArray
        val infoHashBytes = infoHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val peerId = "00112233445566778899"
        val peerIdBytes = peerId.toByteArray()

        outputStream.writeByte(19)
        outputStream.write(protocolName.toByteArray())
        outputStream.write(reserved)
        outputStream.write(infoHashBytes)
        outputStream.write(peerIdBytes)

        outputStream.flush()

        // Receive handshake response
        val responsePstrlen = inputStream.readByte().toInt()
        if (responsePstrlen != 19) {
            throw Exception("Invalid pstrlen in response: $responsePstrlen")
        }

        val responsePstr = ByteArray(19)
        inputStream.readFully(responsePstr)
        val responseProtocol = String(responsePstr)
        if (responseProtocol != protocolName) {
            throw Exception("Invalid protocol in response: $responseProtocol")
        }

        val responseReserved = ByteArray(8)
        inputStream.readFully(responseReserved)

        val responseInfoHash = ByteArray(20)
        inputStream.readFully(responseInfoHash)
        if (!responseInfoHash.contentEquals(infoHashBytes)) {
            throw Exception("Info hash mismatch in response")
        }

        val responsePeerId = ByteArray(20)
        inputStream.readFully(responsePeerId)

        //println("BitTorrent handshake response received successfully")
        println("Peer ID: ${responsePeerId.joinToString("") { "%02x".format(it) }}")

    } finally {
        socket.close()
    }
}

fun decodeTorrentFile(torrentFile: String, supressOutput:Boolean = false): Map<String, Any> {
    val fileBytes = File(torrentFile).readBytes()
    //Decode the non UTF-16 data normally
    val bencode = Bencode(false)
    val torrentData = bencode.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>
    val url = torrentData["announce"]
    val info = torrentData["info"] as Map<*, *>
    val length = info["length"]
    val pieceLength = info["piece length"]

    //We need to preserve UTF-16 for the info section.
    val bencode2 = Bencode(true)
    val infoData = bencode2.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>

    val map = infoData["info"] as Map<*, *>

    var index = 0
    val list = mutableListOf<String>()
    val buffer = map["pieces"] as ByteBuffer
    val byteArray = buffer.array()
    while ((index * 20) + 20 <= byteArray.size) {
        val chunk = byteArray.sliceArray(index * 20..<(index * 20) + 20)
        list.add(chunk.toHexString())
        index += 1
    }

    val encodedInfo = bencode2.encode(map)
    val digest = MessageDigest.getInstance("SHA-1")
    val bytes = digest.digest(encodedInfo)
    val result = bytes.toHexString()

    if (!supressOutput) {
        println("Tracker URL: $url")
        println("Length: $length")
        println("Info Hash: $result")
        println("Piece Length: $pieceLength")
        println("Piece Hashes: \n${list.joinToString(separator = "\n")}")
    }
    var params = mutableMapOf<String, Any>()
    params["url"] = url as Any
    params["length"] = length as Any
    params["info_hash"] = result as Any
    return params
}

fun getPeers(torrentInfo: Map<String, Any>): MutableList<String> {
    val bencode = Bencode(true)
    var params = mutableMapOf<String, String>()
    params["peer_id"] = "00112233445566778899"
    params["port"] = "6881"
    params["uploaded"] = "0"
    params["downloaded"] = "0"
    params["left"] = (torrentInfo["length"] as? Long)?.toString() ?: "0"//Length field
    params["compact"] = "1"

    val url = torrentInfo["url"].toString()
    val getResult = getRequestWithHttpURLConnection(url, params, customUrlEncode(torrentInfo["info_hash"].toString()))
    val response = bencode.decode(getResult, Type.DICTIONARY) as Map<String, Any>
    val peersByteBuffer = response["peers"] as ByteBuffer
    val peersByteArray = ByteArray(peersByteBuffer.remaining())
    peersByteBuffer.get(peersByteArray)
    return processPeerByteArray(peersByteArray)
}

fun customUrlEncode(input: String): String {
    // Creating a ByteArray with half the length of the input
    // string (since each byte is represented by two hex characters).
    val bytes = ByteArray(input.length / 2) {
        ((Character.digit(input[it * 2], 16) shl 4) +
                Character.digit(input[it * 2 + 1], 16)).toByte()
    }

    // URL encode each byte
    return bytes.joinToString("") { byte ->
        "%" + String.format("%02x", byte.toInt() and 0xFF)
    }
}

fun processPeerByteArray(peerData: ByteArray): MutableList<String> {
    val peers = mutableListOf<String>()

    for (i in peerData.indices step 6) {
        if (i + 5 < peerData.size) {
            val ip = "${peerData[i].toUByte()}.${peerData[i+1].toUByte()}.${peerData[i+2].toUByte()}.${peerData[i+3].toUByte()}"
            val port = (peerData[i+4].toInt() and 0xFF) * 256 + (peerData[i+5].toInt() and 0xFF)
            peers.add("$ip:$port")
        }
    }

    peers.forEachIndexed { index, peer ->
        println(peer)
    }

    return peers
}

fun printMap(infoData:Map<*,*>) {
    for ((key, value) in infoData) {
        val formattedValue = when (value) {
            is String -> "\"$value\""
            is Number -> value.toString()
            is List<*> -> value.joinToString(", ", "[", "]")
            is Map<*, *> -> "{...}" // You might want to recurse here for nested maps
            else -> value.toString()
        }
        println("Key: $key, Value: $formattedValue")
    }
}

fun getRequestWithHttpURLConnection(baseUrl: String, params:Map<String,String>, infoHash:String): ByteArray {
    val query = params.map { (k, v) -> "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}" }
        .joinToString("&")
    var urlString = if (query.isNotEmpty()) "$baseUrl?$query" else baseUrl
    urlString += "&info_hash=${infoHash}"
    val url = URL(urlString)
    val connection = url.openConnection() as HttpURLConnection
    try {
        connection.requestMethod = "GET"
        connection.connectTimeout = 5000
        connection.readTimeout = 5000

        val responseCode = connection.responseCode
        if (responseCode == HttpURLConnection.HTTP_OK) {
            val responseBody = connection.inputStream.readBytes()
            //println(responseBody.toString(Charsets.UTF_8))
            return responseBody
        } else {
            throw Exception("HTTP GET request failed with response code: $responseCode")
        }
    } finally {
        connection.disconnect()
    }
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

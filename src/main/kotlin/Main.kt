import com.google.gson.Gson
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentLinkedQueue

val gson = Gson()

/*
Optional: To improve download speeds, you can download from multiple peers at once.
You could have a work queue consisting of each piece that needs to be downloaded.
Your worker (connection with a peer) could pick a piece from the work queue, attempt to download it,
check the integrity, and write the downloaded piece into a buffer.
Any failure (network issue, hashes not matching, peer not having the piece etc.) would put the piece
back into the work queue to be tried again.
 */


fun main(args: Array<String>) {
    val command = args[0]
    when (command) {
        "info" -> {
            // ./your_bittorrent.sh info sample.torrent
            val torrentFile = args[1]
            decodeTorrentFile(torrentFile)
        }
        "decode" -> {
            // ./your_bittorrent.sh decode d3:foo3:bar5:helloi52ee
            val bencodedValue = args[1]
            val decoded = decodeBencode(bencodedValue)
            println(gson.toJson(decoded))
            return
        }
        "peers" -> {
            //./your_bittorrent.sh handshake sample.torrent 161.35.47.237:51419
            val torrentFile = args[1]
            val info = decodeTorrentFile(torrentFile, true)
            getPeers(info)
        }
        "handshake" -> {
            // ./your_bittorrent.sh handshake sample.torrent <peer_ip>:<peer_port>
            val torrentFile = args[1]
            val peer = args[2]
            val torrent = decodeTorrentFile(torrentFile, true)

            val address = peer.split(":")
            val host = address[0]
            val port = address[1].toInt()

            val peers = mutableListOf<String>() //getPeers(info)
            performHandshake(peers, host, port, torrent)
        }
        "download_piece" -> {
            // ./your_bittorrent.sh download_piece -o /tmp/test-piece-0 sample.torrent 0
            val outputLocation = args[2]
            val torrentFile = args[3]
            val piece = args[4]
            downloadPiece(torrentFile, outputLocation, piece)
        }
        "download" -> {
            val outputLocation = args[2]
            val torrentFile = args[3]
            download(outputLocation, torrentFile)
        }
        "magnet_parse" -> {
            //magnet:?xt=urn:btih:d69f91e6b2ae4c542468d1073a71d4ea13879a7f&dn=sample.torrent&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
            val link = args[1]
            magnetParse(link)
        }
        else -> println("Unknown command $command")
    }
}

fun magnetParse(link: String) {
    val removed = link.removePrefix("magnet:?")
    val params = removed.split("&")

    var hash = ""
    var trackerUrl = ""

    for (param in params) {
        if (param.startsWith("xt=urn:btih:")) {
            hash = param.removePrefix("xt=urn:btih:")
        }

        if (param.startsWith("tr=")) {
            trackerUrl = URLDecoder.decode( param.removePrefix("tr="), StandardCharsets.UTF_8.toString())
        }
    }
    //Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
    //Info Hash: d69f91e6b2ae4c542468d1073a71d4ea13879a7f
    println("Tracker URL: $trackerUrl")
    println("Info Hash: $hash")
}

fun download(outputLocation: String, torrentFileLocation: String) {
    val torrentFile = decodeTorrentFile(torrentFileLocation)
    val peers = getPeers(torrentFile)
    val peer = peers[0]
    println("PEER $peer")
    val address = peers[0].split(":")
    val host = address[0]
    val port = address[1].toInt()
    val socket = Socket(host, port)

    val outputStream = DataOutputStream(socket.getOutputStream())
    val inputStream = DataInputStream(socket.getInputStream())

    socket.use { _ ->
        val peerId = performHandshake(outputStream, inputStream, torrentFile)
        println("Peer ID: $peerId")

        var bitfieldReceived = false
        val totalLength = torrentFile.length
        val pieceLength = torrentFile.pieceLength
        val pieces = torrentFile.pieceHashes.size

        //Initialize a workQueue
        val workQueue = ConcurrentLinkedQueue<Int>()
        for (i in 0 until pieces) {
            workQueue.offer(i)
        }

        val allPieces = mutableListOf<ByteArray>()
        while (true) {
            val messageLength = inputStream.readInt()
            if (messageLength > 0) {
                val messageId = inputStream.readByte().toInt()

                when (messageId) {
                    5 -> { // Bitfield
                        val payload = ByteArray(messageLength - 1)
                        inputStream.readFully(payload)
                        bitfieldReceived = true
                        println("Received: Bitfield message")
                        sendInterestedMessage(outputStream)
                    }
                    1 -> { // Unchoke
                        println("Received: Unchoke message")
                        if (bitfieldReceived) {
                            var pieceIndex = 0
                            while (pieceIndex < pieces) {
                                val pieceData = downloadPiece(pieceIndex, pieceLength, totalLength, outputStream, inputStream)
                                if (verifyPiece(pieceData, torrentFile.pieceHashes, pieceIndex)) {
                                    allPieces.add(pieceData)
                                    println("Piece $pieceIndex downloaded and verified.")
                                    pieceIndex++
                                } else {
                                    println("Piece $pieceIndex verification failed. Retrying...")
                                    // No need to decrement pieceIndex, it will retry the same piece
                                }
                            }
                            break // Exit the loop after downloading all pieces
                        }
                    }
                    else -> {
                        val payload = ByteArray(messageLength - 1)
                        inputStream.readFully(payload)
                    }
                }
            }
        }

        // Combine all pieces and write to the output file
        val fullFile = allPieces.reduce { acc, bytes -> acc + bytes }
        File(outputLocation).writeBytes(fullFile)
        println("Downloaded ${torrentFileLocation.split("/").last()} to $outputLocation.")
    }
}

fun downloadPiece(pieceIndex: Int, standardPieceLength: Long, totalLength: Long, outputStream: DataOutputStream, inputStream: DataInputStream): ByteArray {
    val pieceLength = if (pieceIndex == (totalLength / standardPieceLength).toInt()) {
        totalLength % standardPieceLength
    } else {
        standardPieceLength
    }

    val blocks = mutableListOf<ByteArray>()

    requestBlocks(outputStream, pieceIndex, pieceLength)

    while (blocks.sumOf { it.size.toLong() } < pieceLength) {
        val messageLength = inputStream.readInt()
        if (messageLength > 0) {
            val messageId = inputStream.readByte().toInt()
            if (messageId == 7) { // Piece
                val index = inputStream.readInt()
                val begin = inputStream.readInt()
                val blockLength = messageLength - 9
                val block = ByteArray(blockLength)
                inputStream.readFully(block)
                blocks.add(block)
            }
        }
    }

    return blocks.reduce { acc, bytes -> acc + bytes }
}

fun verifyPiece(pieceData: ByteArray, pieceHashes: List<String>, pieceIndex: Int): Boolean {
    val digest = MessageDigest.getInstance("SHA-1")
    val calculatedHash = digest.digest(pieceData).toHexString()
    return calculatedHash == pieceHashes[pieceIndex]
}

fun performHandshake(outputStream: DataOutputStream, inputStream: DataInputStream, torrentFile: TorrentFile): String {
    val protocolName = "BitTorrent protocol"
    val reserved = ByteArray(8) // 8 reserved bytes, all set to 0
    val infoHashBytes = torrentFile.infoHashBytes()
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

    return responsePeerId.joinToString("") { "%02x".format(it) }
}

fun downloadPiece(torrentFile: String, outputLocation: String, pieceIndex: String) {
    //Wait for a bitfield message from the peer indicating which pieces it has
    //Send an interested message
    //Wait until you receive an unchoke message back
    //Break the piece into blocks of 16 kiB (16 * 1024 bytes)
    //and send a request message for each block

    //Read the torrent file to get the tracker URL
    //val torrentFile = args[1]
    val info = decodeTorrentFile(torrentFile)
    //Perform the tracker GET request to get a list of peers
    val peers = getPeers(info)
    val address = peers[0].split(":")
    val host = address[0]
    val port = address[1].toInt()
    val socket = Socket(host, port)
    val infoHash = info.infoHash

    val outputStream = DataOutputStream(socket.getOutputStream())
    val inputStream = DataInputStream(socket.getInputStream())

    try {
        val protocolName = "BitTorrent protocol"
        val reserved = ByteArray(8) // 8 reserved bytes, all set to 0
        // Convert infoHash and peerId from hex string to ByteArray
        val infoHashBytes = infoHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val peerId = "00112233445566778899"
        val peerIdBytes = peerId.toByteArray()

        //Send Handshake
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

        println("Peer ID: ${responsePeerId.joinToString("") { "%02x".format(it) }}")

        var bitfieldReceived = false
        val pieceLength = calculatePieceLength(info, pieceIndex.toInt())
        val blocks = mutableListOf<ByteArray>()

        while (true) {
            val messageLength = inputStream.readInt()
            if (messageLength > 0) {
                val messageId = inputStream.readByte().toInt()

                when (messageId) {
                    5 -> { // Bitfield
                        val payload = ByteArray(messageLength - 1)
                        inputStream.readFully(payload)
                        bitfieldReceived = true
                        println("Received: Bitfield message")
                        sendInterestedMessage(outputStream)
                    }
                    1 -> { // Unchoke
                        println("Received: Unchoke message")
                        if (bitfieldReceived) {
                            requestBlocks(outputStream, pieceIndex.toInt(), pieceLength)
                        }
                    }
                    7 -> { // Piece
                        val index = inputStream.readInt()
                        val begin = inputStream.readInt()
                        val blockLength = messageLength - 9
                        val block = ByteArray(blockLength)
                        inputStream.readFully(block)

                        println("Received block: index=$index, begin=$begin, length=$blockLength")
                        blocks.add(block)

                        if (blocks.sumOf { it.size } >= pieceLength) {
                            val pieceData = blocks.reduce { acc, bytes -> acc + bytes }
                            File(outputLocation).writeBytes(pieceData)
                            println("Piece $pieceIndex downloaded to $outputLocation.")
                            return
                        }
                    }
                    else -> {
                        val payload = ByteArray(messageLength - 1)
                        inputStream.readFully(payload)
                    }
                }
            }
        }
        } finally {
            socket.close()
        }
}

fun requestBlocks(outputStream: DataOutputStream, pieceIndex: Int, pieceLength: Long) {
    var begin = 0L
    while (begin < pieceLength) {
        val blockSize = minOf(16384L, pieceLength - begin)
        outputStream.writeInt(13)
        outputStream.writeByte(6)
        outputStream.writeInt(pieceIndex)
        outputStream.writeInt(begin.toInt())
        outputStream.writeInt(blockSize.toInt())
        outputStream.flush()
        println("Sent request: index=$pieceIndex, begin=$begin, length=$blockSize")
        begin += blockSize
    }
}

fun calculatePieceLength(info: TorrentFile, pieceIndex: Int): Long {  // Return type changed to Long
    val pieceLength = info.pieceLength
    val pieces = info.pieceHashes.size
    val totalLength = info.length

    return if (pieceIndex == pieces - 1) {
        // Last piece
        totalLength - (pieces - 1) * pieceLength
    } else {
        pieceLength
    }
}

fun sendInterestedMessage(outputStream: DataOutputStream) {
    // Message length (1 byte for message ID, no payload)
    outputStream.writeInt(1)

    // Message ID for interested is 2
    outputStream.writeByte(2)
    outputStream.flush()

    println("Sent: Interested message")
}

//    In the BitTorrent protocol, a request message has the following structure:
//
//    Length prefix (4 bytes): 13 (1 for message ID + 12 for payload)
//    Message ID (1 byte): 6
//    Payload (12 bytes):
//
//    index (4 bytes): zero-based piece index
//    begin (4 bytes): zero-based byte offset within the piece
//    length (4 bytes): requested length, typically 16 KiB (16384 bytes)
fun sendRequest(outputStream: DataOutputStream, index: Int, begin: Int, length: Int) {
    // Message length (1 byte for message ID + 12 bytes for payload)
    outputStream.writeInt(13)
    // Message ID for "request" is 6
    outputStream.writeByte(6)

    // Payload
    outputStream.writeInt(index)  // piece index
    outputStream.writeInt(begin)  // byte offset within the piece
    outputStream.writeInt(length) // requested length

    // Flush to ensure the message is sent immediately
    outputStream.flush()
}

fun handleInterested() {
    println("Received interested")

}

fun handleNotInterested() {
    println("Received not interested")
}

fun handleHave(payload: ByteArray) {
    println("Received Have")
}

fun handleBitfield(payload: ByteArray, outputStream: DataOutputStream) {
    println("Received bitfield")
    println(payload)
    //Send Interested
    outputStream.writeInt(2)
    outputStream.flush()
}

fun handleRequest() {
    println("Received request")
}

fun handlePiece() {
    println("Received piece")
}

fun handleChoke() {
    //Choking is a notification that no data will be sent until unchoking happens.
    println("Received choke")
}

fun handleUnchoke() {
    println("Received unchoke")
}

fun handleCancel() {
    println("Received cancel")
}

fun performHandshake(peers: MutableList<String>, host:String, port:Int, torrent:TorrentFile) {
    val socket = Socket(host, port)
    val outputStream = DataOutputStream(socket.getOutputStream())
    val inputStream = DataInputStream(socket.getInputStream())
    try {
        val protocolName = "BitTorrent protocol"
        val reserved = ByteArray(8) // 8 reserved bytes, all set to 0
        // Convert infoHash and peerId from hex string to ByteArray
        val infoHashBytes = torrent.infoHashBytes()
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

fun decodeTorrentFile(torrentFile: String, supressOutput:Boolean = false): TorrentFile {
    val fileBytes = File(torrentFile).readBytes()
    //Decode the non UTF-16 data normally
    val bencode = Bencode(false)
    val torrentData = bencode.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>
    val url = torrentData["announce"]
    val info = torrentData["info"] as Map<*, *>
    val length = info["length"] as Long  // Changed to Long
    val pieceLength = info["piece length"] as Long

    //We need to preserve UTF-16 for the info section.
    val bencode2 = Bencode(true)
    val infoData = bencode2.decode(fileBytes, Type.DICTIONARY) as Map<String, Any>

    val map = infoData["info"] as Map<*, *>

    var index = 0
    val pieceHashes = mutableListOf<String>()
    val buffer = map["pieces"] as ByteBuffer
    val pieces = buffer.array()

    while ((index * 20) + 20 <= pieces.size) {
        val chunk = pieces.sliceArray(index * 20..<(index * 20) + 20)
        pieceHashes.add(chunk.toHexString())
        index += 1
    }

    val encodedInfo = bencode2.encode(map)
    val digest = MessageDigest.getInstance("SHA-1")
    val bytes = digest.digest(encodedInfo)
    val infoHash = bytes.toHexString()

    val torrent = TorrentFile(url.toString(), info, length, pieceLength, infoHash, pieceHashes, pieces)
    if (!supressOutput) {
        torrent.print()
    }

    return torrent
}

fun getPeers(torrentInfo:TorrentFile): MutableList<String> {
    val bencode = Bencode(true)
    var params = mutableMapOf<String, String>()
    params["peer_id"] = "00112233445566778899"
    params["port"] = "6881"
    params["uploaded"] = "0"
    params["downloaded"] = "0"
    params["left"] = torrentInfo.length.toString()
    params["compact"] = "1"

    val url = torrentInfo.announceUrl
    val getResult = getRequestWithHttpURLConnection(url, params, customUrlEncode(torrentInfo.infoHash))
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

class TorrentFile(
    val announceUrl: String, val info: Map<*, *>, val length: Long,
    val pieceLength: Long, val infoHash: String, val pieceHashes: MutableList<String>,
    val pieces:ByteArray
) {

    fun print() {
        println("Tracker URL: $announceUrl")
        println("Length: $length")
        println("Info Hash: $infoHash")
        println("Piece Length: $pieceLength")
        println("Piece Hashes: \n${pieceHashes.joinToString(separator = "\n")}")
    }
}
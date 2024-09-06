import com.google.gson.Gson;
import java.math.BigInteger

// import com.dampcake.bencode.Bencode; - available if you need it!

val gson = Gson()

fun main(args: Array<String>) {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    //println("Logs from your program will appear here!")
    val command = args[0]
    when (command) {
        "decode" -> {
            // Uncomment this block to pass the first stage
             val bencodedValue = args[1]

            when {
                Character.isDigit(bencodedValue[0]) -> {
                    val decoded = decodeBencode(bencodedValue)
                    println(gson.toJson(decoded))
                }
                Character.isLetter(bencodedValue[0]) -> {
                    val decoded = decodeBencodeInt(bencodedValue)
                    println(gson.toJson(decoded))
                }
            }
             return
        }
        else -> println("Unknown command $command")
    }
}

fun decodeBencodeInt(bencodedString: String): BigInteger {
    val firstVal = bencodedString[0]
    val end = bencodedString[bencodedString.length - 1]
    if (firstVal == 'i' && end == 'e') {
        val integerToDecode = bencodedString.substring(1, bencodedString.length - 1)
        try {
            val parsed =  integerToDecode.toBigInteger()
            return parsed
        } catch (e: NumberFormatException) {
            return BigInteger.ZERO
        }
    }
    return BigInteger.ZERO
}

fun decodeBencode(bencodedString: String): String {
    when {
        Character.isDigit(bencodedString[0]) -> {
            val firstColonIndex = bencodedString.indexOfFirst { it == ':' }
            val length = Integer.parseInt(bencodedString.substring(0, firstColonIndex))
            return bencodedString.substring(firstColonIndex + 1, firstColonIndex + 1 + length)
        }
        else -> TODO("Only strings are supported at the moment")
    }
}

import com.google.gson.Gson
import java.math.BigInteger
import com.dampcake.bencode.Bencode
import com.dampcake.bencode.Type

val gson = Gson()

fun main(args: Array<String>) {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    //println("Logs from your program will appear here!")
    val command = args[0]
    when (command) {
        "decode" -> {
            // Uncomment this block to pass the first stage
             val bencodedValue = args[1]

            val decoded = decodeBencode(bencodedValue)
            println(gson.toJson(decoded))
             return
        }
        else -> println("Unknown command $command")
    }
}

fun decodeBencode(encodedString: String): Any {
    val bencode = Bencode()
    val bytes = encodedString.toByteArray()

    return when {
        encodedString.startsWith("d") -> {
            val decoded = bencode.decode(bytes, Type.DICTIONARY) as Map<String, Any>
            decoded.mapValues { (_, value) ->
                if (value is ByteArray) String(value) else value
            }
        }
        encodedString.startsWith("l") -> {
            val decoded = bencode.decode(bytes, Type.LIST) as List<Any>
            decoded.map { if (it is ByteArray) String(it) else it }
        }
        encodedString.startsWith("i") -> {
            bencode.decode(bytes, Type.NUMBER)
        }
        else -> {
            bencode.decode(bytes, Type.STRING)
        }
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

fun decodeBencodeString(bencodedString: String): String {
    when {
        Character.isDigit(bencodedString[0]) -> {
            val firstColonIndex = bencodedString.indexOfFirst { it == ':' }
            val length = Integer.parseInt(bencodedString.substring(0, firstColonIndex))
            return bencodedString.substring(firstColonIndex + 1, firstColonIndex + 1 + length)
        }
        else -> TODO("Only strings are supported at the moment")
    }
}

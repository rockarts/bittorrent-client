import java.util.ArrayList

class WorkQueue<T> {
    private var pieces = ArrayList<T>()

    fun enqueue(piece:T) {
        pieces.add(piece)
    }

    fun dequeue() : T? {
        return pieces.removeFirstOrNull()
    }

    fun peek() : T? {
        return pieces.lastOrNull()
    }
}
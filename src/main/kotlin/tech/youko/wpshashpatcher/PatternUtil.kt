package tech.youko.wpshashpatcher

import java.nio.ByteBuffer

fun findPattern(
    data: ByteBuffer,
    pattern: IntArray,
    index: Int = data.position(),
    reverse: Boolean = false,
    maxMatches: Int = Int.MAX_VALUE
): List<Int> {
    val matches = mutableListOf<Int>()
    val start = if (reverse) minOf(data.limit() - pattern.size, index) else maxOf(0, index)
    val range = if (reverse) start downTo 0 else start..data.limit() - pattern.size

    for (i in range) {
        if (pattern.indices.all { j -> pattern[j] > 0xFF || pattern[j].toByte() == data[i + j] }) {
            matches.add(i)
            if (matches.size >= maxMatches) break
        }
    }
    return matches
}

fun bytesOf(vararg values: Int): ByteArray = values.map(Int::toByte).toByteArray()

fun ByteArray.toPattern(): IntArray = map { it.toUByte().toInt() }.toIntArray()
